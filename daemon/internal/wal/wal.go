// Package wal is VeriLog's write-ahead log: JSON Lines segment files that
// are fsynced in batches (group commit) before events are acknowledged.
//
// Two record types exist:
//   - "event":  one accepted event with its global sequence number and its
//     canonical JSON.
//   - "sealed": an epoch boundary. All events of AgentID with sequence in
//     [FirstSeq, LastSeq], except those listed in Skip, form one sealed
//     epoch with the given root. Skipped events (left out at seal time
//     because their key was revoked) are never anchored; a seal that skips
//     every event has Count 0 and no root.
//
// Anchoring progress is not stored here; it lives in the checkpoint file
// (package store). A segment is deleted once every event and seal it holds
// is covered by the checkpoint.
package wal

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Record types.
const (
	TypeEvent  = "event"
	TypeSealed = "sealed"
)

// Record is one WAL line.
type Record struct {
	Type    string          `json:"t"`
	AgentID string          `json:"agent"`
	Seq     uint64          `json:"seq,omitempty"`   // event
	Event   json.RawMessage `json:"event,omitempty"` // event: canonical event JSON
	// Sealed epoch fields.
	FirstSeq uint64   `json:"first,omitempty"`
	LastSeq  uint64   `json:"last,omitempty"`
	Count    int      `json:"count,omitempty"`
	Root     string   `json:"root,omitempty"`
	Skip     []uint64 `json:"skip,omitempty"`
}

// highSeq is the sequence a record must be anchored past before it can be dropped.
func (r Record) highSeq() uint64 {
	if r.Type == TypeSealed {
		return r.LastSeq
	}
	return r.Seq
}

func (r Record) validate() error {
	if r.AgentID == "" {
		return errors.New("record without agent")
	}
	switch r.Type {
	case TypeEvent:
		if r.Seq == 0 || len(r.Event) == 0 {
			return errors.New("event record without seq or event")
		}
	case TypeSealed:
		if r.FirstSeq == 0 || r.LastSeq < r.FirstSeq || r.Count < 0 || (r.Count == 0) != (r.Root == "") || (r.Count == 0 && len(r.Skip) == 0) {
			return errors.New("malformed sealed record")
		}
	default:
		return fmt.Errorf("unknown record type %q", r.Type)
	}
	return nil
}

type segment struct {
	index int
	path  string
	size  int64
	// maxSeq is the highest event seq / sealed LastSeq per agent in this segment.
	maxSeq map[string]uint64
}

// Log is a segmented write-ahead log. All methods are safe for concurrent use.
type Log struct {
	mu          sync.Mutex
	dir         string
	maxSegBytes int64
	segs        []*segment // ascending; the last one is active
	f           *os.File
	size        int64
	buf         bytes.Buffer
	log         *slog.Logger
	// failed is sticky: after a failed write the segment may end in a partial
	// record, so no further appends are allowed (restart truncates the tail).
	failed error
}

const segPrefix, segSuffix = "wal-", ".jsonl"

func segName(i int) string { return fmt.Sprintf("%s%010d%s", segPrefix, i, segSuffix) }

// Loc is where a record is stored: its segment and byte range. It stays
// valid until the segment is compacted away.
type Loc struct {
	Seg int   // segment index
	Off int64 // byte offset of the record's line
	Len int64 // line length, newline included
}

// Open opens (or creates) the log in dir. It checks every segment, streaming
// (records are not kept in memory): a torn final line in the newest segment
// (crash mid-write) is truncated away; corruption anywhere else is an error.
// Replay then yields the records.
func Open(dir string, maxSegmentBytes int64, logger *slog.Logger) (*Log, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var idx []int
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, segPrefix) || !strings.HasSuffix(name, segSuffix) {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(name, segPrefix), segSuffix))
		if err != nil {
			continue
		}
		idx = append(idx, n)
	}
	sort.Ints(idx)

	l := &Log{dir: dir, maxSegBytes: maxSegmentBytes, log: logger}
	for i, n := range idx {
		seg := &segment{index: n, path: filepath.Join(dir, segName(n)), maxSeq: map[string]uint64{}}
		if err := scanSegment(seg, i == len(idx)-1, logger, nil); err != nil {
			return nil, err
		}
		l.segs = append(l.segs, seg)
	}
	if len(l.segs) == 0 {
		if err := l.newSegment(1); err != nil {
			return nil, err
		}
	} else {
		active := l.segs[len(l.segs)-1]
		f, err := os.OpenFile(active.path, os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, err
		}
		st, err := f.Stat()
		if err != nil {
			f.Close()
			return nil, err
		}
		l.f, l.size = f, st.Size()
		active.size = l.size
	}
	return l, nil
}

// Replay calls fn for every record in write order, with its location,
// reading one record at a time. Call it before the first Write.
func (l *Log) Replay(fn func(Record, Loc) error) error {
	l.mu.Lock()
	segs := append([]*segment(nil), l.segs...)
	l.mu.Unlock()
	for _, seg := range segs {
		if err := scanSegment(seg, false, l.log, fn); err != nil {
			return err
		}
	}
	return nil
}

// scanSegment reads a segment one line at a time. With fn nil it checks the
// segment, records its maxSeq and size and, for the newest segment (last),
// truncates a torn tail; otherwise it passes each record to fn.
func scanSegment(seg *segment, last bool, logger *slog.Logger, fn func(Record, Loc) error) error {
	f, err := os.Open(seg.path)
	if err != nil {
		return err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 1<<20)
	var good int64
	done := func() error {
		if fn == nil {
			seg.size = good
		}
		return nil
	}
	for {
		line, err := r.ReadBytes('\n')
		if err == io.EOF {
			if len(line) == 0 {
				return done()
			}
			// Final line without newline: an interrupted write.
			if !last {
				return fmt.Errorf("wal: %s: truncated record in sealed segment", seg.path)
			}
			done()
			return truncate(seg.path, good, logger)
		}
		if err != nil {
			return err
		}
		var rec Record
		if jerr := json.Unmarshal(line, &rec); jerr != nil || rec.validate() != nil {
			if last && isTail(r) {
				done()
				return truncate(seg.path, good, logger)
			}
			return fmt.Errorf("wal: %s: corrupt record at offset %d", seg.path, good)
		}
		loc := Loc{Seg: seg.index, Off: good, Len: int64(len(line))}
		good += int64(len(line))
		if fn != nil {
			if err := fn(rec, loc); err != nil {
				return err
			}
			continue
		}
		if s := rec.highSeq(); s > seg.maxSeq[rec.AgentID] {
			seg.maxSeq[rec.AgentID] = s
		}
	}
}

// isTail reports whether nothing but the remainder of the current line is left.
func isTail(r *bufio.Reader) bool {
	_, err := r.Peek(1)
	return err == io.EOF
}

func truncate(path string, size int64, logger *slog.Logger) error {
	logger.Warn("wal: truncating torn tail record", "segment", path, "offset", size)
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Truncate(size); err != nil {
		return err
	}
	return f.Sync()
}

func (l *Log) newSegment(index int) error {
	seg := &segment{index: index, path: filepath.Join(l.dir, segName(index)), maxSeq: map[string]uint64{}}
	f, err := os.OpenFile(seg.path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if err := syncDir(l.dir); err != nil {
		f.Close()
		return err
	}
	if l.f != nil {
		if err := l.f.Close(); err != nil {
			l.log.Warn("wal: closing segment", "err", err)
		}
	}
	l.f, l.size = f, 0
	l.segs = append(l.segs, seg)
	return nil
}

// Write appends records and fsyncs once. It returns only after the records
// are durable. The caller groups records to amortize the fsync.
func (l *Log) Write(recs []Record) error {
	_, err := l.Append(recs)
	return err
}

// Append is Write that also returns where each record was stored.
func (l *Log) Append(recs []Record) ([]Loc, error) {
	if len(recs) == 0 {
		return nil, nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil, errors.New("wal: closed")
	}
	if l.failed != nil {
		return nil, l.failed
	}
	l.buf.Reset()
	enc := json.NewEncoder(&l.buf)
	enc.SetEscapeHTML(false)
	active := l.segs[len(l.segs)-1]
	locs := make([]Loc, len(recs))
	for i, r := range recs {
		if err := r.validate(); err != nil {
			return nil, fmt.Errorf("wal: %w", err)
		}
		start := int64(l.buf.Len())
		if err := enc.Encode(r); err != nil { // Encode appends '\n'
			return nil, err
		}
		locs[i] = Loc{Seg: active.index, Off: l.size + start, Len: int64(l.buf.Len()) - start}
	}
	n, err := l.f.Write(l.buf.Bytes())
	l.size += int64(n)
	active.size = l.size
	if l.buf.Cap() > 4<<20 {
		l.buf = bytes.Buffer{} // do not keep a large batch's buffer
	}
	if err != nil {
		l.failed = fmt.Errorf("wal: write failed, log is read-only until restart: %w", err)
		return nil, l.failed
	}
	if err := l.f.Sync(); err != nil {
		l.failed = fmt.Errorf("wal: fsync failed, log is read-only until restart: %w", err)
		return nil, l.failed
	}
	for _, r := range recs {
		if s := r.highSeq(); s > active.maxSeq[r.AgentID] {
			active.maxSeq[r.AgentID] = s
		}
	}
	if l.size >= l.maxSegBytes {
		if err := l.newSegment(active.index + 1); err != nil {
			return locs, fmt.Errorf("wal: rotate: %w", err)
		}
	}
	return locs, nil
}

// Reader reads records back by location. It keeps the segments it has read
// open until Close. Not safe for concurrent use.
type Reader struct {
	dir   string
	files map[int]*os.File
}

// NewReader returns a Reader for the log's segments.
func (l *Log) NewReader() *Reader { return &Reader{dir: l.dir, files: map[int]*os.File{}} }

// Read returns the record stored at loc.
func (r *Reader) Read(loc Loc) (Record, error) {
	f := r.files[loc.Seg]
	if f == nil {
		var err error
		if f, err = os.Open(filepath.Join(r.dir, segName(loc.Seg))); err != nil {
			return Record{}, err
		}
		r.files[loc.Seg] = f
	}
	buf := make([]byte, loc.Len)
	if _, err := f.ReadAt(buf, loc.Off); err != nil {
		return Record{}, fmt.Errorf("wal: reading %s at %d: %w", segName(loc.Seg), loc.Off, err)
	}
	var rec Record
	if err := json.Unmarshal(buf, &rec); err != nil {
		return Record{}, fmt.Errorf("wal: corrupt record in %s at %d: %w", segName(loc.Seg), loc.Off, err)
	}
	return rec, nil
}

// Close closes the segments the reader opened.
func (r *Reader) Close() {
	for _, f := range r.files {
		f.Close()
	}
	r.files = nil
}

// Bytes returns the total size of the segment files.
func (l *Log) Bytes() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	var n int64
	for _, s := range l.segs {
		n += s.size
	}
	return n
}

// Compact deletes the oldest inactive segments whose records are all
// anchored, i.e. maxSeq[agent] <= anchoredSeq(agent) for every agent in them.
// It returns the number of segments removed.
func (l *Log) Compact(anchoredSeq func(agentID string) uint64) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	removed := 0
	for len(l.segs) > 1 {
		seg := l.segs[0]
		for agent, s := range seg.maxSeq {
			if s > anchoredSeq(agent) {
				return removed, nil
			}
		}
		if err := os.Remove(seg.path); err != nil {
			return removed, err
		}
		l.segs = l.segs[1:]
		removed++
	}
	if removed > 0 {
		return removed, syncDir(l.dir)
	}
	return removed, nil
}

// Segments returns the number of segment files.
func (l *Log) Segments() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.segs)
}

// Close closes the active segment.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
