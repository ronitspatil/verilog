// Package wal is VeriLog's write-ahead log: JSON Lines segment files that
// are fsynced in batches (group commit) before events are acknowledged.
//
// Two record types exist:
//   - "event":  one accepted event with its global sequence number and its
//     canonical JSON.
//   - "sealed": an epoch boundary. All events of AgentID with sequence in
//     [FirstSeq, LastSeq] form one sealed epoch with the given root.
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
	FirstSeq uint64 `json:"first,omitempty"`
	LastSeq  uint64 `json:"last,omitempty"`
	Count    int    `json:"count,omitempty"`
	Root     string `json:"root,omitempty"`
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
		if r.FirstSeq == 0 || r.LastSeq < r.FirstSeq || r.Count <= 0 || r.Root == "" {
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

// Open opens (or creates) the log in dir and returns every record in it, in
// write order. A torn final line in the newest segment (crash mid-write) is
// truncated away; corruption anywhere else is an error.
func Open(dir string, maxSegmentBytes int64, logger *slog.Logger) (*Log, []Record, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, err
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
	var all []Record
	for i, n := range idx {
		seg := &segment{index: n, path: filepath.Join(dir, segName(n)), maxSeq: map[string]uint64{}}
		recs, err := readSegment(seg, i == len(idx)-1, logger)
		if err != nil {
			return nil, nil, err
		}
		all = append(all, recs...)
		l.segs = append(l.segs, seg)
	}
	if len(l.segs) == 0 {
		if err := l.newSegment(1); err != nil {
			return nil, nil, err
		}
	} else {
		active := l.segs[len(l.segs)-1]
		f, err := os.OpenFile(active.path, os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, nil, err
		}
		st, err := f.Stat()
		if err != nil {
			f.Close()
			return nil, nil, err
		}
		l.f, l.size = f, st.Size()
	}
	return l, all, nil
}

func readSegment(seg *segment, last bool, logger *slog.Logger) ([]Record, error) {
	f, err := os.Open(seg.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 1<<20)
	var recs []Record
	var good int64
	for {
		line, err := r.ReadBytes('\n')
		if err == io.EOF {
			if len(line) == 0 {
				return recs, nil
			}
			// Final line without newline: an interrupted write.
			if !last {
				return nil, fmt.Errorf("wal: %s: truncated record in sealed segment", seg.path)
			}
			return recs, truncate(seg.path, good, logger)
		}
		if err != nil {
			return nil, err
		}
		var rec Record
		if jerr := json.Unmarshal(line, &rec); jerr != nil || rec.validate() != nil {
			if last && isTail(r) {
				return recs, truncate(seg.path, good, logger)
			}
			return nil, fmt.Errorf("wal: %s: corrupt record at offset %d", seg.path, good)
		}
		good += int64(len(line))
		if s := rec.highSeq(); s > seg.maxSeq[rec.AgentID] {
			seg.maxSeq[rec.AgentID] = s
		}
		recs = append(recs, rec)
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
	if len(recs) == 0 {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return errors.New("wal: closed")
	}
	if l.failed != nil {
		return l.failed
	}
	l.buf.Reset()
	enc := json.NewEncoder(&l.buf)
	enc.SetEscapeHTML(false)
	active := l.segs[len(l.segs)-1]
	for _, r := range recs {
		if err := r.validate(); err != nil {
			return fmt.Errorf("wal: %w", err)
		}
		if err := enc.Encode(r); err != nil { // Encode appends '\n'
			return err
		}
	}
	n, err := l.f.Write(l.buf.Bytes())
	l.size += int64(n)
	if err != nil {
		l.failed = fmt.Errorf("wal: write failed, log is read-only until restart: %w", err)
		return l.failed
	}
	if err := l.f.Sync(); err != nil {
		l.failed = fmt.Errorf("wal: fsync failed, log is read-only until restart: %w", err)
		return l.failed
	}
	for _, r := range recs {
		if s := r.highSeq(); s > active.maxSeq[r.AgentID] {
			active.maxSeq[r.AgentID] = s
		}
	}
	if l.size >= l.maxSegBytes {
		if err := l.newSegment(active.index + 1); err != nil {
			return fmt.Errorf("wal: rotate: %w", err)
		}
	}
	return nil
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
