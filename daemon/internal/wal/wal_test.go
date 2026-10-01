package wal

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func ev(agent string, seq uint64) Record {
	return Record{Type: TypeEvent, AgentID: agent, Seq: seq, Event: json.RawMessage(fmt.Sprintf(`{"n":%d}`, seq))}
}

func TestWriteAndReopen(t *testing.T) {
	dir := t.TempDir()
	l, recs, err := openAll(dir, 1<<20, nil)
	if err != nil || len(recs) != 0 {
		t.Fatalf("open: %v %d", err, len(recs))
	}
	if err := l.Write([]Record{ev("a", 1), ev("b", 2)}); err != nil {
		t.Fatal(err)
	}
	seal := Record{Type: TypeSealed, AgentID: "a", FirstSeq: 1, LastSeq: 1, Count: 1, Root: "0x01"}
	if err := l.Write([]Record{seal, ev("a", 3)}); err != nil {
		t.Fatal(err)
	}
	l.Close()

	l2, recs, err := openAll(dir, 1<<20, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	if len(recs) != 4 || recs[2].Type != TypeSealed || recs[3].Seq != 3 || string(recs[0].Event) != `{"n":1}` {
		t.Fatalf("unexpected replay: %+v", recs)
	}
	// Appending after reopen continues the same log.
	if err := l2.Write([]Record{ev("a", 4)}); err != nil {
		t.Fatal(err)
	}
}

func TestRejectsInvalidRecords(t *testing.T) {
	l, _, _ := openAll(t.TempDir(), 1<<20, nil)
	defer l.Close()
	for _, r := range []Record{
		{Type: TypeEvent, AgentID: "a"},
		{Type: "bogus", AgentID: "a"},
		{Type: TypeSealed, AgentID: "a", FirstSeq: 5, LastSeq: 4, Count: 1, Root: "x"},
	} {
		if err := l.Write([]Record{r}); err == nil {
			t.Errorf("accepted %+v", r)
		}
	}
}

func TestTornTailIsTruncated(t *testing.T) {
	dir := t.TempDir()
	l, _, _ := openAll(dir, 1<<20, nil)
	if err := l.Write([]Record{ev("a", 1), ev("a", 2)}); err != nil {
		t.Fatal(err)
	}
	l.Close()
	path := filepath.Join(dir, segName(1))
	f, _ := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	f.WriteString(`{"t":"event","agent":"a","seq":3,"ev`) // crash mid-write
	f.Close()

	l2, recs, err := openAll(dir, 1<<20, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("want 2 records after truncation, got %d", len(recs))
	}
	if err := l2.Write([]Record{ev("a", 3)}); err != nil {
		t.Fatal(err)
	}
	l2.Close()
	_, recs, err = openAll(dir, 1<<20, nil)
	if err != nil || len(recs) != 3 {
		t.Fatalf("after rewrite: %v %d", err, len(recs))
	}
}

func TestCorruptionInOlderSegmentIsFatal(t *testing.T) {
	dir := t.TempDir()
	l, _, _ := openAll(dir, 1, nil) // rotate after every write
	l.Write([]Record{ev("a", 1)})
	l.Write([]Record{ev("a", 2)})
	l.Close()
	path := filepath.Join(dir, segName(1))
	os.WriteFile(path, []byte("garbage\n"+`{"t":"event","agent":"a","seq":1,"event":{}}`+"\n"), 0o600)
	if _, _, err := openAll(dir, 1, nil); err == nil {
		t.Fatal("expected corruption error")
	}
}

func TestRotationAndCompaction(t *testing.T) {
	dir := t.TempDir()
	l, _, _ := openAll(dir, 1, nil) // every write rotates
	defer l.Close()
	l.Write([]Record{ev("a", 1), ev("b", 2)})
	l.Write([]Record{ev("a", 3)})
	l.Write([]Record{{Type: TypeSealed, AgentID: "a", FirstSeq: 1, LastSeq: 3, Count: 2, Root: "0x01"}})
	if got := l.Segments(); got != 4 { // three written + fresh active
		t.Fatalf("segments = %d", got)
	}
	anchored := map[string]uint64{"a": 3}
	n, err := l.Compact(func(a string) uint64 { return anchored[a] })
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 { // segment 1 still holds b's unanchored event 2
		t.Fatalf("compacted %d segments, want 0", n)
	}
	anchored["b"] = 2
	if n, _ = l.Compact(func(a string) uint64 { return anchored[a] }); n != 3 {
		t.Fatalf("compacted %d segments, want 3", n)
	}
	if l.Segments() != 1 {
		t.Fatalf("segments = %d", l.Segments())
	}
	l.Close()
	_, recs, err := openAll(dir, 1, nil)
	if err != nil || len(recs) != 0 {
		t.Fatalf("reopen after compaction: %v %d", err, len(recs))
	}
}

// openAll opens the log and replays every record.
func openAll(dir string, maxSeg int64, logger *slog.Logger) (*Log, []Record, error) {
	l, err := Open(dir, maxSeg, logger)
	if err != nil {
		return nil, nil, err
	}
	var recs []Record
	err = l.Replay(func(r Record, _ Loc) error { recs = append(recs, r); return nil })
	return l, recs, err
}

func TestAppendLocsAndReader(t *testing.T) {
	dir := t.TempDir()
	l, _, _ := openAll(dir, 64, nil) // rotate often
	var locs []Loc
	for i := uint64(1); i <= 6; i++ {
		ls, err := l.Append([]Record{ev("a", i)})
		if err != nil {
			t.Fatal(err)
		}
		locs = append(locs, ls...)
	}
	if l.Bytes() == 0 {
		t.Fatal("Bytes() = 0")
	}
	r := l.NewReader()
	defer r.Close()
	for i, loc := range locs {
		rec, err := r.Read(loc)
		if err != nil || rec.Seq != uint64(i+1) {
			t.Fatalf("read %d: %+v %v", i, rec, err)
		}
	}
	l.Close()
	// Replay reports the same locations.
	l2, err := Open(dir, 64, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	i := 0
	if err := l2.Replay(func(rec Record, loc Loc) error {
		if loc != locs[i] {
			t.Fatalf("replay loc %d = %+v, want %+v", i, loc, locs[i])
		}
		i++
		return nil
	}); err != nil || i != len(locs) {
		t.Fatalf("replay: %v (%d records)", err, i)
	}
	if l2.Bytes() != l.Bytes() {
		t.Fatalf("Bytes after reopen = %d, want %d", l2.Bytes(), l.Bytes())
	}
}
