package store

import (
	"errors"
	"testing"
	"time"
)

func TestCheckpointRoundTrip(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cp, err := s.LoadCheckpoint()
	if err != nil || len(cp.Agents) != 0 {
		t.Fatalf("empty checkpoint: %v %+v", err, cp)
	}
	cp.Agents["a"] = AgentProgress{AnchoredSeq: 10, Epoch: 2}
	if err := s.SaveCheckpoint(cp); err != nil {
		t.Fatal(err)
	}
	got, err := s.LoadCheckpoint()
	if err != nil || got.Agents["a"] != (AgentProgress{AnchoredSeq: 10, Epoch: 2}) {
		t.Fatalf("got %+v %v", got, err)
	}
}

func TestBundleRoundTrip(t *testing.T) {
	s, _ := Open(t.TempDir())
	b := &Bundle{
		Version: 1, AgentID: "a", AgentKey: "0xABCD", EpochID: 3, MerkleRoot: "0x01", LogCount: 1,
		AnchoredAt: time.Unix(1, 0).UTC(),
		Events:     []EventProof{{LeafIndex: 0, Seq: 1, Proof: []string{}, CanonicalEvent: `{"x":"<&>"}`}},
	}
	if err := s.WriteBundle(b); err != nil {
		t.Fatal(err)
	}
	got, err := s.ReadBundle("0xabcd", 3)
	if err != nil {
		t.Fatal(err)
	}
	if got.EpochID != 3 || got.Events[0].CanonicalEvent != `{"x":"<&>"}` {
		t.Fatalf("got %+v", got)
	}
	if _, err := s.ReadBundle("0xabcd", 4); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing bundle err = %v", err)
	}
}
