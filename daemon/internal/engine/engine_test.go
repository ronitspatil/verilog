package engine

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/ronitspatil/verilog/daemon/internal/anchor"
	"github.com/ronitspatil/verilog/daemon/internal/canonical"
	"github.com/ronitspatil/verilog/daemon/internal/merkle"
	"github.com/ronitspatil/verilog/daemon/internal/store"
	"github.com/ronitspatil/verilog/daemon/internal/wal"
)

type jobSink struct {
	mu   sync.Mutex
	jobs []anchor.Job
}

func (s *jobSink) Enqueue(j anchor.Job) {
	s.mu.Lock()
	s.jobs = append(s.jobs, j)
	s.mu.Unlock()
}

func (s *jobSink) take() []anchor.Job {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.jobs
	s.jobs = nil
	return out
}

func (s *jobSink) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.jobs)
}

type harness struct {
	dir    string
	eng    *Engine
	sink   *jobSink
	wal    *wal.Log
	st     *store.Store
	cancel context.CancelFunc
}

func start(t *testing.T, dir string, cfg Config) *harness {
	t.Helper()
	return startWith(t, dir, cfg, nil)
}

// startWith starts an engine whose sealed epochs go to enq (the harness's
// job sink if nil).
func startWith(t *testing.T, dir string, cfg Config, enq Enqueuer) *harness {
	t.Helper()
	w, err := wal.Open(dir+"/wal", 1<<20, nil)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	sink := &jobSink{}
	if enq == nil {
		enq = sink
	}
	eng, err := New(cfg, w, st, enq, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.Recover(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	eng.Start(ctx)
	h := &harness{dir: dir, eng: eng, sink: sink, wal: w, st: st, cancel: cancel}
	t.Cleanup(h.stop)
	return h
}

func (h *harness) stop() {
	h.cancel()
	h.eng.Close()
	h.wal.Close()
}

func slowCfg() Config {
	return Config{EpochInterval: time.Hour, EpochMaxLogs: 1 << 20, ChainID: "31337", Contract: "0xc0ffee"}
}

func event(agent string, step uint64) canonical.Event {
	ev := canonical.Event{
		AgentID:      agent,
		StepNumber:   step,
		EventType:    "tool_start",
		PayloadJSON:  []byte(fmt.Sprintf(`{"step":%d,"tool":"search"}`, step)),
		TimestampUTC: time.Unix(1_800_000_000, int64(step)).UTC(),
	}
	sign(&ev)
	return ev
}

var testKey = ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))

func sign(ev *canonical.Event) {
	if ev.RunID == "" {
		ev.RunID = "run-" + ev.AgentID
	}
	if err := ev.Sign(testKey); err != nil {
		panic(err)
	}
}

func submit(t *testing.T, e *Engine, ev canonical.Event) Result {
	t.Helper()
	p, err := Prepare(ev)
	if err != nil {
		t.Fatal(err)
	}
	ch, err := e.Submit(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	r := <-ch
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	return r
}

// finalizeAll completes every queued job with sequential per-agent epochs.
func finalizeAll(t *testing.T, h *harness, firstEpoch map[[32]byte]uint64) []anchor.Job {
	t.Helper()
	jobs := h.sink.take()
	for _, j := range jobs {
		firstEpoch[j.AgentKey]++
		if err := j.Done(context.Background(), anchor.Result{EpochID: firstEpoch[j.AgentKey], TxHash: "0xabc", BlockNumber: 7}); err != nil {
			t.Fatal(err)
		}
	}
	return jobs
}

func TestConcurrentIngestSealAndBundles(t *testing.T) {
	h := start(t, t.TempDir(), slowCfg())
	agents := []string{"agent-a", "agent-b", "agent-c"}
	const perAgent, writersPerAgent = 200, 4

	var wg sync.WaitGroup
	seqs := sync.Map{}
	for _, a := range agents {
		for w := 0; w < writersPerAgent; w++ {
			wg.Add(1)
			go func(a string, w int) {
				defer wg.Done()
				for i := 0; i < perAgent/writersPerAgent; i++ {
					step := uint64(w*1000 + i)
					p, _ := Prepare(event(a, step))
					ch, err := h.eng.Submit(context.Background(), p)
					if err != nil {
						t.Error(err)
						return
					}
					r := <-ch
					if r.Err != nil || r.Duplicate {
						t.Errorf("unexpected result %+v", r)
						return
					}
					if _, dup := seqs.LoadOrStore(r.Seq, true); dup {
						t.Errorf("seq %d assigned twice", r.Seq)
					}
				}
			}(a, w)
		}
		// Seal concurrently with ingestion to exercise the swap.
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 5; i++ {
				h.eng.SealAll(context.Background())
				time.Sleep(time.Millisecond)
			}
		}()
	}
	wg.Wait()
	if err := h.eng.SealAll(context.Background()); err != nil {
		t.Fatal(err)
	}

	epochs := map[[32]byte]uint64{}
	jobs := finalizeAll(t, h, epochs)
	total := 0
	for _, j := range jobs {
		total += int(j.Count)
	}
	if total != len(agents)*perAgent {
		t.Fatalf("sealed %d events, want %d", total, len(agents)*perAgent)
	}

	// Every bundle's proofs verify and digests match the canonical bytes.
	seen := 0
	for _, a := range agents {
		key := canonical.AgentKey(a)
		for ep := uint64(1); ep <= epochs[key]; ep++ {
			b, err := h.st.ReadBundle(key.Hex(), ep)
			if err != nil {
				t.Fatal(err)
			}
			root, _ := canonical.ParseDigest(b.MerkleRoot)
			for _, ev := range b.Events {
				d := canonical.ContentDigest([]byte(ev.CanonicalEvent))
				if d.Hex() != ev.ContentDigest {
					t.Fatal("digest mismatch in bundle")
				}
				var proof []merkle.Hash
				for _, p := range ev.Proof {
					x, _ := canonical.ParseDigest(p)
					proof = append(proof, x)
				}
				if !merkle.Verify(merkle.LeafFromDigest(d), proof, root) {
					t.Fatalf("bundle %s epoch %d leaf %d proof invalid", a, ep, ev.LeafIndex)
				}
				parsed, err := canonical.ParseEvent([]byte(ev.CanonicalEvent))
				if err != nil || parsed.AgentID != a {
					t.Fatalf("bundle event agent mismatch: %v", err)
				}
				seen++
			}
		}
	}
	if seen != len(agents)*perAgent {
		t.Fatalf("bundles hold %d events, want %d", seen, len(agents)*perAgent)
	}
	if s := h.eng.Stats(); s.Accepted != uint64(len(agents)*perAgent) || s.AnchoredEpochs != uint64(len(jobs)) {
		t.Fatalf("stats %+v", s)
	}
}

func TestCountTriggerSeals(t *testing.T) {
	cfg := slowCfg()
	cfg.EpochMaxLogs = 10
	h := start(t, t.TempDir(), cfg)
	for i := uint64(1); i <= 25; i++ {
		submit(t, h.eng, event("agent-a", i))
	}
	deadline := time.Now().Add(5 * time.Second)
	for h.sink.len() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := h.sink.len(); n < 2 {
		t.Fatalf("count trigger produced %d epochs, want >= 2", n)
	}
}

func TestIntervalTriggerSeals(t *testing.T) {
	cfg := slowCfg()
	cfg.EpochInterval = 20 * time.Millisecond
	h := start(t, t.TempDir(), cfg)
	submit(t, h.eng, event("agent-a", 1))
	deadline := time.Now().Add(5 * time.Second)
	for h.sink.len() < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if h.sink.len() != 1 {
		t.Fatal("interval trigger did not seal")
	}
}

func TestDuplicateDetection(t *testing.T) {
	h := start(t, t.TempDir(), slowCfg())
	first := submit(t, h.eng, event("agent-a", 1))
	again := submit(t, h.eng, event("agent-a", 1))
	if !again.Duplicate || again.Seq != first.Seq {
		t.Fatalf("second submission %+v, want duplicate of seq %d", again, first.Seq)
	}
	// Same content for a different agent is not a duplicate.
	other := submit(t, h.eng, event("agent-b", 1))
	if other.Duplicate {
		t.Fatal("cross-agent event marked duplicate")
	}
	h.eng.SealAll(context.Background())
	for _, j := range h.sink.take() {
		if j.Count != 1 {
			t.Fatalf("epoch count %d, want 1", j.Count)
		}
	}
}

func TestReplayAfterRestart(t *testing.T) {
	dir := t.TempDir()
	h := start(t, dir, slowCfg())
	for i := uint64(1); i <= 5; i++ {
		submit(t, h.eng, event("agent-a", i))
	}
	h.eng.SealAll(context.Background())
	sealedJobs := h.sink.take() // sealed, but never anchored (crash before anchoring)
	if len(sealedJobs) != 1 {
		t.Fatalf("jobs = %d", len(sealedJobs))
	}
	for i := uint64(6); i <= 8; i++ {
		submit(t, h.eng, event("agent-a", i))
	}
	submit(t, h.eng, event("agent-b", 1))
	h.stop()

	// Restart 1: the sealed epoch is re-queued with the identical root; the
	// open events are back in their shards.
	h2 := start(t, dir, slowCfg())
	requeued := h2.sink.take()
	if len(requeued) != 1 || requeued[0].Root != sealedJobs[0].Root || requeued[0].Count != 5 {
		t.Fatalf("requeued %+v, want root %x count 5", requeued, sealedJobs[0].Root)
	}
	if n := h2.eng.shard("agent-a").size(); n != 3 {
		t.Fatalf("agent-a open epoch has %d events, want 3", n)
	}
	// Replayed events still deduplicate.
	if r := submit(t, h2.eng, event("agent-a", 7)); !r.Duplicate {
		t.Fatal("replayed event not deduplicated")
	}
	// New events get fresh sequence numbers.
	r := submit(t, h2.eng, event("agent-a", 9))
	if r.Seq != 10 {
		t.Fatalf("next seq = %d, want 10", r.Seq)
	}
	if err := requeued[0].Done(context.Background(), anchor.Result{EpochID: 1}); err != nil {
		t.Fatal(err)
	}
	h2.eng.SealAll(context.Background())
	pendingAfter := h2.sink.take() // agent-a [6..9] and agent-b [1]; not anchored
	if len(pendingAfter) != 2 {
		t.Fatalf("jobs = %d, want 2", len(pendingAfter))
	}
	h2.stop()

	// Restart 2: epoch 1 is anchored (checkpoint), the two later seals are re-queued.
	h3 := start(t, dir, slowCfg())
	again := h3.sink.take()
	if len(again) != 2 {
		t.Fatalf("requeued %d jobs after restart 2, want 2", len(again))
	}
	roots := map[[32]byte]bool{pendingAfter[0].Root: true, pendingAfter[1].Root: true}
	for _, j := range again {
		if !roots[j.Root] {
			t.Fatalf("unexpected requeued root %x", j.Root)
		}
	}
	if b, err := h3.st.ReadBundle(canonical.AgentKey("agent-a").Hex(), 1); err != nil || b.LogCount != 5 {
		t.Fatalf("epoch 1 bundle: %v", err)
	}
}

func TestSubmitAfterClose(t *testing.T) {
	h := start(t, t.TempDir(), slowCfg())
	h.stop()
	p, _ := Prepare(event("a", 1))
	if _, err := h.eng.Submit(context.Background(), p); err != ErrClosed {
		t.Fatalf("err = %v, want ErrClosed", err)
	}
}

func BenchmarkSubmitParallel(b *testing.B) {
	dir := b.TempDir()
	w, _ := wal.Open(dir+"/wal", 64<<20, nil)
	st, _ := store.Open(dir)
	eng, _ := New(Config{EpochInterval: time.Hour, EpochMaxLogs: 1 << 24}, w, st, &jobSink{}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	eng.Start(ctx)
	defer func() { cancel(); eng.Close(); w.Close() }()
	var n uint64
	var mu sync.Mutex
	b.RunParallel(func(pb *testing.PB) {
		var pending []<-chan Result
		for pb.Next() {
			mu.Lock()
			n++
			step := n
			mu.Unlock()
			p, _ := Prepare(event("bench", step))
			ch, err := eng.Submit(ctx, p)
			if err != nil {
				b.Error(err)
				return
			}
			pending = append(pending, ch)
			if len(pending) == 256 { // pipelined like an ingest stream
				for _, c := range pending {
					<-c
				}
				pending = pending[:0]
			}
		}
		for _, c := range pending {
			<-c
		}
	})
}

// revokedKeys reports the keys in the set as revoked now.
type revokedKeys struct {
	mu      sync.Mutex
	revoked map[canonical.Digest]bool
}

func (r *revokedKeys) RevokedNow(_ context.Context, _, keyID canonical.Digest) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.revoked[keyID], nil
}

// M4: events accepted while the key cache still showed the key unrevoked
// (a replay, say) are left out of the epoch at seal time, and the WAL
// replays the same grouping after a crash.
func TestSealLeavesOutEventsOfRevokedKeys(t *testing.T) {
	dir := t.TempDir()
	other := ed25519.NewKeyFromSeed([]byte("0123456789abcdef0123456789abcdef"))
	check := &revokedKeys{revoked: map[canonical.Digest]bool{canonical.KeyID(other.Public().(ed25519.PublicKey)): true}}
	cfg := slowCfg()
	cfg.KeyCheck = check
	h := start(t, dir, cfg)

	revokedEvent := func(step uint64) canonical.Event {
		ev := event("agent-a", step)
		if err := ev.Sign(other); err != nil {
			t.Fatal(err)
		}
		return ev
	}
	submit(t, h.eng, event("agent-a", 1))
	submit(t, h.eng, revokedEvent(2))
	submit(t, h.eng, event("agent-a", 3))
	submit(t, h.eng, revokedEvent(4))
	if err := h.eng.SealAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	jobs := h.sink.take()
	if len(jobs) != 1 || jobs[0].Count != 2 {
		t.Fatalf("jobs %+v, want one epoch of 2 events", jobs)
	}
	want := jobs[0].Root
	if s := h.eng.Stats(); s.RevokedExcluded != 2 || s.Accepted != 4 {
		t.Fatalf("stats %+v", s)
	}

	// An epoch where every event is left out anchors nothing.
	submit(t, h.eng, revokedEvent(5))
	h.eng.SealAll(context.Background())
	if n := h.sink.len(); n != 0 {
		t.Fatalf("empty epoch anchored: %d jobs", n)
	}
	h.stop()

	// Crash before anchoring: recovery rebuilds exactly the kept events.
	h2 := start(t, dir, cfg)
	again := h2.sink.take()
	if len(again) != 1 || again[0].Root != want || again[0].Count != 2 {
		t.Fatalf("recovered %+v", again)
	}
	if n := h2.eng.shard("agent-a").size(); n != 0 {
		t.Fatalf("left-out events reopened: %d", n)
	}
}
