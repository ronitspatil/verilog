package engine

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ronitspatil/verilog/daemon/internal/anchor"
	"github.com/ronitspatil/verilog/daemon/internal/canonical"
)

// trySubmit submits ev and returns the backpressure error, if any.
func trySubmit(t *testing.T, e *Engine, ev canonical.Event) *BackpressureError {
	t.Helper()
	p, err := Prepare(ev)
	if err != nil {
		t.Fatal(err)
	}
	ch, err := e.Submit(context.Background(), p)
	var bp *BackpressureError
	if errors.As(err, &bp) {
		return bp
	}
	if err != nil {
		t.Fatal(err)
	}
	if r := <-ch; r.Err != nil {
		t.Fatal(r.Err)
	}
	return nil
}

func wantReason(t *testing.T, bp *BackpressureError, reason string) {
	t.Helper()
	if bp == nil || bp.Reason != reason || bp.RetryAfter <= 0 {
		t.Fatalf("got %v, want backpressure %s", bp, reason)
	}
}

func limitsCfg(l Limits) Config {
	c := slowCfg()
	c.Limits = l
	return c
}

func sealAndFinalize(t *testing.T, h *harness, epochs map[[32]byte]uint64) {
	t.Helper()
	if err := h.eng.SealAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	finalizeAll(t, h, epochs)
}

func TestAgentEventQuota(t *testing.T) {
	h := start(t, t.TempDir(), limitsCfg(Limits{MaxAgentEvents: 3}))
	for i := uint64(1); i <= 3; i++ {
		if bp := trySubmit(t, h.eng, event("a", i)); bp != nil {
			t.Fatal(bp)
		}
	}
	wantReason(t, trySubmit(t, h.eng, event("a", 4)), ReasonAgentEvents)
	// A duplicate of an accepted event is refused too while over quota, but
	// another agent is not affected.
	if bp := trySubmit(t, h.eng, event("b", 1)); bp != nil {
		t.Fatalf("agent b refused: %v", bp)
	}
	u := h.eng.Usage()
	if u.Agents["a"].Events != 3 || u.Agents["b"].Events != 1 || u.UnanchoredEvents != 4 || u.Rejected[ReasonAgentEvents] != 1 {
		t.Fatalf("usage %+v", u)
	}
	sealAndFinalize(t, h, map[[32]byte]uint64{})
	if u := h.eng.Usage(); u.UnanchoredEvents != 0 || u.UnanchoredBytes != 0 || len(u.Agents) != 0 || u.AnchorQueue != 0 {
		t.Fatalf("usage after anchoring %+v", u)
	}
	if bp := trySubmit(t, h.eng, event("a", 4)); bp != nil {
		t.Fatalf("after anchoring: %v", bp)
	}
}

func TestDuplicateReleasesReservation(t *testing.T) {
	h := start(t, t.TempDir(), limitsCfg(Limits{MaxAgentEvents: 2}))
	submit(t, h.eng, event("a", 1))
	if r := submit(t, h.eng, event("a", 1)); !r.Duplicate {
		t.Fatal("want duplicate")
	}
	if u := h.eng.Usage(); u.Agents["a"].Events != 1 {
		t.Fatalf("duplicate kept its reservation: %+v", u)
	}
	submit(t, h.eng, event("a", 2))
}

func TestAgentByteQuota(t *testing.T) {
	p, _ := Prepare(event("a", 1))
	n := int64(len(p.Canonical))
	h := start(t, t.TempDir(), limitsCfg(Limits{MaxAgentBytes: 2*n + n/2}))
	submit(t, h.eng, event("a", 1))
	submit(t, h.eng, event("a", 2))
	wantReason(t, trySubmit(t, h.eng, event("a", 3)), ReasonAgentBytes)
	submit(t, h.eng, event("b", 1))
}

func TestAgentByteQuotaAdmitsOneLargeEvent(t *testing.T) {
	// An event larger than the quota is still admitted when the agent has
	// nothing unanchored, or it could never be sent.
	h := start(t, t.TempDir(), limitsCfg(Limits{MaxAgentBytes: 10, MaxTotalBytes: 10}))
	submit(t, h.eng, event("a", 1))
	wantReason(t, trySubmit(t, h.eng, event("b", 1)), ReasonTotalBytes)
	wantReason(t, trySubmit(t, h.eng, event("a", 2)), ReasonTotalBytes)
}

func TestTotalBytesLimit(t *testing.T) {
	p, _ := Prepare(event("a", 1))
	n := int64(len(p.Canonical))
	h := start(t, t.TempDir(), limitsCfg(Limits{MaxTotalBytes: 3*n + n/2}))
	submit(t, h.eng, event("a", 1))
	submit(t, h.eng, event("b", 1))
	submit(t, h.eng, event("c", 1))
	wantReason(t, trySubmit(t, h.eng, event("d", 1)), ReasonTotalBytes)
}

func TestAnchorQueueLimit(t *testing.T) {
	h := start(t, t.TempDir(), limitsCfg(Limits{MaxAnchorQueue: 2}))
	submit(t, h.eng, event("a", 1))
	h.eng.SealAll(context.Background())
	submit(t, h.eng, event("b", 1))
	h.eng.SealAll(context.Background())
	if u := h.eng.Usage(); u.AnchorQueue != 2 {
		t.Fatalf("anchor queue %d", u.AnchorQueue)
	}
	wantReason(t, trySubmit(t, h.eng, event("c", 1)), ReasonAnchorQueue)
	finalizeAll(t, h, map[[32]byte]uint64{})
	submit(t, h.eng, event("c", 1))
}

func TestAgentRateLimit(t *testing.T) {
	h := start(t, t.TempDir(), limitsCfg(Limits{AgentRate: 10, AgentBurst: 2}))
	var mu sync.Mutex
	now := time.Unix(1_000, 0)
	h.eng.limMu.Lock()
	h.eng.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	h.eng.use.agents = map[string]*agentUsage{}
	h.eng.limMu.Unlock()
	submit(t, h.eng, event("a", 1))
	submit(t, h.eng, event("a", 2))
	bp := trySubmit(t, h.eng, event("a", 3))
	wantReason(t, bp, ReasonAgentRate)
	if bp.RetryAfter < 90*time.Millisecond || bp.RetryAfter > 110*time.Millisecond {
		t.Fatalf("retry after %v, want ~100ms", bp.RetryAfter)
	}
	submit(t, h.eng, event("b", 1)) // own bucket
	mu.Lock()
	now = now.Add(100 * time.Millisecond)
	mu.Unlock()
	submit(t, h.eng, event("a", 3))
}

func TestLowDiskRefusesIngest(t *testing.T) {
	var mu sync.Mutex
	free := uint64(100)
	cfg := limitsCfg(Limits{MinFreeDiskBytes: 1000, DiskCheckInterval: time.Hour})
	cfg.FreeDisk = func(string) (uint64, uint64, error) { mu.Lock(); defer mu.Unlock(); return free, 1 << 20, nil }
	h := start(t, t.TempDir(), cfg)
	bp := trySubmit(t, h.eng, event("a", 1))
	wantReason(t, bp, ReasonDisk)
	if !strings.Contains(bp.Error(), "100 bytes free") {
		t.Fatalf("error %q", bp.Error())
	}
	if u := h.eng.Usage(); !u.DiskLow || u.DiskFree != 100 || u.UnanchoredEvents != 0 {
		t.Fatalf("usage %+v", u)
	}
	mu.Lock()
	free = 5000
	mu.Unlock()
	h.eng.checkDisk()
	submit(t, h.eng, event("a", 1))
}

// ---------------------------------------------------------------- with a worker

// fakeChain anchors with per-agent epoch ids; while down, every call fails.
type fakeChain struct {
	mu     sync.Mutex
	down   bool
	delay  time.Duration
	epochs map[[32]byte]uint64
	res    map[anchor.Request]anchor.Result
}

func newFakeChain() *fakeChain {
	return &fakeChain{epochs: map[[32]byte]uint64{}, res: map[anchor.Request]anchor.Result{}}
}

func (c *fakeChain) setDown(d bool) { c.mu.Lock(); c.down = d; c.mu.Unlock() }

func (c *fakeChain) Anchor(ctx context.Context, req anchor.Request) (anchor.Result, error) {
	c.mu.Lock()
	d := c.delay
	c.mu.Unlock()
	time.Sleep(d)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.down {
		return anchor.Result{}, errors.New("rpc down")
	}
	if r, ok := c.res[req]; ok {
		return r, nil
	}
	c.epochs[req.AgentKey]++
	r := anchor.Result{EpochID: c.epochs[req.AgentKey], TxHash: "0x01", BlockNumber: 1, Finality: "depth:0"}
	c.res[req] = r
	return r, nil
}

func (c *fakeChain) Final(_ context.Context, req anchor.Request) (anchor.Status, anchor.Result, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.down {
		return anchor.Pending, anchor.Result{}, errors.New("rpc down")
	}
	return anchor.Final, c.res[req], nil
}

func (c *fakeChain) Release(anchor.Request) error { return nil }

// startWithWorker runs an engine with a real anchor worker on chain.
func startWithWorker(t *testing.T, dir string, cfg Config, chain anchor.Chain) *Engine {
	t.Helper()
	w := anchor.NewWorker(chain, anchor.WorkerOptions{Backoff: anchor.Backoff{Initial: time.Millisecond, Max: 20 * time.Millisecond},
		FinalityPoll: 5 * time.Millisecond}, nil)
	h := startWith(t, dir, cfg, w)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); w.Run(ctx) }()
	t.Cleanup(func() { h.stop(); cancel(); <-done })
	return h.eng
}

// submitRetrying submits ev, re-sending it on backpressure like the SDK does.
// It returns the number of backpressure rejections.
func submitRetrying(t *testing.T, e *Engine, ev canonical.Event, deadline time.Time) int {
	t.Helper()
	for n := 0; ; n++ {
		bp := trySubmit(t, e, ev)
		if bp == nil {
			return n
		}
		if time.Now().After(deadline) {
			t.Fatalf("event %s/%d still refused: %v", ev.AgentID, ev.StepNumber, bp)
		}
		time.Sleep(min(bp.RetryAfter, 5*time.Millisecond))
	}
}

func waitAnchored(t *testing.T, e *Engine, agent string, upTo uint64, within time.Duration) time.Duration {
	t.Helper()
	start := time.Now()
	for e.anchoredSeq(agent) < upTo {
		if time.Since(start) > within {
			t.Fatalf("agent %s: anchored seq %d < %d after %v", agent, e.anchoredSeq(agent), upTo, within)
		}
		time.Sleep(2 * time.Millisecond)
	}
	return time.Since(start)
}

// M6: an agent flooding past its quota gets backpressure, while another
// agent's events are still anchored promptly.
func TestFloodingAgentDoesNotStarveOthers(t *testing.T) {
	chain := newFakeChain()
	chain.delay = 25 * time.Millisecond // each anchor takes a while
	cfg := Config{EpochInterval: 10 * time.Millisecond, EpochMaxLogs: 5, ChainID: "31337", Contract: "0xc0ffee",
		Limits: Limits{MaxAgentEvents: 400}}
	e := startWithWorker(t, t.TempDir(), cfg, chain)

	stop := make(chan struct{})
	var floodRejected, floodAccepted int
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for step := uint64(1); ; step++ {
			select {
			case <-stop:
				return
			default:
			}
			p, _ := Prepare(event("flood", step))
			ch, err := e.Submit(context.Background(), p)
			if err != nil {
				floodRejected++
				step--
				time.Sleep(time.Millisecond)
				continue
			}
			<-ch
			floodAccepted++
		}
	}()
	// Let the flooder build a backlog of sealed epochs at its quota.
	deadline := time.Now().Add(5 * time.Second)
	for e.Usage().Rejected[ReasonAgentEvents] == 0 {
		if time.Now().After(deadline) {
			t.Fatal("flooder never hit its quota")
		}
		time.Sleep(time.Millisecond)
	}
	// The quiet agent's five events, submitted together, form one epoch.
	var chans []<-chan Result
	for step := uint64(1); step <= 5; step++ {
		p, _ := Prepare(event("quiet", step))
		ch, err := e.Submit(context.Background(), p)
		if err != nil {
			t.Fatal(err)
		}
		chans = append(chans, ch)
	}
	var last Result
	for _, ch := range chans {
		if last = <-ch; last.Err != nil {
			t.Fatal(last.Err)
		}
	}
	took := waitAnchored(t, e, "quiet", last.Seq, 3*time.Second)
	close(stop)
	wg.Wait()
	if floodRejected == 0 || floodAccepted == 0 {
		t.Fatalf("flood accepted %d rejected %d", floodAccepted, floodRejected)
	}
	// In FIFO order the quiet agent's epoch would wait behind the flooder's
	// backlog of up to 80 epochs (2s of anchoring); taken in turn it waits
	// for about one.
	if took > time.Second {
		t.Fatalf("quiet agent's events took %v to anchor", took)
	}
	if u := e.Usage(); u.Agents["flood"].Events > 400 {
		t.Fatalf("flooder over quota: %+v", u.Agents["flood"])
	}
	t.Logf("quiet agent anchored in %v while the flooder had %d accepted, %d refused", took, floodAccepted, floodRejected)
}

// M6: during an RPC outage the anchor queue fills and ingest refuses events
// (retryable); nothing acknowledged is lost, and after recovery every
// accepted event is anchored, exactly once.
func TestRPCOutageBackpressureLosesNothing(t *testing.T) {
	chain := newFakeChain()
	chain.setDown(true)
	cfg := Config{EpochInterval: 5 * time.Millisecond, EpochMaxLogs: 4, ChainID: "31337", Contract: "0xc0ffee",
		Limits: Limits{MaxAnchorQueue: 3}}
	dir := t.TempDir()
	e := startWithWorker(t, dir, cfg, chain)

	accepted := map[string]bool{}
	step := uint64(1)
	deadline := time.Now().Add(5 * time.Second)
	var refused *BackpressureError
	for refused == nil {
		if time.Now().After(deadline) {
			t.Fatal("ingest never backpressured")
		}
		ev := event("agent", step)
		if refused = trySubmit(t, e, ev); refused == nil {
			p, _ := Prepare(ev)
			accepted[canonical.Digest(p.Digest).Hex()] = true
			step++
		}
		time.Sleep(time.Millisecond)
	}
	wantReason(t, refused, ReasonAnchorQueue)
	if e.Usage().AnchorQueue < 3 {
		t.Fatalf("usage %+v", e.Usage())
	}
	// Still refused a while later: the queue does not drain while the RPC is down.
	time.Sleep(30 * time.Millisecond)
	wantReason(t, trySubmit(t, e, event("agent", step)), ReasonAnchorQueue)

	chain.setDown(false)
	// The refused event, re-sent, and a few more get in after recovery.
	for end := step + 5; step < end; step++ {
		ev := event("agent", step)
		submitRetrying(t, e, ev, time.Now().Add(5*time.Second))
		p, _ := Prepare(ev)
		accepted[canonical.Digest(p.Digest).Hex()] = true
	}
	deadline = time.Now().Add(5 * time.Second)
	for e.Usage().UnanchoredEvents > 0 {
		if time.Now().After(deadline) {
			t.Fatalf("not all anchored: %+v", e.Usage())
		}
		time.Sleep(2 * time.Millisecond)
	}
	// Every accepted event is in exactly one bundle.
	key := canonical.AgentKey("agent")
	found := map[string]int{}
	for ep := uint64(1); ; ep++ {
		b, err := e.Store().ReadBundle(key.Hex(), ep)
		if err != nil {
			break
		}
		for _, ev := range b.Events {
			if canonical.Digest(canonical.ContentDigest([]byte(ev.CanonicalEvent))).Hex() != ev.ContentDigest {
				t.Fatalf("bundle %d: event bytes do not match digest", ep)
			}
			found[ev.ContentDigest]++
		}
	}
	for d := range accepted {
		if found[d] != 1 {
			t.Fatalf("accepted event %s anchored %d times", d, found[d])
		}
	}
	if len(found) != len(accepted) {
		t.Fatalf("bundles hold %d events, %d accepted", len(found), len(accepted))
	}
	t.Logf("%d events accepted and anchored across the outage", len(accepted))
}

func paddedEvent(agent string, step uint64, pad int) canonical.Event {
	ev := event(agent, step)
	ev.PayloadJSON = []byte(fmt.Sprintf(`{"pad":%q,"step":%d}`, strings.Repeat("x", pad), step))
	sign(&ev)
	return ev
}

func heapInUse() uint64 {
	var m runtime.MemStats
	for i := 0; i < 3; i++ {
		runtime.GC()
	}
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// M6: sealed (and open) epochs hold digests and WAL locations, not payloads:
// the engine's memory does not grow with payload size.
func TestEpochMemoryDoesNotGrowWithPayloadSize(t *testing.T) {
	const events = 300
	grow := func(pad int) uint64 {
		h := start(t, t.TempDir(), slowCfg())
		before := heapInUse()
		for i := uint64(1); i <= events; i++ {
			submit(t, h.eng, paddedEvent("a", i, pad))
			if i%100 == 0 {
				h.eng.SealAll(context.Background()) // sealed, never anchored
			}
		}
		after := heapInUse()
		if n := h.sink.len(); n != 3 {
			t.Fatalf("%d sealed epochs", n)
		}
		runtime.KeepAlive(h)
		if after < before {
			return 0
		}
		return after - before
	}
	small, large := grow(16), grow(64<<10)
	payload := uint64(events * (64 << 10))
	t.Logf("heap growth: %d bytes with 16-byte payloads, %d with 64 KiB payloads (%d payload bytes)", small, large, payload)
	if large > small+payload/20 {
		t.Fatalf("heap grew by %d bytes with 64 KiB payloads vs %d with tiny ones: payloads are kept in memory", large, small)
	}
}

// M6: a restart replays a large, many-segment WAL streaming, without loading
// it into memory, and rebuilds the sealed and open epochs.
func TestRecoverLargeWALStreaming(t *testing.T) {
	dir := t.TempDir()
	h := start(t, dir, slowCfg()) // 1 MiB segments
	const events, pad = 600, 16 << 10
	for i := uint64(1); i <= events; i++ {
		submit(t, h.eng, paddedEvent("a", i, pad))
		if i == 400 {
			h.eng.SealAll(context.Background())
		}
	}
	roots := h.sink.take()
	h.stop()

	before := heapInUse()
	h2 := start(t, dir, slowCfg())
	after := heapInUse()
	walBytes := uint64(h2.wal.Bytes())
	if h2.wal.Segments() < 5 || walBytes < events*pad {
		t.Fatalf("WAL %d bytes in %d segments: not large", walBytes, h2.wal.Segments())
	}
	jobs := h2.sink.take()
	if len(jobs) != 1 || jobs[0].Root != roots[0].Root || jobs[0].Count != 400 {
		t.Fatalf("requeued %d jobs", len(jobs))
	}
	if n := h2.eng.shard("a").size(); n != 200 {
		t.Fatalf("reopened %d events, want 200", n)
	}
	if u := h2.eng.Usage(); u.UnanchoredEvents != events || u.UnanchoredBytes < events*pad {
		t.Fatalf("usage after recovery %+v", u)
	}
	growth := int64(after) - int64(before)
	t.Logf("WAL %d bytes; heap growth across recovery %d bytes", walBytes, growth)
	if growth > int64(walBytes/4) {
		t.Fatalf("recovery kept %d bytes for a %d-byte WAL", growth, walBytes)
	}
	// The recovered epoch's bundle is written from the WAL.
	if err := jobs[0].Done(context.Background(), anchor.Result{EpochID: 1}); err != nil {
		t.Fatal(err)
	}
	b, err := h2.st.ReadBundle(canonical.AgentKey("a").Hex(), 1)
	if err != nil || len(b.Events) != 400 || !strings.Contains(b.Events[399].CanonicalEvent, `"step":400`) {
		t.Fatalf("bundle: %v", err)
	}
}
