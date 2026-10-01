// Package anchor commits sealed epoch roots to the VeriLogRegistry contract.
//
// Worker is a queue of sealed epochs processed by a single goroutine in two
// stages. The send stage anchors the jobs one transaction at a time from the
// daemon's single signer, and moves on as soon as a transaction is mined. It
// takes the agents in turn (round-robin, each agent's epochs oldest first),
// so one agent's backlog cannot hold up the other agents' epochs; a job is
// retried until it is mined before the next one is picked. The finality stage watches the mined anchors and
// completes a job (evidence bundle, checkpoint, WAL compaction) only once its
// anchor is final, strictly in queue order. Sending the next epoch while an
// earlier one awaits finality keeps nonce ordering safe because every
// transaction is persisted before broadcast, a new nonce is always above
// every nonce still awaiting finality, and a reorg is answered by sending the
// same signed transaction (same nonce) again; see EthChain.
//
// A job is retried with exponential backoff until it succeeds or the daemon
// stops; jobs are never dropped (on restart they are rebuilt from the WAL).
// Finality waits never block sealing or ingest: Enqueue never blocks.
package anchor

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"
)

// Request is one root to anchor.
type Request struct {
	AgentKey [32]byte
	Root     [32]byte
	Count    uint32
}

// Result is an anchor. Chain.Anchor returns it once mined; Chain.Final
// returns it, re-read at the final block, with the finality fields set.
type Result struct {
	EpochID     uint64
	TxHash      string // empty if recovered from chain state without locating the tx
	BlockNumber uint64
	BlockHash   string
	// Finality is the finality mode under which the anchor was judged final
	// (e.g. "finalized" or "depth:12"); FinalBlockNumber and FinalBlockHash
	// identify the final block at which the anchor was re-read.
	Finality         string
	FinalBlockNumber uint64
	FinalBlockHash   string
}

// Status is the finality of a mined anchor.
type Status int

const (
	// Pending: not final yet (or the finality check could not tell).
	Pending Status = iota
	// Final: the anchor is in a final block and was re-read there.
	Final
	// Reanchor: the anchor is gone for good (its nonce was used by another
	// transaction, or the chain disagrees with the receipt): anchor again.
	Reanchor
)

func (s Status) String() string {
	switch s {
	case Final:
		return "final"
	case Reanchor:
		return "reanchor"
	default:
		return "pending"
	}
}

// Chain anchors requests and judges their finality.
type Chain interface {
	// Anchor sends req (or resumes its earlier transaction) and waits until
	// it is mined. It must be idempotent across retries of the same request.
	Anchor(ctx context.Context, req Request) (Result, error)
	// Final reports whether the mined anchor of req is final.
	Final(ctx context.Context, req Request) (Status, Result, error)
	// Release forgets req's anchor once the job is complete.
	Release(req Request) error
}

// Retainer is implemented by a Chain that persists anchors across restarts:
// Retain drops the anchors of requests no longer queued (completed before a
// crash, but not yet released).
type Retainer interface {
	Retain(reqs []Request) error
}

// Job is a request plus the completion callback run once the anchor is
// final. Done is retried with backoff until it returns nil.
type Job struct {
	Request
	Label string // for logs
	Done  func(ctx context.Context, res Result) error
}

// Backoff configures retry delays.
type Backoff struct {
	Initial time.Duration
	Max     time.Duration
}

func (b Backoff) delay(attempt int) time.Duration {
	d := b.Initial
	for i := 1; i < attempt && d < b.Max; i++ {
		d *= 2
	}
	d = min(d, b.Max)
	// +/-20% jitter.
	return time.Duration(float64(d) * (0.8 + 0.4*rand.Float64()))
}

// WorkerOptions configures a Worker.
type WorkerOptions struct {
	Backoff Backoff
	// FinalityPoll is how often the oldest mined anchor is checked for
	// finality (default 5s).
	FinalityPoll time.Duration
	// FinalityTimeout: an anchor that is not final this long after it was
	// mined is logged at ERROR, again every further FinalityTimeout. It is
	// never dropped: its events stay in the WAL. Default 30m.
	FinalityTimeout time.Duration
}

// Worker processes anchor jobs.
type Worker struct {
	chain Chain
	opts  WorkerOptions
	log   *slog.Logger

	mu     sync.Mutex
	queue  []*item
	notify chan struct{}

	// Owned by the Run goroutine.
	nextFinal time.Time
	current   *item               // job being sent, until it is mined
	served    map[[32]byte]uint64 // agent key -> turn it was last picked in
	turn      uint64

	// Published by the Run goroutine for Stats (guarded by mu).
	mined       int
	oldestMined time.Time
}

// WorkerStats is a snapshot of the queue.
type WorkerStats struct {
	Queued int // jobs not completed
	Mined  int // of which mined and awaiting finality
	// FinalityLag is how long the oldest mined anchor has awaited finality.
	FinalityLag time.Duration
}

// Stats returns a snapshot of the queue.
func (w *Worker) Stats() WorkerStats {
	w.mu.Lock()
	defer w.mu.Unlock()
	st := WorkerStats{Queued: len(w.queue), Mined: w.mined}
	if !w.oldestMined.IsZero() {
		st.FinalityLag = time.Since(w.oldestMined)
	}
	return st
}

// publish refreshes the figures Stats reports (Run goroutine).
func (w *Worker) publish() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.mined, w.oldestMined = 0, time.Time{}
	for _, it := range w.queue {
		if it.mined {
			w.mined++
			if w.oldestMined.IsZero() || it.minedAt.Before(w.oldestMined) {
				w.oldestMined = it.minedAt
			}
		}
	}
}

// item is a queued job and its progress (owned by the Run goroutine, except
// for the queue slice itself).
type item struct {
	Job
	mined          bool
	minedAt        time.Time
	attempts       int
	nextTry        time.Time
	nextTimeoutLog time.Time
}

// NewWorker returns a worker using chain.
func NewWorker(chain Chain, opts WorkerOptions, logger *slog.Logger) *Worker {
	if logger == nil {
		logger = slog.Default()
	}
	if opts.Backoff.Initial <= 0 {
		opts.Backoff.Initial = 500 * time.Millisecond
	}
	if opts.Backoff.Max < opts.Backoff.Initial {
		opts.Backoff.Max = 30 * time.Second
	}
	if opts.FinalityPoll <= 0 {
		opts.FinalityPoll = 5 * time.Second
	}
	if opts.FinalityTimeout <= 0 {
		opts.FinalityTimeout = 30 * time.Minute
	}
	return &Worker{chain: chain, opts: opts, log: logger, notify: make(chan struct{}, 1), served: map[[32]byte]uint64{}}
}

// Enqueue adds a job to the end of the queue. It never blocks.
func (w *Worker) Enqueue(j Job) {
	w.mu.Lock()
	w.queue = append(w.queue, &item{Job: j})
	w.mu.Unlock()
	w.wake()
}

func (w *Worker) wake() {
	select {
	case w.notify <- struct{}{}:
	default:
	}
}

// Pending returns the number of jobs not yet completed (sent or not).
func (w *Worker) Pending() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.queue)
}

func (w *Worker) items() []*item {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]*item(nil), w.queue...)
}

func (w *Worker) head() *item {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.queue) == 0 {
		return nil
	}
	return w.queue[0]
}

func (w *Worker) pop() {
	w.mu.Lock()
	w.queue[0] = nil
	w.queue = w.queue[1:]
	w.mu.Unlock()
}

// Run processes jobs until ctx is cancelled. Unfinished jobs stay queued.
func (w *Worker) Run(ctx context.Context) {
	if r, ok := w.chain.(Retainer); ok {
		var reqs []Request
		for _, it := range w.items() {
			reqs = append(reqs, it.Request)
		}
		if err := r.Retain(reqs); err != nil {
			w.log.Warn("anchor: pruning completed anchors failed", "err", err)
		}
	}
	for {
		ok := w.finalize(ctx)
		w.publish()
		if !ok || ctx.Err() != nil {
			return
		}
		sent := w.send(ctx)
		w.publish()
		if sent {
			continue
		}
		t := time.NewTimer(w.idle())
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-w.notify:
			t.Stop()
		case <-t.C:
		}
	}
}

// idle is how long Run may sleep before there is work to do.
func (w *Worker) idle() time.Duration {
	wait := time.Hour
	now := time.Now()
	if h := w.head(); h != nil && h.mined {
		wait = min(wait, w.nextFinal.Sub(now))
	}
	if it := w.next(); it != nil {
		wait = min(wait, it.nextTry.Sub(now))
	}
	return max(wait, 0)
}

// next picks the job to send: the job being sent until it is mined; else a
// job whose anchor was lost (Reanchor), which keeps its place; else the
// oldest job of the agent whose turn it is. The pick is moved to the front
// of the unmined jobs, so queue order stays the order anchors are sent in,
// which is the order finalize completes them in.
func (w *Worker) next() *item {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.current != nil && !w.current.mined {
		for _, it := range w.queue {
			if it == w.current {
				return it
			}
		}
	}
	w.current = nil
	k := -1
	for i, it := range w.queue {
		if !it.mined {
			k = i
			break
		}
	}
	if k < 0 {
		return nil
	}
	pick := k
	for _, it := range w.queue[k:] {
		if it.mined { // a reanchor ahead of mined jobs: send it first
			w.current = w.queue[k]
			return w.current
		}
	}
	seen := map[[32]byte]bool{}
	for i := k; i < len(w.queue); i++ {
		a := w.queue[i].AgentKey
		if seen[a] {
			continue
		}
		seen[a] = true
		if w.served[a] < w.served[w.queue[pick].AgentKey] {
			pick = i
		}
	}
	it := w.queue[pick]
	copy(w.queue[k+1:pick+1], w.queue[k:pick])
	w.queue[k] = it
	w.turn++
	w.served[it.AgentKey] = w.turn
	if len(w.served) > 2*len(w.queue)+64 {
		keep := make(map[[32]byte]uint64, len(w.queue))
		for _, q := range w.queue {
			keep[q.AgentKey] = w.served[q.AgentKey]
		}
		w.served = keep
	}
	w.current = it
	return it
}

// send anchors the next job (see next), if its retry time has come. It
// reports whether it tried.
func (w *Worker) send(ctx context.Context) bool {
	it := w.next()
	if it == nil || time.Now().Before(it.nextTry) {
		return false
	}
	res, err := w.chain.Anchor(ctx, it.Request)
	if err != nil {
		if ctx.Err() != nil {
			return true
		}
		it.attempts++
		d := w.opts.Backoff.delay(it.attempts)
		it.nextTry = time.Now().Add(d)
		w.log.Warn("anchor: attempt failed, retrying", "stage", "anchor", "epoch", it.Label, "attempt", it.attempts,
			"retry_in", d.Round(time.Millisecond), "err", err)
		return true
	}
	it.mined, it.minedAt, it.attempts = true, time.Now(), 0
	it.nextTimeoutLog = it.minedAt.Add(w.opts.FinalityTimeout)
	w.log.Debug("anchor: mined, awaiting finality", "epoch", it.Label, "on_chain_epoch", res.EpochID, "tx", res.TxHash)
	return true
}

// finalize completes, in queue order, the jobs whose anchors are final. It
// returns false only if ctx ended.
func (w *Worker) finalize(ctx context.Context) bool {
	for {
		it := w.head()
		if it == nil || !it.mined || time.Now().Before(w.nextFinal) {
			return true
		}
		st, res, err := w.chain.Final(ctx, it.Request)
		if err != nil {
			if ctx.Err() != nil {
				return false
			}
			w.log.Warn("anchor: finality check failed, retrying", "epoch", it.Label, "retry_in", w.opts.FinalityPoll, "err", err)
		}
		switch {
		case err != nil || st == Pending:
			w.nextFinal = time.Now().Add(w.opts.FinalityPoll)
			if now := time.Now(); !now.Before(it.nextTimeoutLog) {
				w.log.Error("anchor: epoch not final yet; its events stay in the WAL until it is",
					"epoch", it.Label, "mined_ago", now.Sub(it.minedAt).Round(time.Second), "tx", res.TxHash,
					"block", res.BlockNumber, "hint", "check the RPC endpoint and the chain's finality; see --finality")
				it.nextTimeoutLog = now.Add(w.opts.FinalityTimeout)
			}
			return true
		case st == Reanchor:
			w.log.Warn("anchor: anchoring the epoch again", "epoch", it.Label)
			it.mined, it.attempts, it.nextTry = false, 0, time.Time{}
			w.current = nil // it keeps its place at the head
			return true
		}
		if _, ok := retry(ctx, w, "finalize", it.Label, func() (struct{}, error) { return struct{}{}, it.Done(ctx, res) }); !ok {
			return false
		}
		if err := w.chain.Release(it.Request); err != nil {
			w.log.Warn("anchor: releasing a completed anchor failed", "epoch", it.Label, "err", err)
		}
		w.pop()
	}
}

// retry runs fn until it succeeds or ctx ends; ok is false if ctx ended first.
func retry[T any](ctx context.Context, w *Worker, stage, label string, fn func() (T, error)) (T, bool) {
	for attempt := 1; ; attempt++ {
		v, err := fn()
		if err == nil {
			return v, true
		}
		var zero T
		if ctx.Err() != nil {
			return zero, false
		}
		d := w.opts.Backoff.delay(attempt)
		w.log.Warn("anchor: attempt failed, retrying", "stage", stage, "epoch", label, "attempt", attempt, "retry_in", d.Round(time.Millisecond), "err", err)
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
			return zero, false
		case <-t.C:
		}
	}
}
