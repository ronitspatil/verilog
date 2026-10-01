// Package anchor commits sealed epoch roots to the VeriLogRegistry contract.
//
// Worker is a FIFO of sealed epochs processed by a single goroutine, so
// transactions from the daemon's signer are submitted strictly one at a time
// (one nonce source) and per-agent epochs are anchored in seal order. A job
// is retried with exponential backoff until it succeeds or the daemon stops;
// jobs are never dropped (on restart they are rebuilt from the WAL).
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

// Result is a confirmed anchor.
type Result struct {
	EpochID     uint64
	TxHash      string // empty if recovered from chain state without locating the tx
	BlockNumber uint64
}

// Chain anchors a request and waits for confirmation. Implementations must
// be idempotent across retries of the same request.
type Chain interface {
	Anchor(ctx context.Context, req Request) (Result, error)
}

// Job is a request plus the completion callback run after confirmation.
// Done is retried with backoff until it returns nil.
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

// Worker processes anchor jobs sequentially.
type Worker struct {
	chain   Chain
	backoff Backoff
	log     *slog.Logger

	mu     sync.Mutex
	queue  []Job
	notify chan struct{}
}

// NewWorker returns a worker using chain.
func NewWorker(chain Chain, backoff Backoff, logger *slog.Logger) *Worker {
	if logger == nil {
		logger = slog.Default()
	}
	if backoff.Initial <= 0 {
		backoff.Initial = 500 * time.Millisecond
	}
	if backoff.Max < backoff.Initial {
		backoff.Max = 30 * time.Second
	}
	return &Worker{chain: chain, backoff: backoff, log: logger, notify: make(chan struct{}, 1)}
}

// Enqueue adds a job to the end of the queue. It never blocks.
func (w *Worker) Enqueue(j Job) {
	w.mu.Lock()
	w.queue = append(w.queue, j)
	w.mu.Unlock()
	select {
	case w.notify <- struct{}{}:
	default:
	}
}

// Pending returns the number of jobs not yet completed (including the current one).
func (w *Worker) Pending() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.queue)
}

func (w *Worker) head() (Job, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.queue) == 0 {
		return Job{}, false
	}
	return w.queue[0], true
}

func (w *Worker) pop() {
	w.mu.Lock()
	w.queue[0] = Job{}
	w.queue = w.queue[1:]
	w.mu.Unlock()
}

// Run processes jobs until ctx is cancelled. Unfinished jobs stay queued.
func (w *Worker) Run(ctx context.Context) {
	for {
		job, ok := w.head()
		if !ok {
			select {
			case <-ctx.Done():
				return
			case <-w.notify:
				continue
			}
		}
		res, ok := retry(ctx, w, "anchor", job.Label, func() (Result, error) { return w.chain.Anchor(ctx, job.Request) })
		if !ok {
			return
		}
		if _, ok := retry(ctx, w, "finalize", job.Label, func() (struct{}, error) { return struct{}{}, job.Done(ctx, res) }); !ok {
			return
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
		d := w.backoff.delay(attempt)
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
