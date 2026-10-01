// Package engine is the core of the VeriLog daemon.
//
// Data flow:
//
//	ingest handlers ──Submit──▶ submit channel ──▶ committer goroutine
//	                                                 │ assign seq, group-commit to WAL (one fsync)
//	                                                 │ append leaves to per-agent shards
//	                                                 ▼ resolve each submitter's result (ack)
//	sealer goroutine ── every EpochInterval, or when a shard reaches EpochMaxLogs:
//	   swap the shard's tree for a fresh one (ingestion never waits on hashing),
//	   build the root, commit a "sealed" WAL record, enqueue an anchor job.
//	anchor worker ── anchors sealed epochs one at a time, then finalize():
//	   write the evidence bundle, advance the checkpoint, compact the WAL.
//
// Durability: an event is acknowledged only after its WAL record is fsynced.
// On restart, Recover replays the WAL: sealed-but-unanchored epochs are
// rebuilt (and their roots re-checked) and re-queued for anchoring, and the
// remaining unanchored events reopen each agent's current epoch.
package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ronitspatil/verilog/daemon/internal/anchor"
	"github.com/ronitspatil/verilog/daemon/internal/canonical"
	"github.com/ronitspatil/verilog/daemon/internal/merkle"
	"github.com/ronitspatil/verilog/daemon/internal/store"
	"github.com/ronitspatil/verilog/daemon/internal/wal"
)

// ErrClosed is returned by Submit after the engine has stopped.
var ErrClosed = errors.New("engine: closed")

// Config tunes the engine.
type Config struct {
	EpochInterval time.Duration // seal every non-empty epoch this often
	EpochMaxLogs  int           // seal an agent's epoch once it holds this many events
	CommitBatch   int           // max submissions per WAL fsync
	SubmitQueue   int           // capacity of the submit channel (backpressure point)
	ChainID       string        // recorded in evidence bundles
	Contract      string        // recorded in evidence bundles
}

// Enqueuer receives sealed epochs for anchoring (anchor.Worker).
type Enqueuer interface {
	Enqueue(anchor.Job)
}

// Prepared is a validated, canonicalized event ready to commit.
type Prepared struct {
	AgentID   string
	Canonical []byte
	Digest    [32]byte // SHA-256 of Canonical
	Leaf      [32]byte // keccak256(Digest)
}

// Prepare canonicalizes and hashes an event.
func Prepare(ev canonical.Event) (Prepared, error) {
	canon, err := ev.Canonical()
	if err != nil {
		return Prepared{}, err
	}
	d := canonical.ContentDigest(canon)
	return Prepared{AgentID: ev.AgentID, Canonical: canon, Digest: d, Leaf: merkle.LeafFromDigest(d)}, nil
}

// Result is the outcome of one submission.
type Result struct {
	Seq       uint64 // WAL sequence (for duplicates: of the original event)
	LeafIndex int    // index in the agent's open epoch
	Duplicate bool
	Err       error
}

// Stats are cumulative counters.
type Stats struct {
	Accepted, Duplicates, SealedEpochs, AnchoredEpochs uint64
}

type entry struct {
	seq       uint64
	canonical []byte
	digest    [32]byte
	leaf      merkle.Hash
}

// shard holds one agent's open epoch.
type shard struct {
	agentID  string
	agentKey canonical.Digest

	mu      sync.Mutex
	tree    *merkle.Tree
	entries []entry
	seen    map[[32]byte]entry // content digest -> entry, for duplicate detection
}

func newShard(agentID string) *shard {
	s := &shard{agentID: agentID, agentKey: canonical.AgentKey(agentID)}
	s.reset()
	return s
}

func (s *shard) reset() {
	s.tree = merkle.NewTree(0)
	s.entries = nil
	s.seen = map[[32]byte]entry{}
}

// append adds a committed entry and returns its leaf index and the new size.
func (s *shard) append(e entry) (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := s.tree.Append(e.leaf)
	s.entries = append(s.entries, e)
	s.seen[e.digest] = e
	return idx, len(s.entries)
}

func (s *shard) lookup(digest [32]byte) (entry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.seen[digest]
	return e, ok
}

func (s *shard) size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// swap detaches the open epoch, leaving a fresh one in place.
func (s *shard) swap() (*merkle.Tree, []entry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tree, entries := s.tree, s.entries
	s.reset()
	return tree, entries
}

// sealedEpoch is an epoch awaiting anchoring.
type sealedEpoch struct {
	agentID  string
	agentKey canonical.Digest
	entries  []entry
	tree     *merkle.Sealed
}

func (b *sealedEpoch) label() string {
	return fmt.Sprintf("%s[seq %d-%d]", b.agentID, b.entries[0].seq, b.entries[len(b.entries)-1].seq)
}

type submission struct {
	// event submission
	prep   Prepared
	result chan Result
	// seal-record submission
	seal *wal.Record
	done chan error
}

// Engine coordinates ingestion, sealing and anchoring.
type Engine struct {
	cfg    Config
	log    *slog.Logger
	wal    *wal.Log
	store  *store.Store
	anchor Enqueuer

	submitCh   chan *submission
	sealNotify chan struct{}
	// closeMu makes "check closed + send on submitCh" atomic with respect to
	// Close, so nothing can be queued after the committer's final drain.
	closeMu   sync.RWMutex
	isClosed  bool
	closed    chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup

	shardsMu sync.RWMutex
	shards   map[string]*shard

	nextSeq uint64 // owned by the committer after Recover

	cpMu       sync.Mutex
	checkpoint store.Checkpoint

	accepted, duplicates, sealed, anchored atomic.Uint64
	fatal                                  chan error
}

// New creates an engine. Call Recover with the WAL's records, then Start.
func New(cfg Config, w *wal.Log, st *store.Store, enq Enqueuer, logger *slog.Logger) (*Engine, error) {
	if cfg.EpochInterval <= 0 || cfg.EpochMaxLogs <= 0 {
		return nil, errors.New("engine: EpochInterval and EpochMaxLogs must be positive")
	}
	if cfg.EpochMaxLogs > 1<<30 {
		return nil, errors.New("engine: EpochMaxLogs too large (logCount is uint32 on chain)")
	}
	if cfg.CommitBatch <= 0 {
		cfg.CommitBatch = 4096
	}
	if cfg.SubmitQueue <= 0 {
		cfg.SubmitQueue = 16384
	}
	if logger == nil {
		logger = slog.Default()
	}
	cp, err := st.LoadCheckpoint()
	if err != nil {
		return nil, err
	}
	return &Engine{
		cfg: cfg, log: logger, wal: w, store: st, anchor: enq,
		submitCh:   make(chan *submission, cfg.SubmitQueue),
		sealNotify: make(chan struct{}, 1),
		closed:     make(chan struct{}),
		shards:     map[string]*shard{},
		nextSeq:    1,
		checkpoint: cp,
		fatal:      make(chan error, 1),
	}, nil
}

func (e *Engine) shard(agentID string) *shard {
	e.shardsMu.RLock()
	s := e.shards[agentID]
	e.shardsMu.RUnlock()
	if s != nil {
		return s
	}
	e.shardsMu.Lock()
	defer e.shardsMu.Unlock()
	if s = e.shards[agentID]; s == nil {
		s = newShard(agentID)
		e.shards[agentID] = s
	}
	return s
}

func (e *Engine) anchoredSeq(agentID string) uint64 {
	e.cpMu.Lock()
	defer e.cpMu.Unlock()
	return e.checkpoint.Agents[agentID].AnchoredSeq
}

// Recover rebuilds state from WAL records. It must run before Start.
func (e *Engine) Recover(recs []wal.Record) error {
	type agentLog struct {
		events []wal.Record
		seals  []wal.Record
	}
	logs := map[string]*agentLog{}
	var order []string
	var maxSeq uint64
	for _, r := range recs {
		if r.Seq > maxSeq {
			maxSeq = r.Seq
		}
		if r.LastSeq > maxSeq {
			maxSeq = r.LastSeq
		}
		anchored := e.anchoredSeq(r.AgentID)
		l := logs[r.AgentID]
		if l == nil {
			l = &agentLog{}
			logs[r.AgentID] = l
			order = append(order, r.AgentID)
		}
		switch r.Type {
		case wal.TypeEvent:
			if r.Seq > anchored {
				l.events = append(l.events, r)
			}
		case wal.TypeSealed:
			if r.LastSeq > anchored {
				l.seals = append(l.seals, r)
			}
		}
	}
	e.cpMu.Lock()
	for _, p := range e.checkpoint.Agents {
		maxSeq = max(maxSeq, p.AnchoredSeq)
	}
	e.cpMu.Unlock()
	e.nextSeq = maxSeq + 1

	toEntry := func(r wal.Record) entry {
		d := canonical.ContentDigest(r.Event)
		return entry{seq: r.Seq, canonical: []byte(r.Event), digest: d, leaf: merkle.LeafFromDigest(d)}
	}
	var requeued, reopened int
	for _, agentID := range order {
		l := logs[agentID]
		i := 0
		for _, s := range l.seals {
			var entries []entry
			for i < len(l.events) && l.events[i].Seq <= s.LastSeq {
				if l.events[i].Seq < s.FirstSeq {
					return fmt.Errorf("engine: recover %s: event seq %d precedes sealed epoch [%d,%d] and is not anchored",
						agentID, l.events[i].Seq, s.FirstSeq, s.LastSeq)
				}
				entries = append(entries, toEntry(l.events[i]))
				i++
			}
			b, err := e.buildSealed(agentID, entries)
			if err != nil {
				return fmt.Errorf("engine: recover %s epoch [%d,%d]: %w", agentID, s.FirstSeq, s.LastSeq, err)
			}
			if got := canonical.Digest(b.tree.Root()).Hex(); got != s.Root || len(entries) != s.Count {
				return fmt.Errorf("engine: recover %s epoch [%d,%d]: rebuilt root %s/%d events does not match sealed root %s/%d",
					agentID, s.FirstSeq, s.LastSeq, got, len(entries), s.Root, s.Count)
			}
			e.enqueueAnchor(b)
			requeued++
		}
		sh := e.shard(agentID)
		for ; i < len(l.events); i++ {
			sh.append(toEntry(l.events[i]))
			reopened++
		}
	}
	e.log.Info("engine: recovered from WAL", "records", len(recs), "requeued_epochs", requeued, "reopened_events", reopened, "next_seq", e.nextSeq)
	return nil
}

func (e *Engine) buildSealed(agentID string, entries []entry) (*sealedEpoch, error) {
	if len(entries) == 0 {
		return nil, merkle.ErrEmptyTree
	}
	leaves := make([]merkle.Hash, len(entries))
	for i, en := range entries {
		leaves[i] = en.leaf
	}
	tree, err := merkle.Build(leaves)
	if err != nil {
		return nil, err
	}
	return &sealedEpoch{agentID: agentID, agentKey: canonical.AgentKey(agentID), entries: entries, tree: tree}, nil
}

// Start launches the committer and sealer. Fatal errors (WAL failure) are
// reported on Fatal(); the engine stops accepting events after one.
func (e *Engine) Start(ctx context.Context) {
	e.wg.Add(2)
	go func() { defer e.wg.Done(); e.commitLoop() }()
	go func() { defer e.wg.Done(); e.sealLoop(ctx) }()
}

// Fatal delivers an unrecoverable error (at most one).
func (e *Engine) Fatal() <-chan error { return e.fatal }

// Close stops accepting submissions, drains the ones already queued and
// waits for the background goroutines. Open epochs are not sealed; they are
// replayed from the WAL on the next start. The sealer stops when the ctx
// given to Start is cancelled.
func (e *Engine) Close() {
	e.closeOnce.Do(func() {
		e.closeMu.Lock()
		e.isClosed = true
		close(e.closed)
		e.closeMu.Unlock()
	})
	e.wg.Wait()
}

// send queues a submission unless the engine is closed. While a send is in
// progress Close waits, and the committer is still running to consume it.
func (e *Engine) send(ctx context.Context, sub *submission) error {
	e.closeMu.RLock()
	defer e.closeMu.RUnlock()
	if e.isClosed {
		return ErrClosed
	}
	select {
	case e.submitCh <- sub:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Submit queues a prepared event. The returned channel yields exactly one
// Result once the event is durable (or rejected). Submit blocks only when the
// submit queue is full (backpressure).
func (e *Engine) Submit(ctx context.Context, p Prepared) (<-chan Result, error) {
	sub := &submission{prep: p, result: make(chan Result, 1)}
	if err := e.send(ctx, sub); err != nil {
		return nil, err
	}
	return sub.result, nil
}

func (e *Engine) commitLoop() {
	batch := make([]*submission, 0, e.cfg.CommitBatch)
	for {
		select {
		case sub := <-e.submitCh:
			batch = append(batch[:0], sub)
		case <-e.closed:
			// Drain what was queued before Close.
			for {
				select {
				case sub := <-e.submitCh:
					e.commit([]*submission{sub})
				default:
					return
				}
			}
		}
	drain:
		for len(batch) < e.cfg.CommitBatch {
			select {
			case sub := <-e.submitCh:
				batch = append(batch, sub)
			default:
				break drain
			}
		}
		e.commit(batch)
	}
}

// commit writes one group of submissions with a single fsync. It runs only
// on the committer goroutine, which therefore owns seq assignment and the
// order in which leaves are appended to shards (= WAL order).
func (e *Engine) commit(batch []*submission) {
	type pendingEvent struct {
		sub   *submission
		shard *shard
		entry entry
		dupOf *entry // set for duplicates
	}
	var recs []wal.Record
	events := make([]pendingEvent, 0, len(batch))
	inBatch := map[string]map[[32]byte]entry{}

	for _, sub := range batch {
		if sub.seal != nil {
			recs = append(recs, *sub.seal)
			continue
		}
		p := sub.prep
		sh := e.shard(p.AgentID)
		if prev, ok := sh.lookup(p.Digest); ok {
			events = append(events, pendingEvent{sub: sub, dupOf: &prev})
			continue
		}
		if m := inBatch[p.AgentID]; m != nil {
			if prev, ok := m[p.Digest]; ok {
				events = append(events, pendingEvent{sub: sub, dupOf: &prev})
				continue
			}
		} else {
			inBatch[p.AgentID] = map[[32]byte]entry{}
		}
		en := entry{seq: e.nextSeq, canonical: p.Canonical, digest: p.Digest, leaf: p.Leaf}
		e.nextSeq++
		inBatch[p.AgentID][p.Digest] = en
		recs = append(recs, wal.Record{Type: wal.TypeEvent, AgentID: p.AgentID, Seq: en.seq, Event: p.Canonical})
		events = append(events, pendingEvent{sub: sub, shard: sh, entry: en})
	}

	if err := e.wal.Write(recs); err != nil {
		e.log.Error("engine: WAL write failed; rejecting batch", "err", err)
		select {
		case e.fatal <- err:
		default:
		}
		for _, sub := range batch {
			if sub.seal != nil {
				sub.done <- err
			} else {
				sub.result <- Result{Err: fmt.Errorf("event not persisted: %w", err)}
			}
		}
		return
	}

	needSeal := false
	for _, pe := range events {
		if pe.dupOf != nil {
			e.duplicates.Add(1)
			pe.sub.result <- Result{Seq: pe.dupOf.seq, Duplicate: true, LeafIndex: -1}
			continue
		}
		idx, n := pe.shard.append(pe.entry)
		e.accepted.Add(1)
		pe.sub.result <- Result{Seq: pe.entry.seq, LeafIndex: idx}
		if n >= e.cfg.EpochMaxLogs {
			needSeal = true
		}
	}
	for _, sub := range batch {
		if sub.seal != nil {
			sub.done <- nil
		}
	}
	if needSeal {
		select {
		case e.sealNotify <- struct{}{}:
		default:
		}
	}
}

func (e *Engine) sealLoop(ctx context.Context) {
	tick := time.NewTicker(e.cfg.EpochInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-e.closed:
			return
		case <-tick.C:
			e.sealWhere(ctx, func(n int) bool { return n > 0 })
		case <-e.sealNotify:
			e.sealWhere(ctx, func(n int) bool { return n >= e.cfg.EpochMaxLogs })
		}
	}
}

// SealAll seals every non-empty open epoch now (used by tests and shutdown tooling).
func (e *Engine) SealAll(ctx context.Context) error {
	return e.sealWhere(ctx, func(n int) bool { return n > 0 })
}

func (e *Engine) sealWhere(ctx context.Context, pred func(int) bool) error {
	e.shardsMu.RLock()
	shards := make([]*shard, 0, len(e.shards))
	for _, s := range e.shards {
		shards = append(shards, s)
	}
	e.shardsMu.RUnlock()
	for _, s := range shards {
		if !pred(s.size()) {
			continue
		}
		if err := e.seal(ctx, s); err != nil {
			e.log.Error("engine: sealing failed", "agent", s.agentID, "err", err)
			return err
		}
	}
	return nil
}

// seal closes a shard's open epoch. The swap holds the shard lock only for a
// pointer exchange; root computation and the WAL write happen outside it.
func (e *Engine) seal(ctx context.Context, s *shard) error {
	tree, entries := s.swap()
	if len(entries) == 0 {
		return nil
	}
	snap, err := tree.Seal()
	if err != nil {
		return err
	}
	b := &sealedEpoch{agentID: s.agentID, agentKey: s.agentKey, entries: entries, tree: snap}
	rec := &wal.Record{
		Type: wal.TypeSealed, AgentID: s.agentID,
		FirstSeq: entries[0].seq, LastSeq: entries[len(entries)-1].seq,
		Count: len(entries), Root: canonical.Digest(snap.Root()).Hex(),
	}
	// The seal must be durable before anchoring, so a crash can never anchor
	// a grouping that replay would not reproduce.
	sub := &submission{seal: rec, done: make(chan error, 1)}
	if err := e.send(ctx, sub); err != nil {
		// Not sealed: put nothing back; the events remain in the WAL and are
		// reopened on restart. Only happens during shutdown.
		return err
	}
	if err := <-sub.done; err != nil {
		// Events stay durable in the WAL; replay will reopen them.
		return err
	}
	e.sealed.Add(1)
	e.log.Info("engine: epoch sealed", "agent", s.agentID, "events", len(entries), "root", rec.Root, "first_seq", rec.FirstSeq, "last_seq", rec.LastSeq)
	e.enqueueAnchor(b)
	return nil
}

func (e *Engine) enqueueAnchor(b *sealedEpoch) {
	e.anchor.Enqueue(anchor.Job{
		Request: anchor.Request{AgentKey: b.agentKey, Root: b.tree.Root(), Count: uint32(len(b.entries))},
		Label:   b.label(),
		Done:    func(ctx context.Context, res anchor.Result) error { return e.finalize(b, res) },
	})
}

// finalize persists the evidence bundle and advances the checkpoint.
func (e *Engine) finalize(b *sealedEpoch, res anchor.Result) error {
	bundle := &store.Bundle{
		Version:     store.BundleVersion,
		HashScheme:  store.HashScheme,
		AgentID:     b.agentID,
		AgentKey:    b.agentKey.Hex(),
		EpochID:     res.EpochID,
		MerkleRoot:  canonical.Digest(b.tree.Root()).Hex(),
		LogCount:    len(b.entries),
		ChainID:     e.cfg.ChainID,
		Contract:    e.cfg.Contract,
		TxHash:      res.TxHash,
		BlockNumber: res.BlockNumber,
		AnchoredAt:  time.Now().UTC(),
		Events:      make([]store.EventProof, len(b.entries)),
	}
	for i, en := range b.entries {
		proof, err := b.tree.Proof(i)
		if err != nil {
			return err
		}
		ps := make([]string, len(proof))
		for j, p := range proof {
			ps[j] = canonical.Digest(p).Hex()
		}
		bundle.Events[i] = store.EventProof{
			LeafIndex:      i,
			Seq:            en.seq,
			ContentDigest:  canonical.Digest(en.digest).Hex(),
			Leaf:           canonical.Digest(en.leaf).Hex(),
			Proof:          ps,
			CanonicalEvent: string(en.canonical),
		}
	}
	if err := e.store.WriteBundle(bundle); err != nil {
		return fmt.Errorf("writing evidence bundle: %w", err)
	}

	lastSeq := b.entries[len(b.entries)-1].seq
	e.cpMu.Lock()
	prev := e.checkpoint.Agents[b.agentID]
	if lastSeq > prev.AnchoredSeq {
		e.checkpoint.Agents[b.agentID] = store.AgentProgress{AnchoredSeq: lastSeq, Epoch: res.EpochID}
	}
	cp := store.Checkpoint{Agents: make(map[string]store.AgentProgress, len(e.checkpoint.Agents))}
	for k, v := range e.checkpoint.Agents {
		cp.Agents[k] = v
	}
	err := e.store.SaveCheckpoint(cp)
	if err != nil {
		e.checkpoint.Agents[b.agentID] = prev
	}
	e.cpMu.Unlock()
	if err != nil {
		return fmt.Errorf("saving checkpoint: %w", err)
	}

	e.anchored.Add(1)
	e.log.Info("engine: epoch anchored", "agent", b.agentID, "epoch", res.EpochID, "events", len(b.entries), "tx", res.TxHash, "block", res.BlockNumber,
		"bundle", e.store.BundlePath(bundle.AgentKey, bundle.EpochID))

	if n, err := e.wal.Compact(e.anchoredSeq); err != nil {
		e.log.Warn("engine: WAL compaction failed", "err", err)
	} else if n > 0 {
		e.log.Info("engine: WAL segments compacted", "removed", n)
	}
	return nil
}

// Stats returns cumulative counters.
func (e *Engine) Stats() Stats {
	return Stats{
		Accepted:       e.accepted.Load(),
		Duplicates:     e.duplicates.Load(),
		SealedEpochs:   e.sealed.Load(),
		AnchoredEpochs: e.anchored.Load(),
	}
}

// Store returns the evidence store.
func (e *Engine) Store() *store.Store { return e.store }
