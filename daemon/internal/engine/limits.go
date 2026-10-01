package engine

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Limits bound the resources unanchored events may hold. An event is
// unanchored from the moment it is admitted until its epoch's anchor is
// final (or it is left out of its epoch at seal time). Every limit is checked
// when an event is submitted, before it is acknowledged: an event over a limit
// is refused with a *BackpressureError and never written, so nothing that was
// acknowledged is ever dropped. Zero disables a limit.
type Limits struct {
	// MaxAgentEvents and MaxAgentBytes cap one agent's unanchored events and
	// canonical bytes, so a flooding agent cannot crowd out the others.
	MaxAgentEvents int64
	MaxAgentBytes  int64
	// MaxTotalBytes caps the canonical bytes of all unanchored events (WAL
	// growth during an RPC outage).
	MaxTotalBytes int64
	// MaxAnchorQueue caps the sealed epochs whose anchor is not final yet.
	MaxAnchorQueue int
	// AgentRate (events per second) and AgentBurst rate-limit each agent's
	// ingest with a token bucket.
	AgentRate  float64
	AgentBurst int
	// MinFreeDiskBytes: ingest is refused while the data directory's file
	// system has less free space than this (checked every DiskCheckInterval).
	MinFreeDiskBytes  uint64
	DiskCheckInterval time.Duration
}

// Backpressure reasons, as reported in BackpressureError.Reason and metrics.
const (
	ReasonDisk        = "disk_low"
	ReasonAnchorQueue = "anchor_queue_full"
	ReasonTotalBytes  = "unanchored_bytes"
	ReasonAgentEvents = "agent_unanchored_events"
	ReasonAgentBytes  = "agent_unanchored_bytes"
	ReasonAgentRate   = "agent_rate"
)

// Reasons lists every backpressure reason.
var Reasons = []string{ReasonDisk, ReasonAnchorQueue, ReasonTotalBytes, ReasonAgentEvents, ReasonAgentBytes, ReasonAgentRate}

// BackpressureError refuses an event for now: the identical event may be
// sent again after RetryAfter. Nothing was written.
type BackpressureError struct {
	Reason     string
	Detail     string
	RetryAfter time.Duration
}

func (e *BackpressureError) Error() string {
	return fmt.Sprintf("backpressure (%s): %s; retry in %s", e.Reason, e.Detail, e.RetryAfter)
}

// FreeDiskFunc reports the free and total bytes of the file system holding path.
type FreeDiskFunc func(path string) (free, total uint64, err error)

type agentUsage struct {
	events, bytes int64
	// token bucket
	tokens float64
	last   time.Time
	// last backpressure warning logged for the agent
	warned time.Time
}

// usage is the accounting of unanchored events (guarded by Engine.limMu).
type usage struct {
	agents      map[string]*agentUsage
	totalEvents int64
	totalBytes  int64
	queued      int // sealed epochs awaiting a final anchor
	rejected    map[string]uint64
	diskFree    uint64
	diskTotal   uint64
	diskLow     bool
}

// Usage is a snapshot of resource usage.
type Usage struct {
	UnanchoredEvents int64
	UnanchoredBytes  int64
	AnchorQueue      int
	Agents           map[string]AgentUsage
	Rejected         map[string]uint64 // by reason
	WALBytes         int64
	DiskFree         uint64
	DiskTotal        uint64
	DiskLow          bool
}

// AgentUsage is one agent's unanchored events and bytes.
type AgentUsage struct{ Events, Bytes int64 }

func (e *Engine) agentUsage(agentID string) *agentUsage {
	a := e.use.agents[agentID]
	if a == nil {
		a = &agentUsage{tokens: float64(e.cfg.Limits.AgentBurst), last: e.now()}
		e.use.agents[agentID] = a
	}
	return a
}

// admit reserves room for one event of n canonical bytes, or refuses it.
func (e *Engine) admit(agentID string, n int64) error {
	l := e.cfg.Limits
	e.limMu.Lock()
	defer e.limMu.Unlock()
	a := e.agentUsage(agentID)
	var bp *BackpressureError
	switch {
	case e.use.diskLow:
		bp = &BackpressureError{ReasonDisk, fmt.Sprintf("data directory has %d bytes free, below --min-free-disk-bytes %d",
			e.use.diskFree, l.MinFreeDiskBytes), 10 * time.Second}
	case l.MaxAnchorQueue > 0 && e.use.queued >= l.MaxAnchorQueue:
		bp = &BackpressureError{ReasonAnchorQueue, fmt.Sprintf("%d sealed epochs await anchoring (--max-anchor-queue)", e.use.queued), 5 * time.Second}
	case l.MaxTotalBytes > 0 && e.use.totalBytes+n > l.MaxTotalBytes && e.use.totalEvents > 0:
		bp = &BackpressureError{ReasonTotalBytes, fmt.Sprintf("%d unanchored bytes in total (--max-unanchored-bytes)", e.use.totalBytes), 5 * time.Second}
	case l.MaxAgentEvents > 0 && a.events+1 > l.MaxAgentEvents:
		bp = &BackpressureError{ReasonAgentEvents, fmt.Sprintf("agent %q has %d unanchored events (--max-agent-unanchored-events)", agentID, a.events), 2 * time.Second}
	case l.MaxAgentBytes > 0 && a.bytes+n > l.MaxAgentBytes && a.events > 0:
		bp = &BackpressureError{ReasonAgentBytes, fmt.Sprintf("agent %q has %d unanchored bytes (--max-agent-unanchored-bytes)", agentID, a.bytes), 2 * time.Second}
	case l.AgentRate > 0:
		now := e.now()
		a.tokens = min(float64(l.AgentBurst), a.tokens+now.Sub(a.last).Seconds()*l.AgentRate)
		a.last = now
		if a.tokens < 1 {
			wait := time.Duration((1 - a.tokens) / l.AgentRate * float64(time.Second))
			bp = &BackpressureError{ReasonAgentRate, fmt.Sprintf("agent %q exceeds %g events/s (--agent-rate)", agentID, l.AgentRate), max(wait, 10*time.Millisecond)}
			break
		}
		a.tokens--
	}
	if bp != nil {
		e.use.rejected[bp.Reason]++
		if now := e.now(); now.Sub(a.warned) >= 30*time.Second {
			a.warned = now
			e.log.Warn("engine: backpressure: refusing events for now (retryable)", "agent", agentID, "reason", bp.Reason, "detail", bp.Detail)
		}
		return bp
	}
	a.events++
	a.bytes += n
	e.use.totalEvents++
	e.use.totalBytes += n
	return nil
}

// addUsage accounts events found unanchored in the WAL at recovery.
func (e *Engine) addUsage(agentID string, events, bytes int64) {
	e.limMu.Lock()
	defer e.limMu.Unlock()
	a := e.agentUsage(agentID)
	a.events += events
	a.bytes += bytes
	e.use.totalEvents += events
	e.use.totalBytes += bytes
}

// release returns room taken by events that are anchored, left out of their
// epoch, duplicates or failed to commit.
func (e *Engine) release(agentID string, events, bytes int64) {
	e.limMu.Lock()
	defer e.limMu.Unlock()
	a := e.agentUsage(agentID)
	a.events -= events
	a.bytes -= bytes
	e.use.totalEvents -= events
	e.use.totalBytes -= bytes
	if a.events <= 0 && e.cfg.Limits.AgentRate == 0 {
		delete(e.use.agents, agentID)
	}
}

func (e *Engine) queueDelta(d int) {
	e.limMu.Lock()
	e.use.queued += d
	e.limMu.Unlock()
}

// Usage returns a snapshot of resource usage.
func (e *Engine) Usage() Usage {
	e.limMu.Lock()
	u := Usage{
		UnanchoredEvents: e.use.totalEvents,
		UnanchoredBytes:  e.use.totalBytes,
		AnchorQueue:      e.use.queued,
		Agents:           make(map[string]AgentUsage, len(e.use.agents)),
		Rejected:         make(map[string]uint64, len(Reasons)),
		DiskFree:         e.use.diskFree,
		DiskTotal:        e.use.diskTotal,
		DiskLow:          e.use.diskLow,
	}
	for id, a := range e.use.agents {
		if a.events > 0 {
			u.Agents[id] = AgentUsage{Events: a.events, Bytes: a.bytes}
		}
	}
	for _, r := range Reasons {
		u.Rejected[r] = e.use.rejected[r]
	}
	e.limMu.Unlock()
	u.WALBytes = e.wal.Bytes()
	return u
}

// TopAgents returns up to n agents with the most unanchored bytes.
func (u Usage) TopAgents(n int) []string {
	ids := make([]string, 0, len(u.Agents))
	for id := range u.Agents {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		bi, bj := u.Agents[ids[i]].Bytes, u.Agents[ids[j]].Bytes
		return bi > bj || (bi == bj && ids[i] < ids[j])
	})
	return ids[:min(n, len(ids))]
}

// checkDisk refreshes the free-space reading and the low-disk state.
func (e *Engine) checkDisk() {
	if e.cfg.FreeDisk == nil {
		return
	}
	free, total, err := e.cfg.FreeDisk(e.store.Dir())
	if err != nil {
		e.log.Warn("engine: cannot read free disk space", "dir", e.store.Dir(), "err", err)
		return
	}
	minFree := e.cfg.Limits.MinFreeDiskBytes
	e.limMu.Lock()
	wasLow := e.use.diskLow
	e.use.diskFree, e.use.diskTotal = free, total
	e.use.diskLow = minFree > 0 && free < minFree
	low := e.use.diskLow
	e.limMu.Unlock()
	switch {
	case low && (!wasLow || e.now().Sub(e.diskLogged) >= time.Minute):
		e.diskLogged = e.now()
		e.log.Error("engine: data directory is low on disk space; refusing new events (retryable) until space is freed",
			"dir", e.store.Dir(), "free_bytes", free, "total_bytes", total, "min_free_disk_bytes", minFree, "wal_bytes", e.wal.Bytes())
	case !low && wasLow:
		e.log.Info("engine: disk space recovered; accepting events again", "free_bytes", free)
	}
}

func (e *Engine) diskLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	t := time.NewTicker(e.cfg.Limits.DiskCheckInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-e.closed:
			return
		case <-t.C:
			e.checkDisk()
		}
	}
}
