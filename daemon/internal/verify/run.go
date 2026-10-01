package verify

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/ronitspatil/verilog/daemon/internal/canonical"
	"github.com/ronitspatil/verilog/daemon/internal/merkle"
)

// Evidence is one event with its inclusion proof in an anchored epoch, as
// read from an evidence bundle.
type Evidence struct {
	EpochID   uint64
	EventJSON []byte
	Proof     []merkle.Hash
}

// RunInput describes a run to verify.
type RunInput struct {
	AgentID string // string id, or 0x-prefixed 32-byte hex agent key
	RunID   string
	// Evidence may contain events of other runs; they are ignored.
	Evidence []Evidence
	// AllowIncomplete accepts a run without a terminal run_end event (with a
	// warning). Truncation cannot be told apart from an agent crash, so this
	// is for investigations only.
	AllowIncomplete bool
}

// RunReport is the outcome of a completed run verification.
type RunReport struct {
	Verified   bool
	Reason     string // why verification failed (empty on success)
	Warning    string // set when the run is accepted despite a missing run_end
	AgentKey   canonical.Digest
	RunID      string
	Events     int      // distinct events of the run
	LastStep   uint64   // highest step seen
	Epochs     []uint64 // epochs the run's events are anchored in, ascending
	SDKDropped uint64   // events the SDK reported as dropped (sdk_dropped)
	EndStatus  string   // status in the run_end payload, if present
}

type runEvent struct {
	ev     canonical.Event
	digest canonical.Digest
	epoch  uint64
}

// Run verifies every event of a run (as in single-event mode) and the run's
// hash chain: it must start at step 1 with a zero prev_hash, have no gaps or
// forks, each prev_hash must be the previous event's content digest, no event
// may be anchored in an earlier epoch than its predecessor, and the last
// event must be run_end.
func (v *Verifier) Run(ctx context.Context, in RunInput) (*RunReport, error) {
	if in.RunID == "" {
		return nil, opErr("run id is empty")
	}
	agentKey, _, err := AgentKey(in.AgentID)
	if err != nil {
		return nil, opErr("agent id: %v", err)
	}
	rep := &RunReport{AgentKey: agentKey, RunID: in.RunID}
	fail := func(format string, a ...any) (*RunReport, error) {
		rep.Verified, rep.Reason = false, fmt.Sprintf(format, a...)
		return rep, nil
	}

	// 1. Every event of the run verifies on its own. Events of other runs,
	// and documents that do not parse, cannot be attributed to this run and
	// are skipped; if one of them was this run's, the chain check fails.
	byDigest := map[canonical.Digest]*runEvent{}
	for _, e := range in.Evidence {
		ev, err := canonical.ParseEvent(e.EventJSON)
		if err != nil || ev.RunID != in.RunID {
			continue
		}
		r, err := v.Event(ctx, e.EventJSON, e.Proof, e.EpochID, in.AgentID)
		if err != nil {
			return nil, err
		}
		if !r.Verified {
			return fail("step %d (epoch %d): %s", ev.StepNumber, e.EpochID, r.Reason)
		}
		// A retransmission can be anchored twice; it existed by its earliest anchor.
		if prev, ok := byDigest[r.ContentDigest]; !ok || e.EpochID < prev.epoch {
			byDigest[r.ContentDigest] = &runEvent{ev: ev, digest: r.ContentDigest, epoch: e.EpochID}
		}
	}
	if len(byDigest) == 0 {
		return nil, opErr("no events of run %q for agent key %s in the evidence", in.RunID, agentKey.Hex())
	}

	// 2. One event per step: two validly signed events at the same step are a fork.
	bySteps := map[uint64]*runEvent{}
	epochs := map[uint64]bool{}
	for _, e := range byDigest {
		if other, ok := bySteps[e.ev.StepNumber]; ok {
			return fail("fork: two different signed events at step %d (digests %s and %s); the agent key was misused",
				e.ev.StepNumber, other.digest.Hex(), e.digest.Hex())
		}
		bySteps[e.ev.StepNumber] = e
		epochs[e.epoch] = true
	}
	chain := make([]*runEvent, 0, len(bySteps))
	for _, e := range bySteps {
		chain = append(chain, e)
	}
	sort.Slice(chain, func(i, j int) bool { return chain[i].ev.StepNumber < chain[j].ev.StepNumber })
	rep.Events = len(chain)
	rep.LastStep = chain[len(chain)-1].ev.StepNumber
	for ep := range epochs {
		rep.Epochs = append(rep.Epochs, ep)
	}
	sort.Slice(rep.Epochs, func(i, j int) bool { return rep.Epochs[i] < rep.Epochs[j] })

	// 3. The chain is contiguous from genesis and epochs never go backwards.
	first := chain[0]
	if first.ev.StepNumber != 1 {
		return fail("run does not start at step 1: steps 1-%d are missing", first.ev.StepNumber-1)
	}
	if first.ev.PrevHash != (canonical.Digest{}) {
		return fail("step 1 has a non-zero prev_hash %s: it is not the start of the run", first.ev.PrevHash.Hex())
	}
	for i := 1; i < len(chain); i++ {
		prev, cur := chain[i-1], chain[i]
		switch {
		case cur.ev.StepNumber != prev.ev.StepNumber+1:
			return fail("events missing from the run: step %d is followed by step %d", prev.ev.StepNumber, cur.ev.StepNumber)
		case cur.ev.PrevHash != prev.digest:
			return fail("step %d does not chain to step %d (prev_hash %s, expected %s)",
				cur.ev.StepNumber, prev.ev.StepNumber, cur.ev.PrevHash.Hex(), prev.digest.Hex())
		case prev.epoch > cur.epoch:
			return fail("step %d was anchored in epoch %d, after its successor step %d in epoch %d: it was withheld and reordered",
				prev.ev.StepNumber, prev.epoch, cur.ev.StepNumber, cur.epoch)
		case prev.ev.EventType == canonical.EventRunEnd:
			return fail("events after run_end: step %d follows the terminal event at step %d", cur.ev.StepNumber, prev.ev.StepNumber)
		}
	}
	for _, e := range chain {
		if e.ev.EventType == canonical.EventSDKDropped {
			var p struct {
				Count uint64 `json:"count"`
			}
			if json.Unmarshal(e.ev.PayloadJSON, &p) == nil {
				rep.SDKDropped += p.Count
			}
		}
	}

	// 4. The run is complete.
	last := chain[len(chain)-1]
	if last.ev.EventType != canonical.EventRunEnd {
		msg := fmt.Sprintf("run ended without terminal event after step %d", last.ev.StepNumber)
		if !in.AllowIncomplete {
			return fail("%s", msg)
		}
		rep.Warning = msg + " (accepted because of --allow-incomplete: a truncated run cannot be told apart from an agent crash)"
	} else {
		var p struct {
			Status string `json:"status"`
		}
		if json.Unmarshal(last.ev.PayloadJSON, &p) == nil {
			rep.EndStatus = p.Status
		}
	}
	rep.Verified = true
	return rep, nil
}
