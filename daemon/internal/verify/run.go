package verify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/ronitspatil/verilog/daemon/internal/canonical"
	"github.com/ronitspatil/verilog/daemon/internal/merkle"
)

// EpochEvidence is the full content of one anchored epoch, as read from an
// evidence bundle. It is untrusted until its events rebuild the on-chain root.
type EpochEvidence struct {
	Source   string            // where it was read from (for messages)
	AgentKey *canonical.Digest // agent key the bundle claims; nil if absent or unreadable
	EpochID  uint64
	Events   [][]byte // the epoch's events in leaf order, as hashed
}

// RunInput describes a run to verify.
type RunInput struct {
	AgentID string // string id, or 0x-prefixed 32-byte hex agent key
	RunID   string
	// Epochs must cover every epoch anchored for the agent (1..latestEpoch).
	// Evidence of other agents and other runs may be included; it is ignored.
	Epochs []EpochEvidence
	// AllowIncomplete accepts a run without a terminal run_end event, with
	// the distinct verdict Incomplete. Truncation cannot be told apart from
	// an agent crash, so this is for investigations only.
	AllowIncomplete bool
}

// RunReport is the outcome of a completed run verification.
type RunReport struct {
	Verified bool
	// Incomplete is set (with Verified) when the run was accepted without a
	// run_end because of AllowIncomplete. It is not a full pass.
	Incomplete  bool
	Reason      string   // why verification failed (empty on success)
	Warnings    []string // evidence that was ignored, and why
	AgentKey    canonical.Digest
	RunID       string
	AgentEpochs uint64   // epochs anchored for the agent (all were checked)
	Events      int      // distinct events of the run
	LastStep    uint64   // highest step seen
	Epochs      []uint64 // epochs the run's events are anchored in (earliest valid copy), ascending
	SDKDropped  uint64   // events the SDK reported as dropped (sdk_dropped)
	EndStatus   string   // status in the run_end payload, if present
}

// runEvent is one distinct event (by content digest) of the run.
type runEvent struct {
	ev     canonical.Event
	raw    []byte
	digest canonical.Digest
	copies []uint64 // epochs holding a copy, ascending
	epoch  uint64   // decisive copy: the earliest anchored copy that verifies
}

// Run verifies one run against the complete evidence of its agent.
//
//  1. Completeness: the evidence must hold every epoch 1..latestEpoch of the
//     agent, and each epoch's event list must rebuild its on-chain root with
//     a count equal to logCount. The verifier therefore sees every anchored
//     copy of every event, so a daemon cannot hide an early copy by
//     presenting only later re-anchored ones.
//  2. Every event of the run (events of other runs and other agents are
//     skipped) must be in canonical form, carry a valid signature by a
//     well-formed key registered for the agent, and have at least one
//     anchored copy whose epoch was anchored while the key was valid. The
//     earliest such copy decides the event's epoch; other copies (a replay
//     anchored after the key was revoked, say) only produce a warning.
//  3. The hash chain: one event per step from step 1 with a zero prev_hash,
//     each prev_hash the previous event's content digest, no event in an
//     earlier epoch than its predecessor, nothing after run_end, and run_end
//     as the last event.
//
// Defects in the evidence are a FAILURE (Verified false); only RPC errors are
// returned as an *OperationalError.
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
	warn := func(format string, a ...any) { rep.Warnings = append(rep.Warnings, fmt.Sprintf(format, a...)) }

	latestBig, err := v.reg.LatestEpoch(v.call(ctx, v.at), agentKey)
	if err != nil {
		return nil, opErr("RPC error reading latestEpoch: %v", err)
	}
	if !latestBig.IsUint64() {
		return fail("latestEpoch is out of range")
	}
	latest := latestBig.Uint64()
	rep.AgentEpochs = latest
	// The verdict is reached on the final epochs 1..latest only. Epochs
	// anchored after the final block may still be reorged away: one that
	// holds events of the run makes the run "not anchored yet" (no verdict);
	// others are set aside with a warning.
	finalEvidence, err := v.setAsideNotFinal(ctx, agentKey, in.RunID, latest, in.Epochs, warn)
	if err != nil {
		return nil, err
	}
	in.Epochs = finalEvidence
	if latest == 0 {
		return fail("no epoch is anchored on chain for agent key %s, so run %q was never anchored", agentKey.Hex(), in.RunID)
	}

	// 1. Complete, root-checked evidence for every epoch.
	byEpoch := map[uint64][]*EpochEvidence{}
	for i := range in.Epochs {
		e := &in.Epochs[i]
		if e.AgentKey != nil && *e.AgentKey != agentKey {
			continue // another agent's bundle
		}
		if e.EpochID == 0 || e.EpochID > latest {
			warn("ignored %s: epoch %d is not anchored for this agent (latest epoch is %d)", e.Source, e.EpochID, latest)
			continue
		}
		byEpoch[e.EpochID] = append(byEpoch[e.EpochID], e)
	}
	content := make([][][]byte, latest+1)
	var missing []uint64
	var mismatched []string
	for ep := uint64(1); ep <= latest; ep++ {
		cands := byEpoch[ep]
		if len(cands) == 0 {
			missing = append(missing, ep)
			continue
		}
		anc, err := v.anchor(ctx, agentKey, ep)
		if err != nil {
			return nil, err
		}
		var firstReason string
		var ignored []string
		for _, c := range cands {
			reason := matchAnchor(c.Events, anc)
			if reason == "" {
				if content[ep] == nil {
					content[ep] = c.Events
				}
				continue
			}
			if firstReason == "" {
				firstReason = reason
			}
			ignored = append(ignored, fmt.Sprintf("ignored %s for epoch %d: %s", c.Source, ep, reason))
		}
		if content[ep] == nil {
			mismatched = append(mismatched, fmt.Sprintf("epoch %d: %s", ep, firstReason))
			continue
		}
		for _, w := range ignored {
			warn("%s", w)
		}
	}
	if len(missing) > 0 {
		return fail("evidence is incomplete: no evidence bundle for epoch(s) %s of the %d epochs anchored for this agent "+
			"(run mode needs every epoch, so that no anchored copy of an event can be hidden)", ranges(missing), latest)
	}
	if len(mismatched) > 0 {
		return fail("evidence does not match the on-chain anchors (events withheld, added, reordered or altered): %s",
			strings.Join(mismatched, "; "))
	}

	// 2. Collect the run's events with every anchored copy.
	byDigest := map[canonical.Digest]*runEvent{}
	var order []*runEvent
	unparsed := 0
	for ep := uint64(1); ep <= latest; ep++ {
		for _, raw := range content[ep] {
			ev, err := canonical.ParseEvent(raw)
			if err != nil {
				unparsed++
				continue
			}
			if ev.RunID != in.RunID || canonical.AgentKey(ev.AgentID) != agentKey {
				continue // another run, or an event of another agent inside this agent's epoch
			}
			d := canonical.ContentDigest(raw)
			re := byDigest[d]
			if re == nil {
				re = &runEvent{ev: ev, raw: raw, digest: d}
				byDigest[d] = re
				order = append(order, re)
			}
			if n := len(re.copies); n == 0 || re.copies[n-1] != ep {
				re.copies = append(re.copies, ep)
			}
		}
	}
	if unparsed > 0 {
		warn("%d anchored entries of this agent are not VeriLog events and were skipped", unparsed)
	}
	if len(order) == 0 {
		return fail("no events of run %q in any of the %d epochs anchored for agent key %s", in.RunID, latest, agentKey.Hex())
	}

	// Decide each event by its earliest valid copy.
	var invalid []*runEvent
	reasons := map[*runEvent]string{}
	for _, re := range order {
		reason, err := v.decide(ctx, agentKey, re, warn)
		if err != nil {
			return nil, err
		}
		if reason != "" {
			invalid = append(invalid, re)
			reasons[re] = reason
		}
	}
	if len(invalid) > 0 {
		sort.SliceStable(invalid, func(i, j int) bool { return invalid[i].ev.StepNumber < invalid[j].ev.StepNumber })
		re := invalid[0]
		return fail("step %d (epoch %d): %s", re.ev.StepNumber, re.copies[0], reasons[re])
	}

	// 3. One event per step: two validly signed events at the same step are a fork.
	bySteps := map[uint64]*runEvent{}
	epochs := map[uint64]bool{}
	for _, e := range order {
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

	// The chain is contiguous from genesis and epochs never go backwards.
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
		warn("%s (accepted as INCOMPLETE because of --allow-incomplete: a truncated run cannot be told apart from an agent crash)", msg)
		rep.Incomplete = true
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

// decide checks one event of the run and sets re.epoch to its earliest
// anchored copy that verifies. It returns why no copy verifies ("" if one
// does); copies that do not verify next to one that does are warnings.
func (v *Verifier) decide(ctx context.Context, agentKey canonical.Digest, re *runEvent, warn func(string, ...any)) (string, error) {
	canon, err := re.ev.Canonical()
	if err != nil {
		return fmt.Sprintf("event cannot be canonicalized: %v", err), nil
	}
	if !bytes.Equal(canon, re.raw) {
		return fmt.Sprintf("anchored event %s is not in canonical form, so it is not what the agent signed", re.digest.Hex()), nil
	}
	var firstReason string
	var rejected []string
	for _, ep := range re.copies {
		anc, err := v.anchor(ctx, agentKey, ep)
		if err != nil {
			return "", err
		}
		reason, _, err := v.checkSource(ctx, agentKey, re.ev, ep, anc.timestamp)
		if err != nil {
			return "", err
		}
		if reason == "" {
			if re.epoch == 0 {
				re.epoch = ep
			}
			continue
		}
		if firstReason == "" {
			firstReason = reason
		}
		rejected = append(rejected, fmt.Sprintf("epoch %d (%s)", ep, reason))
	}
	if re.epoch == 0 {
		return firstReason, nil
	}
	for _, r := range rejected {
		warn("step %d: a copy anchored in %s was ignored; the event verifies by its copy in epoch %d", re.ev.StepNumber, r, re.epoch)
	}
	return "", nil
}

// matchAnchor reports why events do not rebuild the anchored epoch ("" if
// they do): the same number of events as logCount, and the same Merkle root.
func matchAnchor(events [][]byte, anc anchorInfo) string {
	if len(events) != int(anc.count) {
		return fmt.Sprintf("it holds %d events, the on-chain anchor counts %d", len(events), anc.count)
	}
	leaves := make([]merkle.Hash, len(events))
	for i, ev := range events {
		leaves[i] = merkle.LeafFromDigest(canonical.ContentDigest(ev))
	}
	tree, err := merkle.Build(leaves)
	if err != nil {
		return err.Error()
	}
	if root := canonical.Digest(tree.Root()); root != anc.root {
		return fmt.Sprintf("its events rebuild root %s, the on-chain root is %s", root.Hex(), anc.root.Hex())
	}
	return ""
}

// ranges formats ascending numbers as "1-3, 5".
func ranges(ns []uint64) string {
	var parts []string
	for i := 0; i < len(ns); {
		j := i
		for j+1 < len(ns) && ns[j+1] == ns[j]+1 {
			j++
		}
		if i == j {
			parts = append(parts, fmt.Sprint(ns[i]))
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", ns[i], ns[j]))
		}
		i = j + 1
	}
	return strings.Join(parts, ", ")
}

// setAsideNotFinal removes from evidence the bundles of epochs anchored at
// the head but not at the final block (latestFinal). If one of them matches
// its head anchor and holds events of the run, the run cannot be judged yet:
// an *OperationalError. Without a pinned final block nothing is set aside.
func (v *Verifier) setAsideNotFinal(ctx context.Context, agentKey canonical.Digest, runID string, latestFinal uint64,
	evidence []EpochEvidence, warn func(string, ...any)) ([]EpochEvidence, error) {
	if v.at == nil {
		return evidence, nil
	}
	headBig, err := v.reg.LatestEpoch(v.call(ctx, nil), agentKey)
	if err != nil {
		return nil, opErr("RPC error reading latestEpoch: %v", err)
	}
	if !headBig.IsUint64() || headBig.Uint64() <= latestFinal {
		return evidence, nil
	}
	headLatest := headBig.Uint64()
	var kept []EpochEvidence
	var pending []uint64
	for _, e := range evidence {
		if (e.AgentKey != nil && *e.AgentKey != agentKey) || e.EpochID <= latestFinal || e.EpochID > headLatest {
			kept = append(kept, e)
			continue
		}
		anc, err := v.headAnchor(ctx, agentKey, e.EpochID)
		if err != nil {
			return nil, err
		}
		if matchAnchor(e.Events, anc) == "" && holdsRun(e.Events, runID, agentKey) {
			pending = append(pending, e.EpochID)
			continue
		}
		warn("ignored %s: epoch %d is not final at block %s", e.Source, e.EpochID, v.at)
	}
	if len(pending) > 0 {
		sort.Slice(pending, func(i, j int) bool { return pending[i] < pending[j] })
		return nil, &OperationalError{Err: notFinalErr{fmt.Sprintf("epoch(s) %s hold events of run %q but are not final at block %s (final epochs: 1-%d): "+
			"the run is not anchored yet; retry once they are final (see --finality)", ranges(pending), runID, v.at, latestFinal)}}
	}
	return kept, nil
}

func holdsRun(events [][]byte, runID string, agentKey canonical.Digest) bool {
	for _, raw := range events {
		if ev, err := canonical.ParseEvent(raw); err == nil && ev.RunID == runID && canonical.AgentKey(ev.AgentID) == agentKey {
			return true
		}
	}
	return false
}
