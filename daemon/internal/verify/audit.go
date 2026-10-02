package verify

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/ronitspatil/verilog/daemon/internal/canonical"
)

// ErrNotFinal marks the *OperationalError returned when a run has events in
// an epoch that is anchored at the head but not final at the pinned block:
// the run is not anchored yet, which is neither a pass nor a failure.
var ErrNotFinal = errors.New("not anchored yet")

type notFinalErr struct{ msg string }

func (e notFinalErr) Error() string        { return e.msg }
func (e notFinalErr) Is(target error) bool { return target == ErrNotFinal }

// Anchor is an epoch's anchor as read from the registry at the pinned block.
type Anchor struct {
	Root  canonical.Digest
	Count uint32
	Time  time.Time // block time of the anchor
	Found bool      // false: the epoch is not anchored for the agent
}

// LatestEpoch reads latestEpoch(agentKey) at the pinned block.
func (v *Verifier) LatestEpoch(ctx context.Context, agentKey canonical.Digest) (uint64, error) {
	n, err := v.reg.LatestEpoch(v.call(ctx, v.at), agentKey)
	if err != nil {
		return 0, opErr("RPC error reading latestEpoch: %v", err)
	}
	if !n.IsUint64() {
		return 0, opErr("latestEpoch is out of range")
	}
	return n.Uint64(), nil
}

// Anchor reads an epoch's anchor at the pinned block.
func (v *Verifier) Anchor(ctx context.Context, agentKey canonical.Digest, epoch uint64) (Anchor, error) {
	a, err := v.anchor(ctx, agentKey, epoch)
	if err != nil {
		return Anchor{}, err
	}
	return Anchor{Root: a.root, Count: a.count, Time: time.Unix(int64(a.timestamp), 0).UTC(), Found: a.found}, nil
}

// Audit verdicts of a run.
const (
	VerdictSuccess    = "SUCCESS"
	VerdictFailure    = "FAILURE"
	VerdictIncomplete = "SUCCESS-INCOMPLETE"
	VerdictNotFinal   = "not-final"
)

// AuditInput selects the runs of one agent over an anchor-time window.
type AuditInput struct {
	AgentID string
	// From (inclusive) and To (exclusive) bound the anchor (block) time of
	// the epochs in the window.
	From, To time.Time
	// Evidence is every bundle at hand for the agent (untrusted, as in run mode).
	Evidence        []EpochEvidence
	AllowIncomplete bool
}

// AuditEpoch is one final epoch of the agent (1..latestEpoch).
type AuditEpoch struct {
	EpochID  uint64
	Anchor   Anchor
	InWindow bool
	// Evidence is the bundle that rebuilds the anchor, or (when none does)
	// the first one presented for the epoch; nil if none was.
	Evidence *EpochEvidence
	// Problem says why no bundle rebuilds the anchor ("" when one does).
	Problem string
}

// AuditRun is the verdict on one run with events in the window.
type AuditRun struct {
	RunID   string
	Verdict string
	Reason  string     // why it failed, or why it is not final
	Report  *RunReport // nil when not final
}

// AuditReport is the outcome of Audit.
type AuditReport struct {
	AgentKey    canonical.Digest
	LatestEpoch uint64       // final epochs 1..LatestEpoch were checked
	Epochs      []AuditEpoch // index i is epoch i+1
	Runs        []AuditRun   // in order of first appearance in the window
	Warnings    []string
}

// Audit verifies, with Run, every run of the agent that has events in an
// epoch anchored within [From, To). The evidence each run is verified
// against is exactly what the report's epochs hold (Evidence), plus any
// bundles of epochs not final yet; the latter only serve to detect runs that
// are not anchored yet. Defects in the evidence are reported per epoch and
// fail every run, as in run mode; only RPC errors are returned.
func (v *Verifier) Audit(ctx context.Context, in AuditInput) (*AuditReport, error) {
	agentKey, _, err := AgentKey(in.AgentID)
	if err != nil {
		return nil, opErr("agent id: %v", err)
	}
	latest, err := v.LatestEpoch(ctx, agentKey)
	if err != nil {
		return nil, err
	}
	rep := &AuditReport{AgentKey: agentKey, LatestEpoch: latest}

	byEpoch := map[uint64][]*EpochEvidence{}
	var later []EpochEvidence // bundles beyond the final epochs
	for i := range in.Evidence {
		e := &in.Evidence[i]
		switch {
		case e.AgentKey != nil && *e.AgentKey != agentKey:
			continue
		case e.EpochID == 0:
			rep.Warnings = append(rep.Warnings, fmt.Sprintf("ignored %s: epoch 0", e.Source))
		case e.EpochID > latest:
			later = append(later, *e)
			rep.Warnings = append(rep.Warnings, fmt.Sprintf("not exported: %s (epoch %d is not final at the verdict block; final epochs: %d)",
				e.Source, e.EpochID, latest))
		default:
			byEpoch[e.EpochID] = append(byEpoch[e.EpochID], e)
		}
	}

	evidence := make([]EpochEvidence, 0, latest+uint64(len(later)))
	for ep := uint64(1); ep <= latest; ep++ {
		anc, err := v.Anchor(ctx, agentKey, ep)
		if err != nil {
			return nil, err
		}
		ae := AuditEpoch{EpochID: ep, Anchor: anc, InWindow: !anc.Time.Before(in.From) && anc.Time.Before(in.To)}
		cands := byEpoch[ep]
		sort.SliceStable(cands, func(i, j int) bool { return cands[i].Source < cands[j].Source })
		for _, c := range cands {
			reason := matchAnchor(c.Events, anchorInfo{root: anc.Root, count: anc.Count})
			if reason == "" {
				ae.Evidence, ae.Problem = c, ""
				break
			}
			if ae.Evidence == nil {
				ae.Evidence, ae.Problem = c, fmt.Sprintf("%s does not match the on-chain anchor: %s", c.Source, reason)
			}
		}
		if len(cands) == 0 {
			ae.Problem = "no evidence bundle for this epoch"
		}
		if ae.Evidence != nil {
			evidence = append(evidence, *ae.Evidence)
		}
		rep.Epochs = append(rep.Epochs, ae)
	}
	evidence = append(evidence, later...)

	// The runs with events in the window, in order of first appearance.
	seen := map[string]bool{}
	var runs []string
	for _, ae := range rep.Epochs {
		if !ae.InWindow || ae.Evidence == nil {
			continue
		}
		for _, raw := range ae.Evidence.Events {
			ev, err := canonical.ParseEvent(raw)
			if err != nil || canonical.AgentKey(ev.AgentID) != agentKey || seen[ev.RunID] {
				continue
			}
			seen[ev.RunID] = true
			runs = append(runs, ev.RunID)
		}
	}

	for _, id := range runs {
		r, err := v.Run(ctx, RunInput{AgentID: in.AgentID, RunID: id, Epochs: evidence, AllowIncomplete: in.AllowIncomplete})
		switch {
		case errors.Is(err, ErrNotFinal):
			rep.Runs = append(rep.Runs, AuditRun{RunID: id, Verdict: VerdictNotFinal, Reason: err.Error()})
			continue
		case err != nil:
			return nil, err
		}
		ar := AuditRun{RunID: id, Report: r, Verdict: VerdictSuccess}
		switch {
		case !r.Verified:
			ar.Verdict, ar.Reason = VerdictFailure, r.Reason
		case r.Incomplete:
			ar.Verdict = VerdictIncomplete
		}
		rep.Runs = append(rep.Runs, ar)
	}
	return rep, nil
}
