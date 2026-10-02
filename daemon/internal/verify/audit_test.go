package verify

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ronitspatil/verilog/daemon/internal/canonical"
)

func (e *chainEnv) audit(v *Verifier, in AuditInput) *AuditReport {
	e.t.Helper()
	if v == nil {
		v = e.pinned(nil)
	}
	if in.AgentID == "" {
		in.AgentID = agentID
	}
	if in.Evidence == nil {
		in.Evidence = e.all()
	}
	rep, err := v.Audit(context.Background(), in)
	if err != nil {
		e.t.Fatal(err)
	}
	return rep
}

// anchorTimes returns each epoch's anchor time, epoch 1 first.
func anchorTimes(t *testing.T, e *chainEnv) []time.Time {
	t.Helper()
	v := e.pinned(nil)
	latest, err := v.LatestEpoch(context.Background(), canonicalAgentKey())
	if err != nil {
		t.Fatal(err)
	}
	var out []time.Time
	for ep := uint64(1); ep <= latest; ep++ {
		a, err := v.Anchor(context.Background(), canonicalAgentKey(), ep)
		if err != nil || !a.Found {
			t.Fatalf("epoch %d: %+v %v", ep, a, err)
		}
		out = append(out, a.Time)
	}
	return out
}

func canonicalAgentKey() canonical.Digest {
	k, _, _ := AgentKey(agentID)
	return k
}

func verdicts(rep *AuditReport) string {
	var parts []string
	for _, r := range rep.Runs {
		parts = append(parts, r.RunID+"="+r.Verdict)
	}
	return strings.Join(parts, " ")
}

// Epochs are selected by anchor time, from inclusive and to exclusive; a run
// is in the report when it has events in the window, and is verified
// against every epoch.
func TestAuditSelectsEpochsByAnchorTime(t *testing.T) {
	e := newChainEnv(t)
	a := signedRun(t, "run-a", 2, true)
	b := signedRun(t, "run-b", 4, true)
	c := signedRun(t, "run-c", 2, true)
	e.anchor(a...)
	e.anchor(b[0], b[1])
	e.anchor(b[2], b[3], c[0])
	e.anchor(c[1])
	times := anchorTimes(t, e)

	rep := e.audit(nil, AuditInput{From: times[1], To: times[2]})
	if rep.LatestEpoch != 4 || len(rep.Epochs) != 4 || verdicts(rep) != "run-b=SUCCESS" {
		t.Fatalf("%+v", rep)
	}
	for i, ep := range rep.Epochs {
		if ep.InWindow != (i == 1) || ep.Evidence == nil || ep.Problem != "" || ep.Anchor.Time != times[i] {
			t.Errorf("epoch %d: %+v", i+1, ep)
		}
	}
	if r := rep.Runs[0].Report; r.Events != 4 || r.EndStatus != "ok" || len(r.Epochs) != 2 {
		t.Fatalf("%+v", r)
	}

	// From is inclusive, to exclusive: [t2, t4) holds epochs 2 and 3.
	rep = e.audit(nil, AuditInput{From: times[1], To: times[3]})
	if verdicts(rep) != "run-b=SUCCESS run-c=SUCCESS" {
		t.Fatalf("%s", verdicts(rep))
	}
	// An empty window: no runs, every epoch is context.
	rep = e.audit(nil, AuditInput{From: times[3].Add(time.Second), To: times[3].Add(time.Hour)})
	if len(rep.Runs) != 0 || len(rep.Epochs) != 4 {
		t.Fatalf("%+v", rep)
	}
}

// Defects in the evidence are reported on their epoch and fail every run.
func TestAuditEvidenceProblems(t *testing.T) {
	e := newChainEnv(t)
	run := signedRun(t, "run-p", 3, true)
	e.anchor(run[0])
	e.anchor(run[1], run[2])
	times := anchorTimes(t, e)
	window := AuditInput{From: times[0], To: times[1].Add(time.Second)}

	all := e.all()
	missing := window
	missing.Evidence = all[:1]
	rep := e.audit(nil, missing)
	if rep.Epochs[1].Problem != "no evidence bundle for this epoch" || rep.Epochs[1].Evidence != nil || verdicts(rep) != "run-p=FAILURE" ||
		!strings.Contains(rep.Runs[0].Reason, "evidence is incomplete") {
		t.Fatalf("%+v %+v", rep.Epochs, rep.Runs)
	}

	// A tampered bundle next to the genuine one: the genuine one is used.
	tampered := all[1]
	tampered.Source = "a-tampered"
	tampered.Events = [][]byte{run[1]}
	both := window
	both.Evidence = append([]EpochEvidence{tampered}, all...)
	rep = e.audit(nil, both)
	if rep.Epochs[1].Problem != "" || rep.Epochs[1].Evidence.Source != "epoch-2" || verdicts(rep) != "run-p=SUCCESS" {
		t.Fatalf("%+v %s", rep.Epochs[1], verdicts(rep))
	}

	// Only the tampered one: it is reported, and the run fails.
	only := window
	only.Evidence = []EpochEvidence{all[0], tampered}
	rep = e.audit(nil, only)
	if !strings.Contains(rep.Epochs[1].Problem, "a-tampered does not match the on-chain anchor") || rep.Epochs[1].Evidence.Source != "a-tampered" ||
		verdicts(rep) != "run-p=FAILURE" {
		t.Fatalf("%+v %s", rep.Epochs[1], verdicts(rep))
	}
}

// A run without run_end is a FAILURE, or SUCCESS-INCOMPLETE when allowed.
func TestAuditIncompleteRun(t *testing.T) {
	e := newChainEnv(t)
	e.anchor(append(signedRun(t, "run-ok", 2, true), signedRun(t, "run-open", 2, false)...)...)
	times := anchorTimes(t, e)
	in := AuditInput{From: times[0], To: times[0].Add(time.Second)}
	if rep := e.audit(nil, in); verdicts(rep) != "run-ok=SUCCESS run-open=FAILURE" ||
		!strings.Contains(rep.Runs[1].Reason, "without terminal event") {
		t.Fatalf("%s %+v", verdicts(rep), rep.Runs)
	}
	in.AllowIncomplete = true
	if rep := e.audit(nil, in); verdicts(rep) != "run-ok=SUCCESS run-open=SUCCESS-INCOMPLETE" {
		t.Fatalf("%s", verdicts(rep))
	}
}

// A run continuing in an epoch that is not final yet is not final: neither
// a pass nor a failure. Bundles of non-final epochs are not exported.
func TestAuditRunNotFinal(t *testing.T) {
	e := newChainEnv(t)
	run := signedRun(t, "run-n", 4, true)
	e.anchor(append(signedRun(t, "run-done", 1, true), run[0], run[1])...)
	final := e.head()
	e.anchor(run[2], run[3])
	times := anchorTimes(t, e)

	rep := e.audit(e.pinned(final), AuditInput{From: times[0], To: times[1].Add(time.Hour)})
	if rep.LatestEpoch != 1 || len(rep.Epochs) != 1 || verdicts(rep) != "run-done=SUCCESS run-n=not-final" ||
		!strings.Contains(rep.Runs[1].Reason, "not anchored yet") || len(rep.Warnings) != 1 ||
		!strings.Contains(rep.Warnings[0], "not exported") {
		t.Fatalf("%+v %s", rep, verdicts(rep))
	}
	// Once final, it verifies.
	if rep := e.audit(e.pinned(e.head()), AuditInput{From: times[0], To: times[1].Add(time.Hour)}); verdicts(rep) != "run-done=SUCCESS run-n=SUCCESS" {
		t.Fatalf("%s", verdicts(rep))
	}
}
