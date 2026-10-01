package verify

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ronitspatil/verilog/daemon/internal/canonical"
)

func (e *chainEnv) run(in RunInput) (*RunReport, error) {
	v, err := New(context.Background(), e.client, e.contract, true)
	if err != nil {
		return nil, err
	}
	if in.AgentID == "" {
		in.AgentID = agentID
	}
	return v.Run(context.Background(), in)
}

// runAll verifies a run against the complete evidence.
func (e *chainEnv) runAll(runID string) *RunReport {
	e.t.Helper()
	rep, err := e.run(RunInput{RunID: runID, Epochs: e.all()})
	if err != nil {
		e.t.Fatal(err)
	}
	return rep
}

func without(evs [][]byte, i int) [][]byte {
	out := append([][]byte(nil), evs[:i]...)
	return append(out, evs[i+1:]...)
}

func expectFailure(t *testing.T, name string, rep *RunReport, reason string) {
	t.Helper()
	if rep.Verified || !strings.Contains(rep.Reason, reason) {
		t.Errorf("%s: verified=%v reason=%q, want a FAILURE containing %q", name, rep.Verified, rep.Reason, reason)
	}
}

func TestRunSuccessAcrossEpochs(t *testing.T) {
	e := newChainEnv(t)
	run := signedRun(t, "run-ok", 6, true)
	other := signedRun(t, "run-other", 2, false) // another run's events are ignored
	e.anchor(run[0], run[1], other[0])
	e.anchor(run[2], run[3], run[4], run[5], other[1])
	// A retransmission anchored again in a later epoch is the same event.
	e.anchor(run[3])
	rep := e.runAll("run-ok")
	if !rep.Verified || rep.Incomplete || rep.Events != 6 || rep.LastStep != 6 || rep.EndStatus != "ok" || len(rep.Epochs) != 2 ||
		rep.AgentEpochs != 3 || len(rep.Warnings) != 0 {
		t.Fatalf("%+v", rep)
	}
}

// Each case is what a compromised daemon (holding the anchorer key) can
// anchor; the complete evidence then shows it.
func TestRunDetectsChainAttacks(t *testing.T) {
	run := signedRun(t, "run-x", 5, true)

	forkEv, _ := canonical.ParseEvent(run[1])
	forkEv.PayloadJSON = []byte(`{"text":"other branch"}`)

	replayEv, _ := canonical.ParseEvent(run[1])
	replayEv.RunID = "run-y"

	lateEv := canonical.Event{AgentID: agentID, RunID: "run-x", StepNumber: 6, PrevHash: canonical.ContentDigest(run[4]),
		EventType: "llm_end", PayloadJSON: []byte(`{}`), TimestampUTC: time.Unix(1_800_000_100, 0).UTC()}

	cases := map[string]struct {
		anchor func(e *chainEnv)
		reason string
	}{
		"dropped middle event": {func(e *chainEnv) { e.anchor(without(run, 2)...) }, "events missing from the run: step 2 is followed by step 4"},
		"dropped genesis":      {func(e *chainEnv) { e.anchor(without(run, 0)...) }, "does not start at step 1"},
		"withheld, reordered": {func(e *chainEnv) {
			e.anchor(run[0], run[1], run[3], run[4])
			e.anchor(run[2])
		}, "step 3 was anchored in epoch 2, after its successor step 4 in epoch 1"},
		"fork": {func(e *chainEnv) {
			e.anchor(run...)
			e.anchor(sign(t, &forkEv, agentPriv))
		}, "fork"},
		"replayed into another run": {func(e *chainEnv) {
			e.anchor(without(run, 1)...)
			e.anchor(sign(t, &replayEv, agentPriv))
		}, "events missing"},
		"missing run_end": {func(e *chainEnv) { e.anchor(without(run, 4)...) }, "run ended without terminal event after step 4"},
		"events after run_end": {func(e *chainEnv) {
			e.anchor(run...)
			e.anchor(sign(t, &lateEv, agentPriv))
		}, "events after run_end"},
	}
	for name, c := range cases {
		e := newChainEnv(t)
		c.anchor(e)
		expectFailure(t, name, e.runAll("run-x"), c.reason)
	}
}

// The evidence must hold every epoch of the agent, each exactly as anchored.
func TestRunRequiresCompleteEvidence(t *testing.T) {
	e := newChainEnv(t)
	run := signedRun(t, "run-c", 4, true)
	e.anchor(run[0], run[1])
	e.anchor(signedRun(t, "run-other", 1, false)...)
	e.anchor(run[2], run[3])
	all := e.all()
	if rep := e.runAll("run-c"); !rep.Verified {
		t.Fatalf("baseline: %+v", rep)
	}

	// An epoch that holds none of the run's events is still required.
	rep, _ := e.run(RunInput{RunID: "run-c", Epochs: []EpochEvidence{all[0], all[2]}})
	expectFailure(t, "missing epoch", rep, "no evidence bundle for epoch(s) 2 of the 3 epochs")

	// A bundle with one event withheld no longer matches its anchor.
	short := all[0]
	short.Events = short.Events[:1]
	rep, _ = e.run(RunInput{RunID: "run-c", Epochs: []EpochEvidence{short, all[1], all[2]}})
	expectFailure(t, "withheld from bundle", rep, "epoch 1: it holds 1 events, the on-chain anchor counts 2")

	// A tampered event changes the rebuilt root.
	bad := all[2]
	bad.Events = [][]byte{bad.Events[0], []byte(strings.Replace(string(bad.Events[1]), "ok", "ko", 1))}
	rep, _ = e.run(RunInput{RunID: "run-c", Epochs: []EpochEvidence{all[0], all[1], bad}})
	expectFailure(t, "tampered", rep, "epoch 3: its events rebuild root")

	// A wrong copy next to the right one is only a warning.
	rep, _ = e.run(RunInput{RunID: "run-c", Epochs: append(append([]EpochEvidence(nil), all...), bad)})
	if !rep.Verified || len(rep.Warnings) != 1 || !strings.Contains(rep.Warnings[0], "ignored epoch-3 for epoch 3") {
		t.Fatalf("extra bad copy: %+v", rep)
	}

	// Another agent's bundles are skipped.
	other := canonical.AgentKey("agent-other")
	foreign := EpochEvidence{Source: "foreign", AgentKey: &other, EpochID: 2, Events: [][]byte{[]byte("{}")}}
	if rep, _ = e.run(RunInput{RunID: "run-c", Epochs: append(all, foreign)}); !rep.Verified || len(rep.Warnings) != 0 {
		t.Fatalf("foreign bundle: %+v", rep)
	}
}

// L3: --allow-incomplete gives a distinct verdict, never a plain pass.
func TestRunAllowIncomplete(t *testing.T) {
	e := newChainEnv(t)
	run := signedRun(t, "run-crash", 3, false)
	e.anchor(run...)
	rep := e.runAll("run-crash")
	expectFailure(t, "incomplete run by default", rep, "without terminal event after step 3")
	rep, err := e.run(RunInput{RunID: "run-crash", Epochs: e.all(), AllowIncomplete: true})
	if err != nil || !rep.Verified || !rep.Incomplete || len(rep.Warnings) != 1 || !strings.Contains(rep.Warnings[0], "INCOMPLETE") {
		t.Fatalf("--allow-incomplete: %+v %v", rep, err)
	}
	// It never excuses a gap.
	e2 := newChainEnv(t)
	e2.anchor(without(run, 1)...)
	rep, err = e2.run(RunInput{RunID: "run-crash", Epochs: e2.all(), AllowIncomplete: true})
	if err != nil || rep.Verified || rep.Incomplete {
		t.Fatalf("gap accepted with --allow-incomplete: %+v %v", rep, err)
	}
	// A complete run is never reported as incomplete.
	e3 := newChainEnv(t)
	e3.anchor(signedRun(t, "run-full", 2, true)...)
	rep, err = e3.run(RunInput{RunID: "run-full", Epochs: e3.all(), AllowIncomplete: true})
	if err != nil || !rep.Verified || rep.Incomplete {
		t.Fatalf("complete run: %+v %v", rep, err)
	}
}

func TestRunSDKDroppedIsReported(t *testing.T) {
	e := newChainEnv(t)
	var evs [][]byte
	var prev canonical.Digest
	for i, typ := range []string{"chain_start", canonical.EventSDKDropped, "chain_end", canonical.EventRunEnd} {
		payload := `{}`
		if typ == canonical.EventSDKDropped {
			payload = `{"count":7}`
		}
		ev := canonical.Event{AgentID: agentID, RunID: "run-d", StepNumber: uint64(i + 1), PrevHash: prev, EventType: typ,
			PayloadJSON: []byte(payload), TimestampUTC: time.Unix(1_800_000_000, int64(i)).UTC()}
		canon := sign(t, &ev, agentPriv)
		prev = canonical.ContentDigest(canon)
		evs = append(evs, canon)
	}
	e.anchor(evs...)
	if rep := e.runAll("run-d"); !rep.Verified || rep.SDKDropped != 7 {
		t.Fatalf("%+v", rep)
	}
}

// Only failures to reach a verdict are operational errors; a run that is not
// in the evidence, or an agent with nothing anchored, is a FAILURE.
func TestRunVerdictsAndOperationalErrors(t *testing.T) {
	e := newChainEnv(t)
	e.anchor(signedRun(t, "run-o", 2, true)...)
	expectFailure(t, "unknown run", e.runAll("run-missing"), `no events of run "run-missing"`)
	rep, err := e.run(RunInput{AgentID: "agent-none", RunID: "run-o", Epochs: e.all()})
	if err != nil {
		t.Fatal(err)
	}
	expectFailure(t, "agent without epochs", rep, "no epoch is anchored")

	var oe *OperationalError
	if _, err := e.run(RunInput{RunID: "", Epochs: e.all()}); !errors.As(err, &oe) {
		t.Fatalf("empty run id: %v", err)
	}
	v, err := New(context.Background(), e.client, e.contract, true)
	if err != nil {
		t.Fatal(err)
	}
	e.sim.Close() // the RPC goes away
	if _, err := v.Run(context.Background(), RunInput{AgentID: agentID, RunID: "run-o", Epochs: e.all()}); !errors.As(err, &oe) {
		t.Fatalf("RPC failure: %v", err)
	}
}

func TestRanges(t *testing.T) {
	if got := ranges([]uint64{1, 2, 3, 5, 7, 8}); got != "1-3, 5, 7-8" {
		t.Fatal(got)
	}
}
