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

func without(evs []Evidence, i int) []Evidence {
	out := append([]Evidence(nil), evs[:i]...)
	return append(out, evs[i+1:]...)
}

func TestRunSuccessAcrossEpochs(t *testing.T) {
	e := newChainEnv(t)
	run := signedRun(t, "run-ok", 6, true)
	other := signedRun(t, "run-other", 2, false) // another run's events are ignored
	evs := append(e.anchor(run[0], run[1], other[0]), e.anchor(run[2], run[3], run[4], run[5], other[1])...)
	// A retransmission anchored again in a later epoch is the same event.
	evs = append(evs, e.anchor(run[3])...)
	rep, err := e.run(RunInput{RunID: "run-ok", Evidence: evs})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Verified || rep.Events != 6 || rep.LastStep != 6 || rep.EndStatus != "ok" || len(rep.Epochs) != 2 || rep.Warning != "" {
		t.Fatalf("%+v", rep)
	}
}

func TestRunDetectsChainAttacks(t *testing.T) {
	e := newChainEnv(t)
	run := signedRun(t, "run-x", 5, true)
	all := e.anchor(run...)

	// Withheld step 3, anchored later than step 4: the reorder is visible
	// even though every event is genuine and included.
	reordered := append(e.anchor(run[0], run[1], run[3], run[4]), e.anchor(run[2])...)

	// A second, validly signed event at step 2 (key misuse).
	forkEv, _ := canonical.ParseEvent(run[1])
	forkEv.PayloadJSON = []byte(`{"text":"other branch"}`)
	fork := append(append([]Evidence(nil), all...), e.anchor(sign(t, &forkEv, agentPriv))...)

	// Event 2 replaced by an event signed for another run at the same position.
	replayEv, _ := canonical.ParseEvent(run[1])
	replayEv.RunID = "run-y"
	replay := append(without(all, 1), e.anchor(sign(t, &replayEv, agentPriv))...)

	// Events after run_end.
	lateEv := canonical.Event{AgentID: agentID, RunID: "run-x", StepNumber: 6, PrevHash: canonical.ContentDigest(run[4]),
		EventType: "llm_end", PayloadJSON: []byte(`{}`), TimestampUTC: time.Unix(1_800_000_100, 0).UTC()}
	late := append(append([]Evidence(nil), all...), e.anchor(sign(t, &lateEv, agentPriv))...)

	cases := map[string]struct {
		evidence []Evidence
		reason   string
	}{
		"dropped middle event":      {without(all, 2), "events missing from the run: step 2 is followed by step 4"},
		"dropped genesis":           {without(all, 0), "does not start at step 1"},
		"withheld, reordered":       {reordered, "anchored in epoch"},
		"fork":                      {fork, "fork"},
		"replayed into another run": {replay, "events missing"},
		"missing run_end":           {without(all, 4), "run ended without terminal event after step 4"},
		"events after run_end":      {late, "events after run_end"},
	}
	for name, c := range cases {
		rep, err := e.run(RunInput{RunID: "run-x", Evidence: c.evidence})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if rep.Verified || !strings.Contains(rep.Reason, c.reason) {
			t.Errorf("%s: verified=%v reason=%q, want %q", name, rep.Verified, rep.Reason, c.reason)
		}
	}

	// A tampered event inside the run fails the whole run.
	bad := append([]Evidence(nil), all...)
	bad[1].EventJSON = []byte(strings.Replace(string(bad[1].EventJSON), "hello", "hellp", 1))
	if rep, err := e.run(RunInput{RunID: "run-x", Evidence: bad}); err != nil || rep.Verified || !strings.Contains(rep.Reason, "step 2") {
		t.Fatalf("tampered event: %+v %v", rep, err)
	}
}

func TestRunAllowIncomplete(t *testing.T) {
	e := newChainEnv(t)
	evs := e.anchor(signedRun(t, "run-crash", 3, false)...)
	rep, err := e.run(RunInput{RunID: "run-crash", Evidence: evs})
	if err != nil || rep.Verified {
		t.Fatalf("incomplete run accepted by default: %+v %v", rep, err)
	}
	rep, err = e.run(RunInput{RunID: "run-crash", Evidence: evs, AllowIncomplete: true})
	if err != nil || !rep.Verified || !strings.Contains(rep.Warning, "without terminal event after step 3") {
		t.Fatalf("--allow-incomplete: %+v %v", rep, err)
	}
	// It never excuses a gap.
	rep, err = e.run(RunInput{RunID: "run-crash", Evidence: without(evs, 1), AllowIncomplete: true})
	if err != nil || rep.Verified {
		t.Fatalf("gap accepted with --allow-incomplete: %+v %v", rep, err)
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
	rep, err := e.run(RunInput{RunID: "run-d", Evidence: e.anchor(evs...)})
	if err != nil || !rep.Verified || rep.SDKDropped != 7 {
		t.Fatalf("%+v %v", rep, err)
	}
}

func TestRunOperationalErrors(t *testing.T) {
	e := newChainEnv(t)
	evs := e.anchor(signedRun(t, "run-o", 2, true)...)
	var oe *OperationalError
	if _, err := e.run(RunInput{RunID: "run-missing", Evidence: evs}); !errors.As(err, &oe) {
		t.Fatalf("no events: %v", err)
	}
	evs[0].EpochID = 99
	if _, err := e.run(RunInput{RunID: "run-o", Evidence: evs}); !errors.As(err, &oe) || !strings.Contains(err.Error(), "not anchored") {
		t.Fatalf("unanchored epoch: %v", err)
	}
}
