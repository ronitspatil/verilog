package verify

// Regression tests for the proofs of concept of the 2026-09-30 security
// review (PoCs 1-7). Each encodes the attack and asserts the fixed outcome.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/ronitspatil/verilog/daemon/internal/canonical"
	"github.com/ronitspatil/verilog/daemon/internal/keys"
)

// PoC 1 (M1): an event file whose visible content differs from the signed
// bytes (9007199254740993.0 shown where 9007199254740992 was signed) must not
// verify.
func TestPoC1_NonCanonicalEventFileIsFailure(t *testing.T) {
	e := newChainEnv(t)
	ev := canonical.Event{AgentID: agentID, RunID: "run-poc", StepNumber: 1, EventType: "tool_end",
		PayloadJSON: []byte(`{"amount":9007199254740992,"to":"acct-1"}`), TimestampUTC: time.Unix(1_800_000_000, 0).UTC()}
	canon := sign(t, &ev, agentPriv)
	evs := e.anchor(canon)
	forged := bytes.Replace(canon, []byte(`9007199254740992`), []byte(`9007199254740993.0`), 1)
	rep, err := e.verify(Evidence{EpochID: evs[0].EpochID, EventJSON: forged, Proof: evs[0].Proof})
	if err != nil || rep.Verified || !strings.Contains(rep.Reason, "not in canonical form") || !bytes.Equal(rep.Canonical, canon) {
		t.Fatalf("altered file: %+v %v", rep, err)
	}
}

// PoC 2 (M2): a decoy evidence entry naming an unanchored epoch must not turn
// a FAILURE into "no verdict".
func TestPoC2_DecoyEvidenceKeepsFailure(t *testing.T) {
	e := newChainEnv(t)
	run := signedRun(t, "run-d", 4, true)
	e.anchor(without(run, 1)...) // step 2 never anchored
	decoy := EpochEvidence{Source: "decoy", EpochID: 999, Events: [][]byte{run[1]}}
	rep, err := e.run(RunInput{RunID: "run-d", Epochs: append(e.all(), decoy)})
	if err != nil {
		t.Fatalf("decoy produced an operational error: %v", err)
	}
	expectFailure(t, "decoy", rep, "events missing")
	if len(rep.Warnings) != 1 || !strings.Contains(rep.Warnings[0], "epoch 999 is not anchored") {
		t.Fatalf("warnings: %q", rep.Warnings)
	}
	// Same for an unparseable bundle-like entry in the agent's epoch.
	junk := EpochEvidence{Source: "junk", EpochID: 1, Events: [][]byte{[]byte("not json")}}
	if rep, err = e.run(RunInput{RunID: "run-d", Epochs: append(e.all(), junk)}); err != nil || rep.Verified {
		t.Fatalf("junk: %+v %v", rep, err)
	}
}

// PoC 3 (L7): another agent's event with the same run_id must not poison an
// intact run.
func TestPoC3_ForeignAgentEventIsSkipped(t *testing.T) {
	e := newChainEnv(t)
	run := signedRun(t, "run-x", 3, true)
	other := canonical.Event{AgentID: "agent-other", RunID: "run-x", StepNumber: 1, EventType: "x",
		PayloadJSON: []byte(`{}`), TimestampUTC: time.Unix(1_800_000_000, 0).UTC()}
	// Even anchored inside this agent's own epoch.
	e.anchor(append(append([][]byte(nil), run...), sign(t, &other, attackerPriv))...)
	if rep := e.runAll("run-x"); !rep.Verified {
		t.Fatalf("intact run failed: %+v", rep)
	}
	// And in a bundle of the other agent.
	ok := canonical.AgentKey("agent-other")
	foreign := EpochEvidence{Source: "other", AgentKey: &ok, EpochID: 1, Events: [][]byte{sign(t, &other, attackerPriv)}}
	if rep, err := e.run(RunInput{RunID: "run-x", Epochs: append(e.all(), foreign)}); err != nil || !rep.Verified {
		t.Fatalf("foreign bundle: %+v %v", rep, err)
	}
}

// PoC 4 (H1): a small-order public key cannot be registered, and one that is
// registered anyway (an older registry) verifies nothing.
func TestPoC4_SmallOrderKeyCannotForge(t *testing.T) {
	e := newChainEnv(t)
	var weak [32]byte
	weak[0] = 0x01 // the identity point
	if _, err := e.reg.RegisterAgentKey(e.admin, canonical.AgentKey(agentID), weak); err == nil {
		t.Fatal("registry accepted the identity point as an agent key")
	}

	sig := make([]byte, 64)
	sig[0] = 0x01 // R = identity, S = 0: valid for every message under a small-order key
	pub := ed25519.PublicKey(weak[:])
	forged := canonical.Event{AgentID: agentID, RunID: "run-forged", StepNumber: 1, EventType: "tool_end",
		PayloadJSON: []byte(`{"action":"wire $1M","approved_by":"agent"}`), TimestampUTC: time.Unix(1_800_000_000, 0).UTC(),
		KeyID: canonical.KeyID(pub), Sig: sig}
	canon, err := forged.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	evs := e.anchor(canon)
	v, err := New(context.Background(), e.client, e.contract, true)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a registry that accepted the weak key before the fix.
	v.keys = staticKeys{canonical.KeyID(pub): {Pubkey: pub, ValidFrom: 1}}
	rep, err := v.Event(context.Background(), evs[0].EventJSON, evs[0].Proof, evs[0].EpochID, agentID)
	if err != nil || rep.Verified || !strings.Contains(rep.Reason, "unsafe") {
		t.Fatalf("forged event: %+v %v", rep, err)
	}
}

type staticKeys map[canonical.Digest]keys.Key

func (s staticKeys) AgentKey(_ context.Context, _, keyID canonical.Digest) (keys.Key, error) {
	return s[keyID], nil
}

// PoC 5 (M4): re-anchoring a byte-identical copy of an event after its key
// was revoked must not fail the honest run: the earliest valid copy decides.
func TestPoC5_ReplayAfterRevocationKeepsHonestRun(t *testing.T) {
	e := newChainEnv(t)
	run := signedRun(t, "run-r", 3, true)
	e.anchor(run...)
	if rep := e.runAll("run-r"); !rep.Verified {
		t.Fatalf("baseline: %+v", rep)
	}
	e.revoke(agentPriv) // routine rotation
	e.anchor(run[1])    // replay
	rep := e.runAll("run-r")
	if !rep.Verified || len(rep.Warnings) != 1 || !strings.Contains(rep.Warnings[0], "step 2: a copy anchored in epoch 2") {
		t.Fatalf("replay after revocation: %+v", rep)
	}
	if len(rep.Epochs) != 1 || rep.Epochs[0] != 1 {
		t.Fatalf("epochs %v", rep.Epochs)
	}

	// An event first anchored after the revocation took effect still fails.
	late := canonical.Event{AgentID: agentID, RunID: "run-late", StepNumber: 1, EventType: canonical.EventRunEnd,
		PayloadJSON: []byte(`{"status":"ok","steps":0}`), TimestampUTC: time.Unix(1_800_000_000, 0).UTC()}
	e.anchor(sign(t, &late, agentPriv))
	expectFailure(t, "first anchored after revocation", e.runAll("run-late"), "was not valid when epoch 3 was anchored")
}

// A scheduled revocation (drain before revoke) leaves events anchored before
// it takes effect valid.
func TestScheduledRevocationLeavesDrainWindow(t *testing.T) {
	e := newChainEnv(t)
	run := signedRun(t, "run-s", 2, true)
	e.anchor(run[0])
	e.revokeAfter(agentPriv, 3600) // recorded now, effective in an hour
	e.anchor(run[1])               // drained before it takes effect
	if rep := e.runAll("run-s"); !rep.Verified {
		t.Fatalf("drained run: %+v", rep)
	}
}

// PoC 7 (M3): re-anchoring the successors of a withheld event and presenting
// only the later copies must not hide the reorder.
func TestPoC7_CuratedReanchorIsFailure(t *testing.T) {
	e := newChainEnv(t)
	run := signedRun(t, "run-w", 4, true)
	e.anchor(run[0], run[2], run[3]) // epoch 1: step 2 withheld
	e.anchor(run[1])                 // epoch 2: step 2 late
	e.anchor(run[1], run[2], run[3]) // epoch 3: re-anchored successors
	all := e.all()

	expectFailure(t, "complete evidence", e.runAll("run-w"), "step 2 was anchored in epoch 2, after its successor step 3 in epoch 1")

	// The curated presentation (epoch 1 reduced to step 1, plus epoch 3).
	curated := all[0]
	curated.Events = curated.Events[:1]
	rep, err := e.run(RunInput{RunID: "run-w", Epochs: []EpochEvidence{curated, all[2]}})
	if err != nil {
		t.Fatal(err)
	}
	expectFailure(t, "curated", rep, "evidence is incomplete")
	rep, _ = e.run(RunInput{RunID: "run-w", Epochs: []EpochEvidence{curated, all[1], all[2]}})
	expectFailure(t, "curated with every epoch", rep, "epoch 1: it holds 1 events, the on-chain anchor counts 3")
}
