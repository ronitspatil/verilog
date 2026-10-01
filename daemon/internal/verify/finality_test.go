package verify

import (
	"context"
	"crypto/ed25519"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/ronitspatil/verilog/daemon/internal/canonical"
)

// head returns the current block number.
func (e *chainEnv) head() *big.Int {
	e.t.Helper()
	h, err := e.client.HeaderByNumber(context.Background(), nil)
	if err != nil {
		e.t.Fatal(err)
	}
	return h.Number
}

func (e *chainEnv) pinned(at *big.Int) *Verifier {
	e.t.Helper()
	v, err := NewAt(context.Background(), e.client, e.contract, true, at)
	if err != nil {
		e.t.Fatal(err)
	}
	return v
}

func isOperational(err error, contains string) bool {
	var oe *OperationalError
	return errors.As(err, &oe) && strings.Contains(err.Error(), contains)
}

// An epoch anchored after the pinned (final) block is "not anchored yet":
// no verdict. An epoch anchored nowhere stays a FAILURE.
func TestVerifyPinnedEpochNotFinalIsNoVerdict(t *testing.T) {
	e := newChainEnv(t)
	run := signedRun(t, "run-pin", 4, true)
	first := e.anchor(run[0], run[1])
	final := e.head()
	second := e.anchor(run[2], run[3])

	v := e.pinned(final)
	if rep, err := v.Event(context.Background(), first[0].EventJSON, first[0].Proof, first[0].EpochID, agentID); err != nil || !rep.Verified {
		t.Fatalf("final epoch: %+v %v", rep, err)
	}
	_, err := v.Event(context.Background(), second[0].EventJSON, second[0].Proof, second[0].EpochID, agentID)
	if !isOperational(err, "not anchored yet") {
		t.Fatalf("non-final epoch: %v, want a 'not anchored yet' operational error", err)
	}
	rep, err := v.Event(context.Background(), first[0].EventJSON, first[0].Proof, 9, agentID)
	if err != nil || rep.Verified || !strings.Contains(rep.Reason, "epoch 9 is not anchored") {
		t.Fatalf("unanchored epoch: %+v %v, want FAILURE", rep, err)
	}
	// Pinned at the head, the second epoch verifies.
	if rep, err := e.pinned(e.head()).Event(context.Background(), second[0].EventJSON, second[0].Proof, second[0].EpochID, agentID); err != nil || !rep.Verified {
		t.Fatalf("pinned at head: %+v %v", rep, err)
	}
}

// Keys are read at the pinned block: a key registered after it is not
// registered as far as the verdict is concerned.
func TestVerifyPinnedKeysAreReadAtTheFinalBlock(t *testing.T) {
	e := newChainEnv(t)
	before := new(big.Int).Sub(e.head(), big.NewInt(1)) // before the agent key was registered
	evs := e.anchor(signedRun(t, "run-k", 1, true)...)
	v := e.pinned(before)
	// The epoch is not anchored at that block either: not anchored yet.
	if _, err := v.Event(context.Background(), evs[0].EventJSON, evs[0].Proof, evs[0].EpochID, agentID); !isOperational(err, "not anchored yet") {
		t.Fatalf("%v", err)
	}
	key, err := v.agentKey(context.Background(), canonical.AgentKey(agentID), canonical.KeyID(agentPriv.Public().(ed25519.PublicKey)))
	if err != nil || key.Registered() {
		t.Fatalf("key read at block %s: %+v %v, want not registered", before, key, err)
	}
}

// Run mode decides on the final epochs; a non-final epoch holding events of
// the run makes the run not anchored yet, others are set aside.
func TestRunPinnedToFinalBlock(t *testing.T) {
	e := newChainEnv(t)
	run := signedRun(t, "run-f", 4, true)
	other := signedRun(t, "run-o", 1, true)
	e.anchor(run...)
	final := e.head()

	// A later, non-final epoch with another run only: set aside, SUCCESS.
	e.anchor(other...)
	rep, err := e.pinned(final).Run(context.Background(), RunInput{AgentID: agentID, RunID: "run-f", Epochs: e.all()})
	if err != nil || !rep.Verified || rep.AgentEpochs != 1 || len(rep.Warnings) != 1 || !strings.Contains(rep.Warnings[0], "not final") {
		t.Fatalf("%+v %v", rep, err)
	}
	// The other run lives only in the non-final epoch: not anchored yet.
	if _, err := e.pinned(final).Run(context.Background(), RunInput{AgentID: agentID, RunID: "run-o", Epochs: e.all()}); !isOperational(err, "not anchored yet") {
		t.Fatalf("%v", err)
	}
	// A replayed copy of the run in a non-final epoch: not anchored yet.
	e.anchor(run[1])
	if _, err := e.pinned(final).Run(context.Background(), RunInput{AgentID: agentID, RunID: "run-f", Epochs: e.all()}); !isOperational(err, "not anchored yet") {
		t.Fatalf("%v", err)
	}
	// Once final, the verdict covers every epoch.
	if rep, err := e.pinned(e.head()).Run(context.Background(), RunInput{AgentID: agentID, RunID: "run-f", Epochs: e.all()}); err != nil || !rep.Verified || rep.AgentEpochs != 3 {
		t.Fatalf("%+v %v", rep, err)
	}
	// Nothing final at all, and the run is not in any final epoch: still
	// "not anchored yet", not a FAILURE.
	if _, err := e.pinned(new(big.Int).Sub(final, big.NewInt(1))).Run(context.Background(), RunInput{AgentID: agentID, RunID: "run-f", Epochs: e.all()}); !isOperational(err, "not anchored yet") {
		t.Fatalf("%v", err)
	}
}
