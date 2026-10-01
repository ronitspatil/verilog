package verify

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient/simulated"

	"github.com/ronitspatil/verilog/daemon/internal/canonical"
	"github.com/ronitspatil/verilog/daemon/internal/merkle"
	"github.com/ronitspatil/verilog/daemon/internal/registry"
)

const agentID = "agent-v"

var (
	agentPriv    = ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	attackerPriv = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xa7}, ed25519.SeedSize))
)

// chainEnv is a simulated chain with a registry whose admin (key admin) and
// anchorer are different accounts, and agentPriv registered for agentID.
type chainEnv struct {
	t        *testing.T
	sim      *simulated.Backend
	client   simulated.Client
	contract common.Address
	reg      *registry.VeriLogRegistry
	admin    *bind.TransactOpts
	anchorer *bind.TransactOpts
}

func newChainEnv(t *testing.T) *chainEnv {
	t.Helper()
	adminKey, _ := crypto.GenerateKey()
	anchorKey, _ := crypto.GenerateKey()
	alloc := types.GenesisAlloc{}
	for _, k := range []*ecdsa.PrivateKey{adminKey, anchorKey} {
		alloc[crypto.PubkeyToAddress(k.PublicKey)] = types.Account{Balance: new(big.Int).Lsh(big.NewInt(1), 100)}
	}
	sim := simulated.NewBackend(alloc)
	t.Cleanup(func() { sim.Close() })
	client := sim.Client()
	chainID, _ := client.ChainID(context.Background())
	admin, _ := bind.NewKeyedTransactorWithChainID(adminKey, chainID)
	anchorer, _ := bind.NewKeyedTransactorWithChainID(anchorKey, chainID)
	addr, _, reg, err := registry.DeployVeriLogRegistry(admin, client, admin.From, anchorer.From)
	if err != nil {
		t.Fatal(err)
	}
	e := &chainEnv{t: t, sim: sim, client: client, contract: addr, reg: reg, admin: admin, anchorer: anchorer}
	e.commit()
	e.register(agentPriv)
	return e
}

// commit mines a block 10s after the previous one.
func (e *chainEnv) commit() {
	e.sim.AdjustTime(10 * time.Second)
	e.sim.Commit()
}

func (e *chainEnv) register(priv ed25519.PrivateKey) {
	var pub [32]byte
	copy(pub[:], priv.Public().(ed25519.PublicKey))
	if _, err := e.reg.RegisterAgentKey(e.admin, canonical.AgentKey(agentID), pub); err != nil {
		e.t.Fatal(err)
	}
	e.commit()
}

func (e *chainEnv) revoke(priv ed25519.PrivateKey) {
	if _, err := e.reg.RevokeAgentKey(e.admin, canonical.AgentKey(agentID), canonical.KeyID(priv.Public().(ed25519.PublicKey))); err != nil {
		e.t.Fatal(err)
	}
	e.commit()
}

// anchor anchors the events as the next epoch (as the daemon would, or as an
// attacker holding the anchorer key would) and returns their evidence.
func (e *chainEnv) anchor(events ...[]byte) []Evidence {
	e.t.Helper()
	var leaves []merkle.Hash
	for _, ev := range events {
		leaves = append(leaves, merkle.LeafFromDigest(canonical.ContentDigest(ev)))
	}
	tree, err := merkle.Build(leaves)
	if err != nil {
		e.t.Fatal(err)
	}
	agent := canonical.AgentKey(agentID)
	if _, err := e.reg.AnchorEpoch(e.anchorer, agent, tree.Root(), uint32(len(leaves))); err != nil {
		e.t.Fatal(err)
	}
	e.commit()
	epoch, _ := e.reg.LatestEpoch(&bind.CallOpts{}, agent)
	out := make([]Evidence, len(events))
	for i, ev := range events {
		p, _ := tree.Proof(i)
		out[i] = Evidence{EpochID: epoch.Uint64(), EventJSON: ev, Proof: p}
	}
	return out
}

// signedRun returns the canonical JSON of a signed run of n events; the last
// one is run_end when withEnd is set.
func signedRun(t *testing.T, runID string, n int, withEnd bool) [][]byte {
	t.Helper()
	var out [][]byte
	var prev canonical.Digest
	for i := 1; i <= n; i++ {
		ev := canonical.Event{
			AgentID: agentID, RunID: runID, StepNumber: uint64(i), PrevHash: prev, EventType: "llm_end",
			PayloadJSON:  []byte(fmt.Sprintf(`{"text":"hello world","i":%d}`, i)),
			TimestampUTC: time.Unix(1_800_000_000, int64(i)).UTC(),
		}
		if withEnd && i == n {
			ev.EventType = canonical.EventRunEnd
			ev.PayloadJSON = []byte(fmt.Sprintf(`{"status":"ok","steps":%d}`, n-1))
		}
		canon := sign(t, &ev, agentPriv)
		prev = canonical.ContentDigest(canon)
		out = append(out, canon)
	}
	return out
}

func sign(t *testing.T, ev *canonical.Event, priv ed25519.PrivateKey) []byte {
	t.Helper()
	if err := ev.Sign(priv); err != nil {
		t.Fatal(err)
	}
	canon, err := ev.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return canon
}

func (e *chainEnv) verify(ev Evidence) (*Report, error) {
	return Verify(context.Background(), e.client, Input{
		EventJSON: ev.EventJSON, Proof: ev.Proof, EpochID: ev.EpochID, AgentID: agentID, Contract: e.contract, OnChainCheck: true,
	})
}

func TestVerifySuccess(t *testing.T) {
	e := newChainEnv(t)
	evs := e.anchor(signedRun(t, "run-v", 3, true)...)
	for i, ev := range evs {
		rep, err := e.verify(ev)
		if err != nil {
			t.Fatal(err)
		}
		if !rep.Verified || rep.OnChainCheck != "agrees" || rep.RunID != "run-v" || rep.StepNumber != uint64(i+1) {
			t.Fatalf("event %d: %+v", i, rep)
		}
	}
	// Raw bytes32 agent key and a reformatted (non-canonical) event file also verify.
	in := Input{EventJSON: []byte(strings.Replace(string(evs[1].EventJSON), ",", ",\n  ", -1)), Proof: evs[1].Proof,
		EpochID: evs[1].EpochID, AgentID: canonical.AgentKey(agentID).Hex(), Contract: e.contract}
	if rep, err := Verify(context.Background(), e.client, in); err != nil || !rep.Verified {
		t.Fatalf("raw key / reformatted: %+v %v", rep, err)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	e := newChainEnv(t)
	evs := e.anchor(signedRun(t, "run-v", 3, true)...)
	base := evs[0]
	cases := map[string]func(*Evidence){
		"payload byte flipped": func(in *Evidence) { in.EventJSON = []byte(strings.Replace(string(in.EventJSON), "hello", "hellp", 1)) },
		"step number changed": func(in *Evidence) {
			in.EventJSON = []byte(strings.Replace(string(in.EventJSON), `"step_number":1`, `"step_number":2`, 1))
		},
		"timestamp changed": func(in *Evidence) {
			in.EventJSON = []byte(strings.Replace(string(in.EventJSON), "00.000000001Z", "00.000000009Z", 1))
		},
		"signature byte flipped": func(in *Evidence) {
			s := string(in.EventJSON)
			i := strings.Index(s, `"sig":"0x`) + 9
			in.EventJSON = []byte(s[:i] + string("0123456789abcdef"[(strings.IndexByte("0123456789abcdef", s[i])+1)%16]) + s[i+1:])
		},
		"not JSON anymore": func(in *Evidence) { in.EventJSON = in.EventJSON[:len(in.EventJSON)-1] },
		"proof element flipped": func(in *Evidence) {
			in.Proof = append([]merkle.Hash(nil), in.Proof...)
			in.Proof[0][5] ^= 0x80
		},
		"proof truncated": func(in *Evidence) { in.Proof = in.Proof[:len(in.Proof)-1] },
		"other agent's event": func(in *Evidence) {
			in.EventJSON = []byte(strings.Replace(string(in.EventJSON), agentID, "agent-w", 1))
		},
		"valid event, other leaf's proof": func(in *Evidence) { in.Proof = evs[2].Proof },
	}
	for name, mutate := range cases {
		in := base
		in.EventJSON = append([]byte(nil), base.EventJSON...)
		mutate(&in)
		rep, err := e.verify(in)
		if err != nil {
			t.Fatalf("%s: unexpected operational error %v", name, err)
		}
		if rep.Verified || rep.Reason == "" {
			t.Fatalf("%s: tampering not detected: %+v", name, rep)
		}
	}
}

// The attacker holds the daemon host and the anchorer key: it can anchor
// whatever it likes, but it cannot sign as the agent.
func TestVerifyRejectsForgedButAnchoredEvents(t *testing.T) {
	e := newChainEnv(t)
	genuine := signedRun(t, "run-v", 1, false)[0]
	forge := func(priv ed25519.PrivateKey, keepKeyID bool) []byte {
		ev, err := canonical.ParseEvent(genuine)
		if err != nil {
			t.Fatal(err)
		}
		ev.PayloadJSON = []byte(`{"text":"transfer all funds"}`)
		keyID := ev.KeyID
		if err := ev.Sign(priv); err != nil {
			t.Fatal(err)
		}
		if keepKeyID {
			ev.KeyID = keyID // claim the agent's registered key
		}
		canon, err := ev.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		return canon
	}

	cases := map[string]struct {
		event  []byte
		reason string
	}{
		"re-signed with an unregistered key":    {forge(attackerPriv, false), "not registered"},
		"altered, signature under agent key_id": {forge(attackerPriv, true), "signature does not verify"},
	}
	for name, c := range cases {
		ev := e.anchor(c.event)[0] // anchoring succeeds: the attacker is the anchorer
		rep, err := e.verify(ev)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if rep.Verified || !strings.Contains(rep.Reason, c.reason) {
			t.Fatalf("%s: %+v", name, rep)
		}
	}
	// The anchorer cannot register its own key.
	var pub [32]byte
	copy(pub[:], attackerPriv.Public().(ed25519.PublicKey))
	if _, err := e.reg.RegisterAgentKey(e.anchorer, canonical.AgentKey(agentID), pub); err == nil {
		t.Fatal("anchorer registered a key")
	}
}

func TestVerifyKeyValidityUsesAnchorTime(t *testing.T) {
	e := newChainEnv(t)
	rotated := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, ed25519.SeedSize))
	signWith := func(priv ed25519.PrivateKey, step uint64) []byte {
		ev := canonical.Event{AgentID: agentID, RunID: "run-r", StepNumber: step, EventType: "tool_end",
			PayloadJSON: []byte(`{}`), TimestampUTC: time.Unix(1_800_000_000, 0).UTC()}
		return sign(t, &ev, priv)
	}
	// Signed before registration and anchored before it: not valid yet.
	early := e.anchor(signWith(rotated, 1))[0]
	e.register(rotated)
	before := e.anchor(signWith(rotated, 2))[0]
	e.revoke(rotated)
	after := e.anchor(signWith(rotated, 3))[0]

	for name, c := range map[string]struct {
		ev Evidence
		ok bool
	}{"anchored before registration": {early, false}, "anchored before revocation": {before, true}, "anchored after revocation": {after, false}} {
		rep, err := e.verify(c.ev)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if rep.Verified != c.ok {
			t.Fatalf("%s: verified=%v, want %v (%s)", name, rep.Verified, c.ok, rep.Reason)
		}
		if !c.ok && !strings.Contains(rep.Reason, "not valid when epoch") {
			t.Fatalf("%s: reason %q", name, rep.Reason)
		}
	}
}

func TestVerifyOperationalErrors(t *testing.T) {
	e := newChainEnv(t)
	ev := e.anchor(signedRun(t, "run-v", 1, false)...)[0]
	var oe *OperationalError
	in := Input{EventJSON: ev.EventJSON, Proof: ev.Proof, EpochID: 2, AgentID: agentID, Contract: e.contract}
	if _, err := Verify(context.Background(), e.client, in); !errors.As(err, &oe) || !strings.Contains(err.Error(), "not anchored") {
		t.Fatalf("unanchored epoch: %v", err)
	}
	in.EpochID, in.AgentID = 1, "agent-unknown"
	if _, err := Verify(context.Background(), e.client, in); !errors.As(err, &oe) {
		t.Fatalf("unknown agent: %v", err)
	}
	in.AgentID, in.Contract = agentID, common.HexToAddress("0x1234")
	if _, err := Verify(context.Background(), e.client, in); !errors.As(err, &oe) {
		t.Fatalf("no contract: %v", err)
	}
	in.Contract, in.EpochID = e.contract, 0
	if _, err := Verify(context.Background(), e.client, in); !errors.As(err, &oe) {
		t.Fatalf("epoch 0: %v", err)
	}
}

func TestParseProof(t *testing.T) {
	p, err := ParseProof([]byte(`["0x` + strings.Repeat("ab", 32) + `"]`))
	if err != nil || len(p) != 1 || p[0][0] != 0xab {
		t.Fatalf("%v %v", p, err)
	}
	if p, err := ParseProof([]byte(`[]`)); err != nil || len(p) != 0 {
		t.Fatalf("empty proof: %v", err)
	}
	for _, bad := range []string{`{}`, `["0x12"]`, `[1]`, `nope`} {
		if _, err := ParseProof([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}
