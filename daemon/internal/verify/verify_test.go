package verify

import (
	"context"
	"errors"
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

type fixture struct {
	client   simulated.Client
	contract common.Address
	events   [][]byte
	tree     *merkle.Sealed
}

func setup(t *testing.T) *fixture {
	t.Helper()
	key, _ := crypto.GenerateKey()
	from := crypto.PubkeyToAddress(key.PublicKey)
	sim := simulated.NewBackend(types.GenesisAlloc{from: {Balance: new(big.Int).Lsh(big.NewInt(1), 100)}})
	t.Cleanup(func() { sim.Close() })
	client := sim.Client()
	chainID, _ := client.ChainID(context.Background())
	opts, _ := bind.NewKeyedTransactorWithChainID(key, chainID)
	addr, _, reg, err := registry.DeployVeriLogRegistry(opts, client, from, from)
	if err != nil {
		t.Fatal(err)
	}
	sim.Commit()

	f := &fixture{client: client, contract: addr}
	var leaves []merkle.Hash
	for i := uint64(1); i <= 3; i++ {
		canon, err := canonical.Event{
			AgentID: "agent-v", StepNumber: i, EventType: "llm_end",
			PayloadJSON:  []byte(`{"text":"hello world"}`),
			TimestampUTC: time.Unix(1_800_000_000, int64(i)).UTC(),
		}.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		f.events = append(f.events, canon)
		leaves = append(leaves, merkle.LeafFromDigest(canonical.ContentDigest(canon)))
	}
	f.tree, _ = merkle.Build(leaves)
	if _, err := reg.AnchorEpoch(opts, canonical.AgentKey("agent-v"), f.tree.Root(), 3); err != nil {
		t.Fatal(err)
	}
	sim.Commit()
	return f
}

func (f *fixture) input(i int) Input {
	p, _ := f.tree.Proof(i)
	return Input{EventJSON: f.events[i], Proof: p, EpochID: 1, AgentID: "agent-v", Contract: f.contract, OnChainCheck: true}
}

func TestVerifySuccess(t *testing.T) {
	f := setup(t)
	for i := range f.events {
		rep, err := Verify(context.Background(), f.client, f.input(i))
		if err != nil {
			t.Fatal(err)
		}
		if !rep.Verified || rep.OnChainCheck != "agrees" {
			t.Fatalf("event %d: %+v", i, rep)
		}
	}
	// Raw bytes32 agent key and a reformatted (non-canonical) event file also verify.
	in := f.input(1)
	in.AgentID = canonical.AgentKey("agent-v").Hex()
	in.EventJSON = []byte(strings.Replace(string(in.EventJSON), ",", ",\n  ", -1))
	if rep, err := Verify(context.Background(), f.client, in); err != nil || !rep.Verified {
		t.Fatalf("raw key / reformatted: %+v %v", rep, err)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	f := setup(t)
	cases := map[string]func(*Input){
		"payload byte flipped": func(in *Input) { in.EventJSON = []byte(strings.Replace(string(in.EventJSON), "hello", "hellp", 1)) },
		"step number changed": func(in *Input) {
			in.EventJSON = []byte(strings.Replace(string(in.EventJSON), `"step_number":1`, `"step_number":2`, 1))
		},
		"timestamp changed": func(in *Input) {
			in.EventJSON = []byte(strings.Replace(string(in.EventJSON), "00.000000001Z", "00.000000009Z", 1))
		},
		"event type changed": func(in *Input) {
			in.EventJSON = []byte(strings.Replace(string(in.EventJSON), "llm_end", "llm_start", 1))
		},
		"not JSON anymore": func(in *Input) { in.EventJSON = in.EventJSON[:len(in.EventJSON)-1] },
		"proof element flipped": func(in *Input) {
			in.Proof = append([]merkle.Hash(nil), in.Proof...)
			in.Proof[0][5] ^= 0x80
		},
		"proof truncated":     func(in *Input) { in.Proof = in.Proof[:len(in.Proof)-1] },
		"other agent's event": func(in *Input) { in.EventJSON = []byte(strings.Replace(string(in.EventJSON), "agent-v", "agent-w", 1)) },
		"valid event, other leaf's proof": func(in *Input) {
			p, _ := f.tree.Proof(2)
			in.Proof = p
		},
	}
	for name, mutate := range cases {
		in := f.input(0)
		in.EventJSON = append([]byte(nil), in.EventJSON...)
		mutate(&in)
		rep, err := Verify(context.Background(), f.client, in)
		if err != nil {
			t.Fatalf("%s: unexpected operational error %v", name, err)
		}
		if rep.Verified || rep.Reason == "" {
			t.Fatalf("%s: tampering not detected: %+v", name, rep)
		}
	}
}

func TestVerifyOperationalErrors(t *testing.T) {
	f := setup(t)
	var oe *OperationalError

	in := f.input(0)
	in.EpochID = 2 // not anchored
	if _, err := Verify(context.Background(), f.client, in); !errors.As(err, &oe) || !strings.Contains(err.Error(), "not anchored") {
		t.Fatalf("unanchored epoch: %v", err)
	}
	in = f.input(0)
	in.AgentID = "agent-unknown"
	if _, err := Verify(context.Background(), f.client, in); !errors.As(err, &oe) {
		t.Fatalf("unknown agent: %v", err)
	}
	in = f.input(0)
	in.Contract = common.HexToAddress("0x1234")
	if _, err := Verify(context.Background(), f.client, in); !errors.As(err, &oe) {
		t.Fatalf("no contract: %v", err)
	}
	in = f.input(0)
	in.EpochID = 0
	if _, err := Verify(context.Background(), f.client, in); !errors.As(err, &oe) {
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
