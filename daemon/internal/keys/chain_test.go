package keys

import (
	"context"
	"crypto/ed25519"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient/simulated"

	"github.com/ronitspatil/verilog/daemon/internal/canonical"
	"github.com/ronitspatil/verilog/daemon/internal/registry"
)

func TestChainSourceReadsRegistry(t *testing.T) {
	admin, _ := crypto.GenerateKey()
	anchorer, _ := crypto.GenerateKey()
	from := crypto.PubkeyToAddress(admin.PublicKey)
	sim := simulated.NewBackend(types.GenesisAlloc{from: {Balance: new(big.Int).Lsh(big.NewInt(1), 100)}})
	t.Cleanup(func() { sim.Close() })
	client := sim.Client()
	chainID, _ := client.ChainID(context.Background())
	opts, _ := bind.NewKeyedTransactorWithChainID(admin, chainID)
	addr, _, reg, err := registry.DeployVeriLogRegistry(opts, client, from, crypto.PubkeyToAddress(anchorer.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	sim.Commit()

	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	pub := priv.Public().(ed25519.PublicKey)
	agent := canonical.AgentKey("agent-k")
	var pub32 [32]byte
	copy(pub32[:], pub)
	if _, err := reg.RegisterAgentKey(opts, agent, pub32); err != nil {
		t.Fatal(err)
	}
	sim.Commit()

	src, err := NewChainSource(addr, client)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	k, err := src.AgentKey(ctx, agent, canonical.KeyID(pub))
	if err != nil {
		t.Fatal(err)
	}
	if !k.Registered() || !pub.Equal(k.Pubkey) || k.ValidFrom == 0 || k.Revoked() {
		t.Fatalf("unexpected key %+v", k)
	}
	if k2, _ := src.AgentKey(ctx, canonical.AgentKey("other"), canonical.KeyID(pub)); k2.Registered() {
		t.Fatal("key registered for another agent")
	}

	// Schedule the revocation an hour ahead: recorded now, effective later.
	head, _ := client.HeaderByNumber(ctx, nil)
	effective := head.Time + 3600
	if _, err := reg.RevokeAgentKey(opts, agent, canonical.KeyID(pub), effective); err != nil {
		t.Fatal(err)
	}
	sim.Commit()
	k, _ = src.AgentKey(ctx, agent, canonical.KeyID(pub))
	if !k.Revoked() || k.RevokedAt != effective || k.ValidAt(k.RevokedAt) || !k.ValidAt(k.RevokedAt-1) || !k.ValidAt(k.ValidFrom) {
		t.Fatalf("revocation not visible: %+v", k)
	}
	check := RevocationCheck{Src: src, Now: func(context.Context) (uint64, error) { return head.Time + 10, nil }}
	if r, err := check.RevokedNow(ctx, agent, canonical.KeyID(pub)); err != nil || r {
		t.Fatalf("scheduled revocation reported in effect: %v %v", r, err)
	}
	check.Now = func(context.Context) (uint64, error) { return effective, nil }
	if r, err := check.RevokedNow(ctx, agent, canonical.KeyID(pub)); err != nil || !r {
		t.Fatalf("revocation in effect not reported: %v %v", r, err)
	}

	// The contract refuses the identity point (H1): with it, R = identity,
	// S = 0 is a valid signature of any message.
	var identity [32]byte
	identity[0] = 1
	if _, err := reg.RegisterAgentKey(opts, agent, identity); err == nil || !strings.Contains(err.Error(), "revert") {
		t.Fatalf("weak key registered: %v", err)
	}
}
