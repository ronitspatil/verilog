package keys

import (
	"context"
	"crypto/ed25519"
	"math/big"
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

	if _, err := reg.RevokeAgentKey(opts, agent, canonical.KeyID(pub)); err != nil {
		t.Fatal(err)
	}
	sim.Commit()
	k, _ = src.AgentKey(ctx, agent, canonical.KeyID(pub))
	if !k.Revoked() || k.ValidAt(k.RevokedAt) || !k.ValidAt(k.ValidFrom) {
		t.Fatalf("revocation not visible: %+v", k)
	}
}
