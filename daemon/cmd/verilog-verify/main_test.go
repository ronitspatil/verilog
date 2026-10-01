package main

import (
	"bytes"
	"context"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient/simulated"

	"github.com/ronitspatil/verilog/daemon/internal/finality"
)

func TestPinChain(t *testing.T) {
	sim := simulated.NewBackend(types.GenesisAlloc{})
	defer sim.Close()
	for i := 0; i < 5; i++ {
		sim.Commit()
	}
	ctx := context.Background()
	c := sim.Client()
	id, _ := c.ChainID(ctx)

	if _, err := pinChain(ctx, c, new(big.Int).Add(id, big.NewInt(1)), finality.Mode{}); err == nil || !strings.Contains(err.Error(), "not --chain-id") {
		t.Fatalf("chain id mismatch accepted: %v", err)
	}
	h, err := pinChain(ctx, c, id, finality.Mode{Kind: finality.Depth, Depth: 2})
	if err != nil || h.Number.Uint64() != 3 {
		t.Fatalf("depth:2 at head 5: %v %v", h, err)
	}
	if h, err := pinChain(ctx, c, id, finality.Mode{Kind: finality.Latest}); err != nil || h.Number.Uint64() != 5 {
		t.Fatalf("latest: %v %v", h, err)
	}
}

func TestChainIDAndFinalityFlags(t *testing.T) {
	base := []string{"--event", "e.json", "--proof", "p.json", "--epoch", "1", "--agent-id", "a",
		"--rpc", "http://127.0.0.1:1", "--contract", "0x5FbDB2315678afecb367f032d93F642f64180aa3"}
	t.Setenv("VERILOG_CHAIN_ID", "")
	for _, tc := range []struct {
		extra []string
		want  string
	}{
		{nil, "--chain-id (or VERILOG_CHAIN_ID) is required"},
		{[]string{"--chain-id", "zero"}, "--chain-id must be a positive"},
		{[]string{"--chain-id", "1", "--finality", "soon"}, "--finality"},
	} {
		var out, errOut bytes.Buffer
		if code := run(append(append([]string{}, base...), tc.extra...), &out, &errOut); code != exitOperational || out.Len() != 0 ||
			!strings.Contains(errOut.String(), tc.want) {
			t.Errorf("%v: exit %d stdout %q stderr %q", tc.extra, code, out.String(), errOut.String())
		}
	}
}
