package finality

import (
	"context"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/core/types"
)

func TestParse(t *testing.T) {
	for in, want := range map[string]Mode{
		"finalized": {Kind: Finalized},
		"safe":      {Kind: Safe},
		"latest":    {Kind: Latest},
		"depth:0":   {Kind: Depth},
		"depth:12":  {Kind: Depth, Depth: 12},
	} {
		got, err := Parse(in)
		if err != nil || got != want || got.String() != in {
			t.Errorf("Parse(%q) = %+v, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "final", "depth:", "depth:-1", "depth:x", "depth:9999999999"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) accepted", bad)
		}
	}
	if (Mode{}).String() != "finalized" {
		t.Error("zero Mode must be finalized")
	}
}

// fakeHeaders serves a chain of n+1 blocks; tags are optional.
type fakeHeaders struct {
	head int64
	tags map[int64]int64 // tag (negative) -> block
}

func (f fakeHeaders) HeaderByNumber(_ context.Context, n *big.Int) (*types.Header, error) {
	switch {
	case n == nil:
		return &types.Header{Number: big.NewInt(f.head)}, nil
	case n.Sign() < 0:
		b, ok := f.tags[n.Int64()]
		if !ok {
			return nil, errors.New("invalid block tag")
		}
		return &types.Header{Number: big.NewInt(b)}, nil
	}
	return &types.Header{Number: new(big.Int).Set(n)}, nil
}

func TestPoint(t *testing.T) {
	ctx := context.Background()
	r := fakeHeaders{head: 100, tags: map[int64]int64{-3: 64, -4: 90}}
	for m, want := range map[Mode]int64{
		{Kind: Finalized}:          64,
		{Kind: Safe}:               90,
		{Kind: Latest}:             100,
		{Kind: Depth, Depth: 0}:    100,
		{Kind: Depth, Depth: 12}:   88,
		{Kind: Depth, Depth: 1000}: 0,
	} {
		h, err := m.Point(ctx, r)
		if err != nil || h.Number.Int64() != want {
			t.Errorf("%s: %v %v, want %d", m, h, err, want)
		}
	}
	_, err := Mode{Kind: Finalized}.Check(ctx, fakeHeaders{head: 5})
	if err == nil || !strings.Contains(err.Error(), "--finality depth:N") {
		t.Fatalf("missing tag: %v", err)
	}
}
