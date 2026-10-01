// Package finality decides which block of the chain is final: the newest
// block that a reorganization is not expected to remove.
//
// The daemon compacts its write-ahead log only once an anchor is in a final
// block, and the verifier pins every read to the final block, so that neither
// relies on state a reorg (or an RPC endpoint serving a short-lived fork) can
// take back.
package finality

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
)

// Kind is how finality is determined.
type Kind int

const (
	// Finalized uses the RPC "finalized" block tag (proof-of-stake
	// finality on Ethereum L1; on rollups, the L2 block whose batch is in a
	// finalized L1 block).
	Finalized Kind = iota
	// Safe uses the RPC "safe" block tag.
	Safe
	// Depth treats a block as final once Depth blocks are built on it.
	Depth
	// Latest trusts the chain head (the verifier's --finality latest only).
	Latest
)

// Mode is a finality rule. The zero Mode is Finalized.
type Mode struct {
	Kind  Kind
	Depth uint64 // for Depth
}

// MaxDepth bounds depth:N.
const MaxDepth = 1 << 20

// Parse reads "finalized", "safe", "latest" or "depth:N".
func Parse(s string) (Mode, error) {
	switch s {
	case "finalized":
		return Mode{Kind: Finalized}, nil
	case "safe":
		return Mode{Kind: Safe}, nil
	case "latest":
		return Mode{Kind: Latest}, nil
	}
	if n, ok := strings.CutPrefix(s, "depth:"); ok {
		d, err := strconv.ParseUint(n, 10, 64)
		if err == nil && d <= MaxDepth {
			return Mode{Kind: Depth, Depth: d}, nil
		}
	}
	return Mode{}, fmt.Errorf("invalid finality %q (finalized, safe, latest or depth:N)", s)
}

// String is the form Parse accepts.
func (m Mode) String() string {
	switch m.Kind {
	case Safe:
		return "safe"
	case Depth:
		return fmt.Sprintf("depth:%d", m.Depth)
	case Latest:
		return "latest"
	default:
		return "finalized"
	}
}

// HeaderReader reads block headers (*ethclient.Client implements it).
type HeaderReader interface {
	HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error)
}

// ErrTagUnsupported means the RPC endpoint does not serve the block tag.
var ErrTagUnsupported = errors.New("block tag not supported by the RPC endpoint")

// Point returns the newest final block under m.
func (m Mode) Point(ctx context.Context, r HeaderReader) (*types.Header, error) {
	switch m.Kind {
	case Finalized, Safe:
		tag := rpc.FinalizedBlockNumber
		if m.Kind == Safe {
			tag = rpc.SafeBlockNumber
		}
		h, err := r.HeaderByNumber(ctx, big.NewInt(int64(tag)))
		if err != nil {
			return nil, fmt.Errorf("reading the %q block: %w", m, err)
		}
		if h == nil || h.Number == nil {
			return nil, fmt.Errorf("reading the %q block: %w", m, ErrTagUnsupported)
		}
		return h, nil
	case Latest, Depth:
		head, err := r.HeaderByNumber(ctx, nil)
		if err != nil {
			return nil, fmt.Errorf("reading the chain head: %w", err)
		}
		if m.Kind == Latest || m.Depth == 0 {
			return head, nil
		}
		n := new(big.Int).Sub(head.Number, new(big.Int).SetUint64(m.Depth))
		if n.Sign() < 0 {
			n.SetUint64(0)
		}
		h, err := r.HeaderByNumber(ctx, n)
		if err != nil {
			return nil, fmt.Errorf("reading block %s: %w", n, err)
		}
		return h, nil
	}
	return nil, fmt.Errorf("unknown finality kind %d", m.Kind)
}

// Check is the startup check: it reads the final block once and turns a
// missing block tag into an actionable error.
func (m Mode) Check(ctx context.Context, r HeaderReader) (*types.Header, error) {
	h, err := m.Point(ctx, r)
	if err != nil && (m.Kind == Finalized || m.Kind == Safe) {
		return nil, fmt.Errorf("finality %q: the RPC endpoint does not serve the %q block tag (%v); "+
			"use an endpoint that does, or --finality depth:N", m, m, err)
	}
	return h, err
}
