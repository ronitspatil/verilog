// Package verify implements forensic verification of a single log event
// against the Merkle root anchored on chain.
package verify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"

	"github.com/ronitspatil/verilog/daemon/internal/canonical"
	"github.com/ronitspatil/verilog/daemon/internal/merkle"
	"github.com/ronitspatil/verilog/daemon/internal/registry"
)

// OperationalError means verification could not be performed (bad input
// files, RPC failure, epoch not anchored). It is never a verdict.
type OperationalError struct{ Err error }

func (e *OperationalError) Error() string { return e.Err.Error() }
func (e *OperationalError) Unwrap() error { return e.Err }

func opErr(format string, args ...any) error {
	return &OperationalError{Err: fmt.Errorf(format, args...)}
}

// Report is the outcome of a completed verification.
type Report struct {
	Verified      bool
	Reason        string // why verification failed (empty on success)
	AgentKey      canonical.Digest
	OnChainRoot   canonical.Digest
	ComputedRoot  canonical.Digest
	ContentDigest canonical.Digest
	Leaf          canonical.Digest
	OnChainCheck  string // "agrees", "skipped", or a description of the disagreement
}

// Input describes what to verify.
type Input struct {
	EventJSON []byte
	Proof     []merkle.Hash
	EpochID   uint64
	AgentID   string // string id, or 0x-prefixed 32-byte hex agent key
	Contract  common.Address
	// OnChainCheck additionally evaluates the proof with the contract's
	// verifyAnchoredLeaf as a second, independent opinion.
	OnChainCheck bool
}

// ParseProof decodes a JSON array of 0x-hex 32-byte strings.
func ParseProof(data []byte) ([]merkle.Hash, error) {
	var items []string
	if err := json.Unmarshal(data, &items); err != nil {
		return nil, fmt.Errorf("proof must be a JSON array of 0x-hex strings: %w", err)
	}
	out := make([]merkle.Hash, len(items))
	for i, s := range items {
		d, err := canonical.ParseDigest(s)
		if err != nil {
			return nil, fmt.Errorf("proof element %d: %w", i, err)
		}
		out[i] = d
	}
	return out, nil
}

// AgentKey resolves --agent-id: a 0x-prefixed 64-hex value is taken as the
// raw bytes32 key, anything else is hashed with keccak256(utf8(id)).
func AgentKey(id string) (canonical.Digest, bool, error) {
	if id == "" {
		return canonical.Digest{}, false, errors.New("agent id is empty")
	}
	if strings.HasPrefix(id, "0x") && len(id) == 66 {
		d, err := canonical.ParseDigest(id)
		return d, true, err
	}
	return canonical.AgentKey(id), false, nil
}

// Verify fetches the anchored root and checks the event against it.
// It returns an *OperationalError when no verdict can be reached.
func Verify(ctx context.Context, backend bind.ContractBackend, in Input) (*Report, error) {
	if in.EpochID == 0 {
		return nil, opErr("epoch id must be >= 1")
	}
	agentKey, raw, err := AgentKey(in.AgentID)
	if err != nil {
		return nil, opErr("agent id: %v", err)
	}
	reg, err := registry.NewVeriLogRegistry(in.Contract, backend)
	if err != nil {
		return nil, opErr("binding contract: %v", err)
	}
	code, err := backend.CodeAt(ctx, in.Contract, nil)
	if err != nil {
		return nil, opErr("RPC error reading contract code: %v", err)
	}
	if len(code) == 0 {
		return nil, opErr("no contract deployed at %s", in.Contract)
	}
	call := &bind.CallOpts{Context: ctx}
	anchor, err := reg.AgentAnchors(call, agentKey, new(big.Int).SetUint64(in.EpochID))
	if err != nil {
		return nil, opErr("RPC error reading agentAnchors: %v", err)
	}
	if anchor.MerkleRoot == ([32]byte{}) {
		return nil, opErr("epoch %d is not anchored for agent key %s", in.EpochID, agentKey.Hex())
	}

	rep := &Report{AgentKey: agentKey, OnChainRoot: anchor.MerkleRoot, OnChainCheck: "skipped"}
	fail := func(reason string) (*Report, error) {
		rep.Verified, rep.Reason = false, reason
		return rep, nil
	}

	// From here on, any defect in the event is evidence of tampering.
	ev, err := canonical.ParseEvent(in.EventJSON)
	if err != nil {
		return fail(fmt.Sprintf("event file is not a valid VeriLog event: %v", err))
	}
	if canonical.AgentKey(ev.AgentID) != agentKey {
		who := fmt.Sprintf("%q", in.AgentID)
		if raw {
			who = agentKey.Hex()
		}
		return fail(fmt.Sprintf("event agent_id %q does not belong to agent %s", ev.AgentID, who))
	}
	canon, err := ev.Canonical()
	if err != nil {
		return fail(fmt.Sprintf("event cannot be canonicalized: %v", err))
	}
	rep.ContentDigest = canonical.ContentDigest(canon)
	rep.Leaf = merkle.LeafFromDigest(rep.ContentDigest)
	rep.ComputedRoot = merkle.ProcessProof(rep.Leaf, in.Proof)
	if rep.ComputedRoot != rep.OnChainRoot {
		return fail("recomputed Merkle root does not match the anchored root")
	}

	if in.OnChainCheck {
		proof := make([][32]byte, len(in.Proof))
		copy(proof, in.Proof)
		ok, err := reg.VerifyAnchoredLeaf(call, agentKey, new(big.Int).SetUint64(in.EpochID), rep.Leaf, proof)
		if err != nil {
			return nil, opErr("RPC error calling verifyAnchoredLeaf: %v", err)
		}
		if !ok {
			rep.OnChainCheck = "contract verifyAnchoredLeaf returned false"
			return fail("on-chain verifyAnchoredLeaf disagrees with the local verification")
		}
		rep.OnChainCheck = "agrees"
	}
	rep.Verified = true
	return rep, nil
}
