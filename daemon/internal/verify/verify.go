// Package verify implements forensic verification of logged events against
// the Merkle roots and agent keys recorded on chain.
//
// Single-event mode checks one event: inclusion in the anchored epoch, a
// valid Ed25519 signature, and a key that was registered and not revoked at
// the epoch's anchor time. Run mode checks every event of one run the same
// way, plus the hash chain: contiguous from genesis, no forks, epochs never
// going backwards along the chain, and a terminal run_end event.
//
// Only the chain is trusted. Evidence bundles and event files come from the
// daemon host and are treated as untrusted input.
package verify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"

	"github.com/ronitspatil/verilog/daemon/internal/canonical"
	"github.com/ronitspatil/verilog/daemon/internal/keys"
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

// Report is the outcome of a completed single-event verification.
type Report struct {
	Verified      bool
	Reason        string // why verification failed (empty on success)
	AgentKey      canonical.Digest
	OnChainRoot   canonical.Digest
	AnchoredAt    time.Time // block timestamp of the epoch's anchor
	ComputedRoot  canonical.Digest
	ContentDigest canonical.Digest
	Leaf          canonical.Digest
	OnChainCheck  string // "agrees", "skipped", or a description of the disagreement
	// Parsed event fields (set once the event parses).
	RunID      string
	StepNumber uint64
	EventType  string
	KeyID      canonical.Digest
	PrevHash   canonical.Digest
	KeyStatus  string // e.g. "valid at anchor time"
}

// Input describes one event to verify.
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

// Verifier verifies events against one registry. It caches anchors and keys,
// so it is meant for one verification session; it is not safe for concurrent use.
type Verifier struct {
	backend      bind.ContractBackend
	reg          *registry.VeriLogRegistry
	keys         keys.Source
	onChainCheck bool

	anchors map[[40]byte]anchorInfo
	keyMemo map[[64]byte]keys.Key
}

type anchorInfo struct {
	root      canonical.Digest
	timestamp uint64
}

// New binds the registry at contract. It returns an *OperationalError if
// the contract cannot be reached or has no code.
func New(ctx context.Context, backend bind.ContractBackend, contract common.Address, onChainCheck bool) (*Verifier, error) {
	reg, err := registry.NewVeriLogRegistry(contract, backend)
	if err != nil {
		return nil, opErr("binding contract: %v", err)
	}
	code, err := backend.CodeAt(ctx, contract, nil)
	if err != nil {
		return nil, opErr("RPC error reading contract code: %v", err)
	}
	if len(code) == 0 {
		return nil, opErr("no contract deployed at %s", contract)
	}
	src, err := keys.NewChainSource(contract, backend)
	if err != nil {
		return nil, opErr("binding contract: %v", err)
	}
	return &Verifier{
		backend: backend, reg: reg, keys: src, onChainCheck: onChainCheck,
		anchors: map[[40]byte]anchorInfo{}, keyMemo: map[[64]byte]keys.Key{},
	}, nil
}

// Verify checks one event. It returns an *OperationalError when no verdict
// can be reached.
func Verify(ctx context.Context, backend bind.ContractBackend, in Input) (*Report, error) {
	v, err := New(ctx, backend, in.Contract, in.OnChainCheck)
	if err != nil {
		return nil, err
	}
	return v.Event(ctx, in.EventJSON, in.Proof, in.EpochID, in.AgentID)
}

func (v *Verifier) anchor(ctx context.Context, agentKey canonical.Digest, epoch uint64) (anchorInfo, error) {
	var id [40]byte
	copy(id[:32], agentKey[:])
	big.NewInt(0).SetUint64(epoch).FillBytes(id[32:])
	if a, ok := v.anchors[id]; ok {
		return a, nil
	}
	out, err := v.reg.AgentAnchors(&bind.CallOpts{Context: ctx}, agentKey, new(big.Int).SetUint64(epoch))
	if err != nil {
		return anchorInfo{}, opErr("RPC error reading agentAnchors: %v", err)
	}
	if out.MerkleRoot == ([32]byte{}) {
		return anchorInfo{}, opErr("epoch %d is not anchored for agent key %s", epoch, agentKey.Hex())
	}
	a := anchorInfo{root: out.MerkleRoot, timestamp: out.Timestamp}
	v.anchors[id] = a
	return a, nil
}

func (v *Verifier) agentKey(ctx context.Context, agentKey, keyID canonical.Digest) (keys.Key, error) {
	var id [64]byte
	copy(id[:32], agentKey[:])
	copy(id[32:], keyID[:])
	if k, ok := v.keyMemo[id]; ok {
		return k, nil
	}
	k, err := v.keys.AgentKey(ctx, agentKey, keyID)
	if err != nil {
		return keys.Key{}, opErr("RPC error reading agentKeys: %v", err)
	}
	v.keyMemo[id] = k
	return k, nil
}

// Event verifies one event (raw JSON) with its Merkle proof against epoch
// epochID of agentID.
func (v *Verifier) Event(ctx context.Context, eventJSON []byte, proof []merkle.Hash, epochID uint64, agentID string) (*Report, error) {
	if epochID == 0 {
		return nil, opErr("epoch id must be >= 1")
	}
	agentKey, raw, err := AgentKey(agentID)
	if err != nil {
		return nil, opErr("agent id: %v", err)
	}
	anc, err := v.anchor(ctx, agentKey, epochID)
	if err != nil {
		return nil, err
	}

	rep := &Report{
		AgentKey: agentKey, OnChainRoot: anc.root, OnChainCheck: "skipped",
		AnchoredAt: time.Unix(int64(anc.timestamp), 0).UTC(),
	}
	fail := func(reason string) (*Report, error) {
		rep.Verified, rep.Reason = false, reason
		return rep, nil
	}

	// From here on, any defect in the event is evidence of tampering.
	ev, err := canonical.ParseEvent(eventJSON)
	if err != nil {
		return fail(fmt.Sprintf("event file is not a valid VeriLog event: %v", err))
	}
	rep.RunID, rep.StepNumber, rep.EventType, rep.KeyID, rep.PrevHash = ev.RunID, ev.StepNumber, ev.EventType, ev.KeyID, ev.PrevHash
	if canonical.AgentKey(ev.AgentID) != agentKey {
		who := fmt.Sprintf("%q", agentID)
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
	rep.ComputedRoot = merkle.ProcessProof(rep.Leaf, proof)
	if rep.ComputedRoot != rep.OnChainRoot {
		return fail("recomputed Merkle root does not match the anchored root")
	}

	if v.onChainCheck {
		p := make([][32]byte, len(proof))
		copy(p, proof)
		ok, err := v.reg.VerifyAnchoredLeaf(&bind.CallOpts{Context: ctx}, agentKey, new(big.Int).SetUint64(epochID), rep.Leaf, p)
		if err != nil {
			return nil, opErr("RPC error calling verifyAnchoredLeaf: %v", err)
		}
		if !ok {
			rep.OnChainCheck = "contract verifyAnchoredLeaf returned false"
			return fail("on-chain verifyAnchoredLeaf disagrees with the local verification")
		}
		rep.OnChainCheck = "agrees"
	}

	// Source authenticity: the key must be registered on chain for this agent
	// and valid at the anchor time, and the signature must verify.
	key, err := v.agentKey(ctx, agentKey, ev.KeyID)
	if err != nil {
		return nil, err
	}
	switch {
	case !key.Registered():
		rep.KeyStatus = "not registered"
		return fail(fmt.Sprintf("signing key %s is not registered on chain for agent %q", ev.KeyID.Hex(), ev.AgentID))
	case !key.ValidAt(anc.timestamp):
		rep.KeyStatus = keyWindow(key)
		return fail(fmt.Sprintf("signing key %s was not valid when epoch %d was anchored at %d (%s)",
			ev.KeyID.Hex(), epochID, anc.timestamp, keyWindow(key)))
	}
	if err := ev.VerifySig(key.Pubkey); err != nil {
		rep.KeyStatus = "valid at anchor time"
		return fail(fmt.Sprintf("signature does not verify with registered key %s: %v", ev.KeyID.Hex(), err))
	}
	rep.KeyStatus = "valid at anchor time (" + keyWindow(key) + ")"
	rep.Verified = true
	return rep, nil
}

func keyWindow(k keys.Key) string {
	if k.RevokedAt == 0 {
		return fmt.Sprintf("registered at %d, not revoked", k.ValidFrom)
	}
	return fmt.Sprintf("registered at %d, revoked at %d", k.ValidFrom, k.RevokedAt)
}
