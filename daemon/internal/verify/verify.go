// Package verify implements forensic verification of logged events against
// the Merkle roots and agent keys recorded on chain.
//
// Single-event mode checks one event: an event file that is exactly the
// canonical bytes, inclusion in the anchored epoch, a valid Ed25519
// signature, and a well-formed key that was registered and not revoked at
// the epoch's anchor time. Run mode requires the complete evidence of the
// agent (every anchored epoch, each rebuilding its on-chain root), checks
// every event of one run the same way, plus the hash chain: contiguous from
// genesis, no forks, epochs never going backwards along the chain, and a
// terminal run_end event.
//
// Only the chain is trusted. Evidence bundles and event files come from the
// daemon host and are treated as untrusted input: any defect in them is a
// FAILURE verdict, never a "no verdict" outcome.
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

// OperationalError means verification could not be performed: bad
// arguments, unreadable files, or an RPC failure. It is never a verdict, and
// a defect in the evidence itself (an unanchored epoch, a malformed event, a
// missing bundle) is never an OperationalError: it is a FAILURE.
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
	// Canonical holds the canonical bytes of the event when the event file
	// parsed but was not in canonical form: these are the bytes that were
	// hashed and signed, which may display different values.
	Canonical []byte
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
	// at pins every read to this block (the final block); nil reads the
	// head. With a pin, anchors that exist at the head but not at the pin
	// are "not final yet", which is no verdict rather than a FAILURE.
	at *big.Int

	anchors     map[[40]byte]anchorInfo
	headAnchors map[[40]byte]anchorInfo
	keyMemo     map[[64]byte]keys.Key
}

type anchorInfo struct {
	root      canonical.Digest
	timestamp uint64
	count     uint32
	found     bool // false: the epoch is not anchored for the agent
}

// New binds the registry at contract and reads the chain head. It returns
// an *OperationalError if the contract cannot be reached or has no code.
func New(ctx context.Context, backend bind.ContractBackend, contract common.Address, onChainCheck bool) (*Verifier, error) {
	return NewAt(ctx, backend, contract, onChainCheck, nil)
}

// NewAt is New with every read pinned to block at (the final block under
// the chosen finality); nil reads the head.
func NewAt(ctx context.Context, backend bind.ContractBackend, contract common.Address, onChainCheck bool, at *big.Int) (*Verifier, error) {
	reg, err := registry.NewVeriLogRegistry(contract, backend)
	if err != nil {
		return nil, opErr("binding contract: %v", err)
	}
	code, err := backend.CodeAt(ctx, contract, at)
	if err != nil {
		return nil, opErr("RPC error reading contract code: %v", err)
	}
	if len(code) == 0 {
		if at != nil {
			return nil, opErr("no contract deployed at %s as of block %s", contract, at)
		}
		return nil, opErr("no contract deployed at %s", contract)
	}
	src, err := keys.NewChainSource(contract, backend)
	if err != nil {
		return nil, opErr("binding contract: %v", err)
	}
	return &Verifier{
		backend: backend, reg: reg, keys: src.At(at), onChainCheck: onChainCheck, at: at,
		anchors: map[[40]byte]anchorInfo{}, headAnchors: map[[40]byte]anchorInfo{}, keyMemo: map[[64]byte]keys.Key{},
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

// anchor reads an epoch's anchor. An epoch that is not anchored is not an
// error (found is false): it is a claim of the evidence that the chain refutes.
func (v *Verifier) anchor(ctx context.Context, agentKey canonical.Digest, epoch uint64) (anchorInfo, error) {
	return v.anchorAt(ctx, agentKey, epoch, v.at, v.anchors)
}

// headAnchor reads an epoch's anchor at the chain head.
func (v *Verifier) headAnchor(ctx context.Context, agentKey canonical.Digest, epoch uint64) (anchorInfo, error) {
	return v.anchorAt(ctx, agentKey, epoch, nil, v.headAnchors)
}

func (v *Verifier) anchorAt(ctx context.Context, agentKey canonical.Digest, epoch uint64, block *big.Int, memo map[[40]byte]anchorInfo) (anchorInfo, error) {
	var id [40]byte
	copy(id[:32], agentKey[:])
	big.NewInt(0).SetUint64(epoch).FillBytes(id[32:])
	if a, ok := memo[id]; ok {
		return a, nil
	}
	out, err := v.reg.AgentAnchors(v.call(ctx, block), agentKey, new(big.Int).SetUint64(epoch))
	if err != nil {
		return anchorInfo{}, opErr("RPC error reading agentAnchors: %v", err)
	}
	a := anchorInfo{root: out.MerkleRoot, timestamp: out.Timestamp, count: out.LogCount, found: out.MerkleRoot != ([32]byte{})}
	memo[id] = a
	return a, nil
}

func (v *Verifier) call(ctx context.Context, block *big.Int) *bind.CallOpts {
	return &bind.CallOpts{Context: ctx, BlockNumber: block}
}

// notFinalError is the "not anchored yet" answer: the epoch is anchored at
// the head but not at the final block.
func (v *Verifier) notFinalError(epoch uint64, agentKey canonical.Digest) error {
	return opErr("epoch %d of agent key %s is anchored but not final at block %s: not anchored yet; "+
		"retry once it is final (see --finality)", epoch, agentKey.Hex(), v.at)
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

	rep := &Report{AgentKey: agentKey, OnChainRoot: anc.root, OnChainCheck: "skipped"}
	fail := func(reason string) (*Report, error) {
		rep.Verified, rep.Reason = false, reason
		return rep, nil
	}
	// The evidence claims the event is anchored in this epoch: if the chain
	// has no such epoch, the claim is false.
	if !anc.found {
		if v.at != nil {
			head, err := v.headAnchor(ctx, agentKey, epochID)
			if err != nil {
				return nil, err
			}
			if head.found {
				return nil, v.notFinalError(epochID, agentKey)
			}
		}
		return fail(fmt.Sprintf("epoch %d is not anchored for agent key %s", epochID, agentKey.Hex()))
	}
	rep.AnchoredAt = time.Unix(int64(anc.timestamp), 0).UTC()

	// From here on, any defect in the event is evidence of tampering.
	ev, canon, err := canonical.ParseCanonicalEvent(eventJSON)
	if err != nil {
		if errors.Is(err, canonical.ErrNotCanonical) {
			rep.Canonical = canon
		}
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
	rep.ContentDigest = canonical.ContentDigest(canon)
	rep.Leaf = merkle.LeafFromDigest(rep.ContentDigest)
	rep.ComputedRoot = merkle.ProcessProof(rep.Leaf, proof)
	if rep.ComputedRoot != rep.OnChainRoot {
		return fail("recomputed Merkle root does not match the anchored root")
	}

	if v.onChainCheck {
		p := make([][32]byte, len(proof))
		copy(p, proof)
		ok, err := v.reg.VerifyAnchoredLeaf(v.call(ctx, v.at), agentKey, new(big.Int).SetUint64(epochID), rep.Leaf, p)
		if err != nil {
			return nil, opErr("RPC error calling verifyAnchoredLeaf: %v", err)
		}
		if !ok {
			rep.OnChainCheck = "contract verifyAnchoredLeaf returned false"
			return fail("on-chain verifyAnchoredLeaf disagrees with the local verification")
		}
		rep.OnChainCheck = "agrees"
	}

	reason, status, err := v.checkSource(ctx, agentKey, ev, epochID, anc.timestamp)
	if err != nil {
		return nil, err
	}
	rep.KeyStatus = status
	if reason != "" {
		return fail(reason)
	}
	rep.Verified = true
	return rep, nil
}

// checkSource checks source authenticity: the event's key must be registered
// on chain for the agent, be a well-formed Ed25519 key, and be valid at the
// anchor time of the epoch, and the signature must verify. It returns the
// reason the check failed ("" if it passed) and a description of the key.
func (v *Verifier) checkSource(ctx context.Context, agentKey canonical.Digest, ev canonical.Event, epochID, anchoredAt uint64) (reason, status string, err error) {
	key, err := v.agentKey(ctx, agentKey, ev.KeyID)
	if err != nil {
		return "", "", err
	}
	switch {
	case !key.Registered():
		return fmt.Sprintf("signing key %s is not registered on chain for agent %q", ev.KeyID.Hex(), ev.AgentID), "not registered", nil
	case key.WellFormed() != nil:
		return fmt.Sprintf("registered signing key %s is unsafe and proves nothing: %v", ev.KeyID.Hex(), key.WellFormed()), "unsafe key", nil
	case !key.ValidAt(anchoredAt):
		return fmt.Sprintf("signing key %s was not valid when epoch %d was anchored at %d (%s)",
			ev.KeyID.Hex(), epochID, anchoredAt, keyWindow(key)), keyWindow(key), nil
	}
	if err := ev.VerifySig(key.Pubkey); err != nil {
		return fmt.Sprintf("signature does not verify with registered key %s: %v", ev.KeyID.Hex(), err), "valid at anchor time", nil
	}
	return "", "valid at anchor time (" + keyWindow(key) + ")", nil
}

func keyWindow(k keys.Key) string {
	if k.RevokedAt == 0 {
		return fmt.Sprintf("registered at %d, not revoked", k.ValidFrom)
	}
	return fmt.Sprintf("registered at %d, revoked effective %d", k.ValidFrom, k.RevokedAt)
}
