// Package store persists anchoring results: the per-agent anchoring
// checkpoint and one evidence bundle per anchored epoch.
//
// Layout under the data directory:
//
//	checkpoint.json                      anchored progress per agent
//	evidence/<agentKeyHex>/epoch-<n>.json  evidence bundle for epoch n
//
// Every file is written atomically (temp file, fsync, rename, dir fsync).
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// HashScheme documents, inside every bundle, how its hashes are derived.
const HashScheme = "canonical_event=v2 (9 fields incl. Ed25519 sig over \"VeriLog/event/v1\\n\"||canonical without sig); " +
	"contentDigest=sha256(canonical_event); leaf=keccak256(contentDigest); " +
	"node=keccak256(min(a,b)||max(a,b)); odd node promoted; agentKey=keccak256(utf8(agent_id))"

// AgentProgress is the anchoring progress of one agent.
type AgentProgress struct {
	// AnchoredSeq is the highest WAL sequence included in an anchored epoch.
	AnchoredSeq uint64 `json:"anchored_seq"`
	// Epoch is the last epoch anchored for the agent.
	Epoch uint64 `json:"epoch"`
}

// Checkpoint is the durable anchoring state.
type Checkpoint struct {
	Agents map[string]AgentProgress `json:"agents"`
}

// EventProof is one event inside an evidence bundle.
type EventProof struct {
	LeafIndex     int      `json:"leaf_index"`
	Seq           uint64   `json:"seq"`
	ContentDigest string   `json:"content_digest"`
	Leaf          string   `json:"leaf"`
	Proof         []string `json:"proof"`
	// CanonicalEvent holds the exact canonical event bytes that were hashed.
	CanonicalEvent string `json:"canonical_event"`
}

// BundleVersion is the evidence bundle format version (2: signed events).
const BundleVersion = 2

// Bundle is the evidence for one anchored epoch.
type Bundle struct {
	Version     int    `json:"version"`
	HashScheme  string `json:"hash_scheme"`
	AgentID     string `json:"agent_id"`
	AgentKey    string `json:"agent_key"`
	EpochID     uint64 `json:"epoch_id"`
	MerkleRoot  string `json:"merkle_root"`
	LogCount    int    `json:"log_count"`
	ChainID     string `json:"chain_id"`
	Contract    string `json:"contract"`
	TxHash      string `json:"tx_hash"`
	BlockNumber uint64 `json:"block_number"`
	BlockHash   string `json:"block_hash,omitempty"`
	// Finality is the daemon's finality mode when it judged the anchor final
	// ("finalized", "safe" or "depth:N"); the anchor was re-read at block
	// FinalBlockNumber (hash FinalBlockHash) before this bundle was written.
	Finality         string       `json:"finality,omitempty"`
	FinalBlockNumber uint64       `json:"final_block_number,omitempty"`
	FinalBlockHash   string       `json:"final_block_hash,omitempty"`
	AnchoredAt       time.Time    `json:"anchored_at"`
	Events           []EventProof `json:"events"`
}

// Store reads and writes the checkpoint and evidence bundles.
type Store struct {
	dir string
	mu  sync.Mutex // guards the checkpoint file
}

// ErrNotFound is returned when a bundle does not exist.
var ErrNotFound = errors.New("store: not found")

// Open prepares the data directory.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dir, "evidence"), 0o700); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

// Dir returns the data directory.
func (s *Store) Dir() string { return s.dir }

func (s *Store) checkpointPath() string { return filepath.Join(s.dir, "checkpoint.json") }

// LoadCheckpoint returns the stored checkpoint, or an empty one.
func (s *Store) LoadCheckpoint() (Checkpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := Checkpoint{Agents: map[string]AgentProgress{}}
	b, err := os.ReadFile(s.checkpointPath())
	if errors.Is(err, os.ErrNotExist) {
		return cp, nil
	}
	if err != nil {
		return cp, err
	}
	if err := json.Unmarshal(b, &cp); err != nil {
		return cp, fmt.Errorf("store: corrupt checkpoint: %w", err)
	}
	if cp.Agents == nil {
		cp.Agents = map[string]AgentProgress{}
	}
	return cp, nil
}

// SaveCheckpoint atomically replaces the checkpoint.
func (s *Store) SaveCheckpoint(cp Checkpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(s.checkpointPath(), b)
}

// BundlePath returns the path of an epoch's evidence bundle.
func (s *Store) BundlePath(agentKeyHex string, epoch uint64) string {
	return filepath.Join(s.dir, "evidence", strings.ToLower(agentKeyHex), fmt.Sprintf("epoch-%d.json", epoch))
}

// WriteBundle atomically writes an evidence bundle.
func (s *Store) WriteBundle(b *Bundle) error {
	path := s.BundlePath(b.AgentKey, b.EpochID)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := MarshalBundle(b)
	if err != nil {
		return err
	}
	return writeAtomic(path, data)
}

// MarshalBundle encodes a bundle as indented JSON without HTML escaping.
func MarshalBundle(b *Bundle) ([]byte, error) {
	return marshalIndent(b)
}

// ReadBundle loads an evidence bundle.
func (s *Store) ReadBundle(agentKeyHex string, epoch uint64) (*Bundle, error) {
	return ReadBundleFile(s.BundlePath(agentKeyHex, epoch))
}

// ReadBundleFile loads an evidence bundle from a path.
func ReadBundleFile(path string) (*Bundle, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var b Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("store: corrupt bundle %s: %w", path, err)
	}
	return &b, nil
}

func marshalIndent(v any) ([]byte, error) {
	var sb strings.Builder
	enc := json.NewEncoder(&sb)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return []byte(sb.String()), nil
}

// WriteFileAtomic writes data to path (mode 0600) through a synced
// temporary file and a rename, then syncs the directory.
func WriteFileAtomic(path string, data []byte) error { return writeAtomic(path, data) }

func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
