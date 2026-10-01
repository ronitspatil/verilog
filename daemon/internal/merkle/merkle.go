// Package merkle implements the VeriLog Merkle tree.
//
// The scheme is byte-for-byte compatible with OpenZeppelin's MerkleProof
// (commutative keccak256):
//
//	leaf = keccak256(contentDigest)            // 32-byte preimage
//	node = keccak256(min(a,b) || max(a,b))     // 64-byte preimage, sorted pair
//
// When a level has an odd number of nodes, the last node is promoted to the
// next level unchanged; proofs for leaves under that node simply have no
// sibling for that level. A one-leaf tree has root == leaf and an empty proof.
//
// Leaves (32-byte preimage) and internal nodes (64-byte preimage) are domain
// separated by preimage length, which blocks second-preimage attacks that
// present an internal node as a leaf.
package merkle

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"
	"sync"

	"golang.org/x/crypto/sha3"
)

// Hash is a 32-byte keccak256 digest.
type Hash = [32]byte

// ErrEmptyTree is returned when a root or proof is requested from an empty tree.
var ErrEmptyTree = errors.New("merkle: empty tree")

// parallelThreshold is the level width above which hashing fans out to
// multiple goroutines. Below it the goroutine overhead dominates.
const parallelThreshold = 2048

// LeafFromDigest derives the Merkle leaf from a SHA-256 content digest.
func LeafFromDigest(digest [32]byte) Hash {
	var out Hash
	h := sha3.NewLegacyKeccak256()
	h.Write(digest[:])
	h.Sum(out[:0])
	return out
}

// HashPair hashes two nodes in sorted order (OpenZeppelin commutativeKeccak256).
func HashPair(a, b Hash) Hash {
	if bytes.Compare(a[:], b[:]) > 0 {
		a, b = b, a
	}
	var buf [64]byte
	copy(buf[:32], a[:])
	copy(buf[32:], b[:])
	var out Hash
	h := sha3.NewLegacyKeccak256()
	h.Write(buf[:])
	h.Sum(out[:0])
	return out
}

// LeavesFromDigests hashes content digests into leaves, in parallel for large inputs.
func LeavesFromDigests(digests [][32]byte) []Hash {
	out := make([]Hash, len(digests))
	parallelFor(len(digests), func(lo, hi int) {
		for i := lo; i < hi; i++ {
			out[i] = LeafFromDigest(digests[i])
		}
	})
	return out
}

// Sealed is an immutable tree with every level materialized, so proofs are
// O(log n) lookups. It is safe for concurrent use.
type Sealed struct {
	levels [][]Hash // levels[0] = leaves, last level = [root]
}

// Build constructs a sealed tree over leaves. The slice is copied.
func Build(leaves []Hash) (*Sealed, error) {
	if len(leaves) == 0 {
		return nil, ErrEmptyTree
	}
	level := make([]Hash, len(leaves))
	copy(level, leaves)
	levels := [][]Hash{level}
	for len(level) > 1 {
		level = nextLevel(level)
		levels = append(levels, level)
	}
	return &Sealed{levels: levels}, nil
}

func nextLevel(level []Hash) []Hash {
	pairs := len(level) / 2
	next := make([]Hash, (len(level)+1)/2)
	parallelFor(pairs, func(lo, hi int) {
		for i := lo; i < hi; i++ {
			next[i] = HashPair(level[2*i], level[2*i+1])
		}
	})
	if len(level)%2 == 1 {
		next[pairs] = level[len(level)-1] // odd node promoted unchanged
	}
	return next
}

// Root returns the Merkle root.
func (s *Sealed) Root() Hash { return s.levels[len(s.levels)-1][0] }

// Len returns the number of leaves.
func (s *Sealed) Len() int { return len(s.levels[0]) }

// Leaf returns leaf i.
func (s *Sealed) Leaf(i int) (Hash, error) {
	if i < 0 || i >= s.Len() {
		return Hash{}, fmt.Errorf("merkle: leaf index %d out of range [0,%d)", i, s.Len())
	}
	return s.levels[0][i], nil
}

// Proof returns the sibling path for leaf i, from the leaf level upward.
func (s *Sealed) Proof(i int) ([]Hash, error) {
	if i < 0 || i >= s.Len() {
		return nil, fmt.Errorf("merkle: leaf index %d out of range [0,%d)", i, s.Len())
	}
	proof := make([]Hash, 0, len(s.levels)-1)
	idx := i
	for _, level := range s.levels[:len(s.levels)-1] {
		sib := idx ^ 1
		if sib < len(level) {
			proof = append(proof, level[sib])
		}
		idx /= 2
	}
	return proof, nil
}

// ProcessProof folds a proof over a leaf and returns the implied root.
func ProcessProof(leaf Hash, proof []Hash) Hash {
	cur := leaf
	for _, p := range proof {
		cur = HashPair(cur, p)
	}
	return cur
}

// Verify reports whether proof proves leaf's inclusion under root.
func Verify(leaf Hash, proof []Hash, root Hash) bool {
	return ProcessProof(leaf, proof) == root
}

// Tree is an append-only, thread-safe Merkle tree. Appends are O(1); the
// root and proofs are computed lazily and cached until the next append.
type Tree struct {
	mu     sync.RWMutex
	leaves []Hash
	cache  *Sealed // nil when stale
}

// NewTree returns an empty tree with capacity for sizeHint leaves.
func NewTree(sizeHint int) *Tree {
	return &Tree{leaves: make([]Hash, 0, sizeHint)}
}

// Append adds a leaf and returns its index.
func (t *Tree) Append(leaf Hash) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.leaves = append(t.leaves, leaf)
	t.cache = nil
	return len(t.leaves) - 1
}

// Len returns the number of leaves.
func (t *Tree) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.leaves)
}

// Seal returns an immutable snapshot of the current tree.
func (t *Tree) Seal() (*Sealed, error) {
	t.mu.RLock()
	if c := t.cache; c != nil {
		t.mu.RUnlock()
		return c, nil
	}
	t.mu.RUnlock()

	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cache != nil {
		return t.cache, nil
	}
	s, err := Build(t.leaves)
	if err != nil {
		return nil, err
	}
	t.cache = s
	return s, nil
}

// Root returns the current Merkle root.
func (t *Tree) Root() (Hash, error) {
	s, err := t.Seal()
	if err != nil {
		return Hash{}, err
	}
	return s.Root(), nil
}

// Proof returns the inclusion proof for leaf i against the current root.
func (t *Tree) Proof(i int) ([]Hash, error) {
	s, err := t.Seal()
	if err != nil {
		return nil, err
	}
	return s.Proof(i)
}

// parallelFor splits [0,n) into chunks processed concurrently when n is large.
func parallelFor(n int, fn func(lo, hi int)) {
	workers := runtime.GOMAXPROCS(0)
	if n < parallelThreshold || workers < 2 {
		fn(0, n)
		return
	}
	chunk := (n + workers - 1) / workers
	var wg sync.WaitGroup
	for lo := 0; lo < n; lo += chunk {
		hi := min(lo+chunk, n)
		wg.Add(1)
		go func(lo, hi int) {
			defer wg.Done()
			fn(lo, hi)
		}(lo, hi)
	}
	wg.Wait()
}
