package merkle

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sync"
	"testing"
)

func digestN(i int) [32]byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(i))
	return sha256.Sum256(b[:])
}

func leavesN(n int) []Hash {
	ds := make([][32]byte, n)
	for i := range ds {
		ds[i] = digestN(i)
	}
	return LeavesFromDigests(ds)
}

// refRoot is a deliberately naive recursive reference implementation.
func refRoot(level []Hash) Hash {
	if len(level) == 1 {
		return level[0]
	}
	var next []Hash
	for i := 0; i+1 < len(level); i += 2 {
		next = append(next, HashPair(level[i], level[i+1]))
	}
	if len(level)%2 == 1 {
		next = append(next, level[len(level)-1])
	}
	return refRoot(next)
}

func TestKnownVectors(t *testing.T) {
	// keccak256 of 32 zero bytes, computed independently (cast keccak 0x00..00).
	got := LeafFromDigest([32]byte{})
	const want = "290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"
	if hex.EncodeToString(got[:]) != want {
		t.Fatalf("LeafFromDigest(0) = %x, want %s", got, want)
	}
}

func TestHashPairCommutative(t *testing.T) {
	a, b := LeafFromDigest(digestN(1)), LeafFromDigest(digestN(2))
	if HashPair(a, b) != HashPair(b, a) {
		t.Fatal("HashPair must be commutative")
	}
}

func TestRootAndProofsAllSizes(t *testing.T) {
	for n := 1; n <= 70; n++ {
		leaves := leavesN(n)
		s, err := Build(leaves)
		if err != nil {
			t.Fatal(err)
		}
		if s.Root() != refRoot(leaves) {
			t.Fatalf("n=%d: root mismatch with reference", n)
		}
		for i := 0; i < n; i++ {
			p, err := s.Proof(i)
			if err != nil {
				t.Fatal(err)
			}
			if !Verify(leaves[i], p, s.Root()) {
				t.Fatalf("n=%d i=%d: valid proof rejected", n, i)
			}
			// Wrong leaf must fail.
			if Verify(leaves[(i+1)%n], p, s.Root()) && n > 1 {
				t.Fatalf("n=%d i=%d: proof accepted for wrong leaf", n, i)
			}
			// Tampering any proof element must fail.
			for j := range p {
				bad := append([]Hash(nil), p...)
				bad[j][0] ^= 0x01
				if Verify(leaves[i], bad, s.Root()) {
					t.Fatalf("n=%d i=%d: tampered proof element %d accepted", n, i, j)
				}
			}
		}
	}
}

func TestSingleLeaf(t *testing.T) {
	leaves := leavesN(1)
	s, _ := Build(leaves)
	if s.Root() != leaves[0] {
		t.Fatal("single-leaf root must equal the leaf")
	}
	if p, _ := s.Proof(0); len(p) != 0 {
		t.Fatalf("single-leaf proof must be empty, got %d", len(p))
	}
}

func TestEmptyAndOutOfRange(t *testing.T) {
	if _, err := Build(nil); err != ErrEmptyTree {
		t.Fatalf("Build(nil) err = %v", err)
	}
	if _, err := NewTree(0).Root(); err != ErrEmptyTree {
		t.Fatalf("empty Root err = %v", err)
	}
	s, _ := Build(leavesN(3))
	if _, err := s.Proof(3); err == nil {
		t.Fatal("expected out of range error")
	}
	if _, err := s.Proof(-1); err == nil {
		t.Fatal("expected out of range error")
	}
}

func TestParallelMatchesSerial(t *testing.T) {
	n := parallelThreshold*3 + 17
	leaves := leavesN(n)
	s, _ := Build(leaves)
	if s.Root() != refRoot(leaves) {
		t.Fatal("parallel build disagrees with reference")
	}
}

func TestTreeConcurrentAppendAndRead(t *testing.T) {
	tree := NewTree(0)
	const writers, perWriter = 8, 500
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				tree.Append(LeafFromDigest(digestN(w*perWriter + i)))
			}
		}(w)
	}
	// Concurrent readers.
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				s, err := tree.Seal()
				if err != nil {
					continue
				}
				p, _ := s.Proof(0)
				l, _ := s.Leaf(0)
				if !Verify(l, p, s.Root()) {
					t.Error("snapshot proof invalid")
					return
				}
			}
		}()
	}
	wg.Wait()
	if tree.Len() != writers*perWriter {
		t.Fatalf("len = %d", tree.Len())
	}
	s, _ := tree.Seal()
	for i := 0; i < s.Len(); i += 97 {
		p, _ := tree.Proof(i)
		l, _ := s.Leaf(i)
		if !Verify(l, p, s.Root()) {
			t.Fatalf("proof %d invalid", i)
		}
	}
}

func benchmarkBuild(b *testing.B, n int) {
	leaves := leavesN(n)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Build(leaves); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(n)*float64(b.N)/b.Elapsed().Seconds(), "leaves/s")
}

func BenchmarkBuild1K(b *testing.B)   { benchmarkBuild(b, 1_000) }
func BenchmarkBuild100K(b *testing.B) { benchmarkBuild(b, 100_000) }
func BenchmarkBuild1M(b *testing.B)   { benchmarkBuild(b, 1_000_000) }

func BenchmarkAppend(b *testing.B) {
	tree := NewTree(b.N)
	leaf := LeafFromDigest(digestN(1))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tree.Append(leaf)
	}
}

func BenchmarkAppendParallel(b *testing.B) {
	tree := NewTree(0)
	leaf := LeafFromDigest(digestN(1))
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			tree.Append(leaf)
		}
	})
}

func BenchmarkProof(b *testing.B) {
	s, _ := Build(leavesN(100_000))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.Proof(i % 100_000); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkLeavesFromDigests100K(b *testing.B) {
	ds := make([][32]byte, 100_000)
	for i := range ds {
		ds[i] = digestN(i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		LeavesFromDigests(ds)
	}
}
