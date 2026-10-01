package keys

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ronitspatil/verilog/daemon/internal/canonical"
)

type fakeSource struct {
	keys  map[canonical.Digest]Key
	calls int
	err   error
}

func (f *fakeSource) AgentKey(_ context.Context, _, keyID canonical.Digest) (Key, error) {
	f.calls++
	if f.err != nil {
		return Key{}, f.err
	}
	return f.keys[keyID], nil
}

func TestValidAt(t *testing.T) {
	pub := ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)
	k := Key{Pubkey: pub, ValidFrom: 100}
	for ts, want := range map[uint64]bool{99: false, 100: true, 10_000: true} {
		if k.ValidAt(ts) != want {
			t.Errorf("unrevoked ValidAt(%d) != %v", ts, want)
		}
	}
	k.RevokedAt = 200
	for ts, want := range map[uint64]bool{100: true, 199: true, 200: false, 300: false} {
		if k.ValidAt(ts) != want {
			t.Errorf("revoked ValidAt(%d) != %v", ts, want)
		}
	}
	if (Key{}).ValidAt(150) {
		t.Error("unregistered key valid")
	}
	if !k.RevokedBy(200) || k.RevokedBy(199) || (Key{Pubkey: pub}).RevokedBy(1<<40) {
		t.Error("RevokedBy")
	}
	// A small-order key registered before the contract refused them is never valid (H1).
	weak := make(ed25519.PublicKey, ed25519.PublicKeySize)
	weak[0] = 1 // the identity point
	if (Key{Pubkey: weak, ValidFrom: 1}).ValidAt(150) || (Key{Pubkey: weak}).WellFormed() == nil {
		t.Error("weak key accepted")
	}
}

func TestCache(t *testing.T) {
	pub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	known, unknown, revoked := canonical.Digest{1}, canonical.Digest{2}, canonical.Digest{3}
	src := &fakeSource{keys: map[canonical.Digest]Key{
		known:   {Pubkey: pub, ValidFrom: 1},
		revoked: {Pubkey: pub, ValidFrom: 1, RevokedAt: 5},
	}}
	now := time.Unix(1000, 0)
	c := NewCache(src, time.Minute, 5*time.Second)
	c.now = func() time.Time { return now }
	ctx := context.Background()
	get := func(id canonical.Digest) Key {
		k, err := c.AgentKey(ctx, canonical.Digest{9}, id)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}

	for i := 0; i < 3; i++ {
		get(known)
		get(unknown)
		get(revoked)
	}
	if src.calls != 3 {
		t.Fatalf("calls = %d, want 3 (one per key)", src.calls)
	}
	// An unknown key is re-queried after the negative TTL: a new registration shows up.
	now = now.Add(6 * time.Second)
	src.keys[unknown] = Key{Pubkey: pub, ValidFrom: 2}
	if !get(unknown).Registered() || src.calls != 4 {
		t.Fatalf("unknown key not re-queried (calls %d)", src.calls)
	}
	// A registered key is re-queried after the TTL: a revocation shows up.
	now = now.Add(2 * time.Minute)
	src.keys[known] = Key{Pubkey: pub, ValidFrom: 1, RevokedAt: 9}
	if !get(known).Revoked() {
		t.Fatal("revocation not picked up after TTL")
	}
	// Revoked keys are final.
	before := src.calls
	get(revoked)
	if src.calls != before {
		t.Fatal("revoked key re-queried")
	}
	// Errors are returned and not cached.
	src.err = errors.New("rpc down")
	if _, err := c.AgentKey(ctx, canonical.Digest{9}, canonical.Digest{7}); err == nil {
		t.Fatal("expected error")
	}
}

// countingSource answers every lookup with key (or not registered), counting
// calls; block, if set, holds each call until closed.
type countingSource struct {
	mu    sync.Mutex
	calls int
	known map[canonical.Digest]bool
	block chan struct{}
}

func (s *countingSource) AgentKey(ctx context.Context, _, keyID canonical.Digest) (Key, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	if s.block != nil {
		<-s.block
	}
	if s.known[keyID] {
		return Key{Pubkey: make(ed25519.PublicKey, ed25519.PublicKeySize), ValidFrom: 1}, nil
	}
	return Key{}, nil
}

func (s *countingSource) n() int { s.mu.Lock(); defer s.mu.Unlock(); return s.calls }

func TestCacheSingleflight(t *testing.T) {
	src := &countingSource{known: map[canonical.Digest]bool{{1}: true}, block: make(chan struct{})}
	c := NewCache(src, time.Minute, 5*time.Second)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if k, err := c.AgentKey(context.Background(), canonical.Digest{9}, canonical.Digest{1}); err != nil || !k.Registered() {
				t.Error("lookup failed", err)
			}
		}()
	}
	for src.n() == 0 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond) // let the others pile up on the same flight
	close(src.block)
	wg.Wait()
	if n := src.n(); n != 1 {
		t.Fatalf("concurrent lookups of one key made %d RPCs, want 1", n)
	}
}

func TestCacheEvictsLeastRecentlyUsed(t *testing.T) {
	good := canonical.Digest{1}
	src := &countingSource{known: map[canonical.Digest]bool{good: true}}
	c := NewCache(src, time.Hour, time.Hour)
	c.MaxEntries = 8
	c.NegativeBurst = 1e9 // not under test here
	ctx := context.Background()
	if _, err := c.AgentKey(ctx, canonical.Digest{9}, good); err != nil {
		t.Fatal(err)
	}
	// A flood of junk key ids (other agents) never flushes a key in active use.
	for i := 0; i < 1000; i++ {
		junk := canonical.Digest{0xff, byte(i), byte(i >> 8)}
		c.AgentKey(ctx, canonical.Digest{8, byte(i)}, junk)
		if i%4 == 0 {
			before := src.n()
			c.AgentKey(ctx, canonical.Digest{9}, good)
			if src.n() != before {
				t.Fatalf("good key evicted after %d junk lookups", i)
			}
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries.len() > 8 {
		t.Fatalf("cache holds %d entries, cap 8", c.entries.len())
	}
}

func TestCacheRateLimitsNegativeLookupsPerAgent(t *testing.T) {
	good := canonical.Digest{1}
	src := &countingSource{known: map[canonical.Digest]bool{good: true}}
	now := time.Unix(1000, 0)
	c := NewCache(src, time.Minute, 5*time.Second)
	c.now = func() time.Time { return now }
	c.NegativeRate, c.NegativeBurst = 1, 5
	ctx := context.Background()
	flooder, other := canonical.Digest{7}, canonical.Digest{8}
	for i := 0; i < 100; i++ {
		if k, err := c.AgentKey(ctx, flooder, canonical.Digest{0xee, byte(i)}); err != nil || k.Registered() {
			t.Fatal(k, err)
		}
	}
	if n := src.n(); n != 5 {
		t.Fatalf("100 junk lookups made %d RPCs, want the burst of 5", n)
	}
	// Other agents are unaffected, and so are cached keys of the flooder.
	if k, _ := c.AgentKey(ctx, other, canonical.Digest{0xee, 1}); k.Registered() || src.n() != 6 {
		t.Fatalf("other agent limited (calls %d)", src.n())
	}
	// The budget refills over time.
	now = now.Add(2 * time.Second)
	c.AgentKey(ctx, flooder, canonical.Digest{0xdd, 1})
	c.AgentKey(ctx, flooder, canonical.Digest{0xdd, 2})
	c.AgentKey(ctx, flooder, canonical.Digest{0xdd, 3})
	if n := src.n(); n != 8 {
		t.Fatalf("after refill: %d RPCs, want 8", n)
	}
	// A registered key of the flooder is still found once its budget refills.
	now = now.Add(10 * time.Second)
	if k, _ := c.AgentKey(ctx, flooder, good); !k.Registered() {
		t.Fatal("registered key not found after refill")
	}
}
