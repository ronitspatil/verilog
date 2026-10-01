package keys

import (
	"context"
	"crypto/ed25519"
	"errors"
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
	pub := make(ed25519.PublicKey, ed25519.PublicKeySize)
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
