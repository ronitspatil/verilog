// Package keys looks up agent signing keys in the on-chain VeriLogRegistry.
//
// The registry is the only trust anchor for agent keys: keys are registered
// and revoked by KEY_ADMIN_ROLE, which the daemon (the anchorer) never holds.
// The daemon uses a Cache to reject badly signed events early; the verifier
// reads the chain directly and decides validity against anchor time.
package keys

import (
	"context"
	"crypto/ed25519"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"

	"github.com/ronitspatil/verilog/daemon/internal/canonical"
	"github.com/ronitspatil/verilog/daemon/internal/registry"
)

// Key is an agent key as recorded on chain. The zero Key means "not registered".
type Key struct {
	Pubkey    ed25519.PublicKey
	ValidFrom uint64 // block timestamp of registration
	RevokedAt uint64 // block timestamp of revocation; 0 if not revoked
}

// Registered reports whether the key exists on chain.
func (k Key) Registered() bool { return len(k.Pubkey) == ed25519.PublicKeySize }

// Revoked reports whether the key has been revoked (at any time).
func (k Key) Revoked() bool { return k.RevokedAt != 0 }

// ValidAt applies the validity rule to a trusted anchor timestamp:
// validFrom <= ts && (revokedAt == 0 || ts < revokedAt).
func (k Key) ValidAt(ts uint64) bool {
	return k.Registered() && k.ValidFrom <= ts && (k.RevokedAt == 0 || ts < k.RevokedAt)
}

// Source returns the on-chain key of (agentKey, keyID); the zero Key when it
// is not registered. An error means the lookup itself failed.
type Source interface {
	AgentKey(ctx context.Context, agentKey, keyID canonical.Digest) (Key, error)
}

// ChainSource reads VeriLogRegistry.agentKeys over RPC.
type ChainSource struct {
	reg *registry.VeriLogRegistryCaller
}

// NewChainSource binds the registry at addr.
func NewChainSource(addr common.Address, backend bind.ContractCaller) (*ChainSource, error) {
	reg, err := registry.NewVeriLogRegistryCaller(addr, backend)
	if err != nil {
		return nil, err
	}
	return &ChainSource{reg: reg}, nil
}

// AgentKey implements Source.
func (c *ChainSource) AgentKey(ctx context.Context, agentKey, keyID canonical.Digest) (Key, error) {
	out, err := c.reg.AgentKeys(&bind.CallOpts{Context: ctx}, agentKey, keyID)
	if err != nil {
		return Key{}, err
	}
	if out.Pubkey == ([32]byte{}) {
		return Key{}, nil
	}
	return Key{Pubkey: ed25519.PublicKey(out.Pubkey[:]), ValidFrom: out.ValidFrom, RevokedAt: out.RevokedAt}, nil
}

// Cache memoizes a Source. Registered, unrevoked keys are kept for TTL so a
// later revocation is picked up; unknown keys are re-queried after NegativeTTL
// (a new registration is seen quickly, while a flood of events signed with an
// unknown key does not turn into a flood of RPC calls); revoked keys are final.
type Cache struct {
	src         Source
	ttl         time.Duration
	negativeTTL time.Duration
	now         func() time.Time

	mu      sync.Mutex
	entries map[[64]byte]cacheEntry
}

type cacheEntry struct {
	key     Key
	expires time.Time // zero: never
}

// maxEntries bounds the cache; it is cleared when full.
const maxEntries = 1 << 16

// NewCache wraps src. ttl applies to registered keys, negativeTTL to unknown ones.
func NewCache(src Source, ttl, negativeTTL time.Duration) *Cache {
	return &Cache{src: src, ttl: ttl, negativeTTL: negativeTTL, now: time.Now, entries: map[[64]byte]cacheEntry{}}
}

// AgentKey implements Source.
func (c *Cache) AgentKey(ctx context.Context, agentKey, keyID canonical.Digest) (Key, error) {
	var id [64]byte
	copy(id[:32], agentKey[:])
	copy(id[32:], keyID[:])
	now := c.now()
	c.mu.Lock()
	e, ok := c.entries[id]
	c.mu.Unlock()
	if ok && (e.expires.IsZero() || now.Before(e.expires)) {
		return e.key, nil
	}
	k, err := c.src.AgentKey(ctx, agentKey, keyID)
	if err != nil {
		return Key{}, err
	}
	e = cacheEntry{key: k}
	switch {
	case !k.Registered():
		e.expires = now.Add(c.negativeTTL)
	case !k.Revoked():
		e.expires = now.Add(c.ttl)
	}
	c.mu.Lock()
	if len(c.entries) >= maxEntries {
		clear(c.entries)
	}
	c.entries[id] = e
	c.mu.Unlock()
	return k, nil
}
