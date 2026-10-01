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
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"golang.org/x/sync/singleflight"

	"github.com/ronitspatil/verilog/daemon/internal/canonical"
	"github.com/ronitspatil/verilog/daemon/internal/registry"
)

// Key is an agent key as recorded on chain. The zero Key means "not registered".
type Key struct {
	Pubkey    ed25519.PublicKey
	ValidFrom uint64 // block timestamp of registration
	// RevokedAt is the time the revocation takes effect (the effectiveAt
	// argument of revokeAgentKey, never earlier than the revoking block);
	// 0 if not revoked. A revocation can be scheduled ahead of time.
	RevokedAt uint64
}

// Registered reports whether the key exists on chain.
func (k Key) Registered() bool { return len(k.Pubkey) == ed25519.PublicKeySize }

// Revoked reports whether a revocation has been recorded, whether or not it
// is in effect yet.
func (k Key) Revoked() bool { return k.RevokedAt != 0 }

// RevokedBy reports whether the revocation is in effect at time ts.
func (k Key) RevokedBy(ts uint64) bool { return k.RevokedAt != 0 && ts >= k.RevokedAt }

// WellFormed reports why the registered public key is unsafe to verify with
// (small or mixed order, non-canonical, not on the curve), or nil. The
// contract refuses such keys, but keys registered before that check existed
// are rejected here too.
func (k Key) WellFormed() error { return canonical.CheckPublicKey(k.Pubkey) }

// ValidAt applies the validity rule to a trusted anchor timestamp:
// a well-formed key with validFrom <= ts && (revokedAt == 0 || ts < revokedAt).
func (k Key) ValidAt(ts uint64) bool {
	return k.Registered() && k.WellFormed() == nil && k.ValidFrom <= ts && !k.RevokedBy(ts)
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
	return c.agentKeyAt(ctx, nil, agentKey, keyID)
}

// At returns a Source that reads the keys as of block (nil: the head). The
// verifier pins it to the final block.
func (c *ChainSource) At(block *big.Int) Source { return pinnedSource{c: c, block: block} }

type pinnedSource struct {
	c     *ChainSource
	block *big.Int
}

func (p pinnedSource) AgentKey(ctx context.Context, agentKey, keyID canonical.Digest) (Key, error) {
	return p.c.agentKeyAt(ctx, p.block, agentKey, keyID)
}

func (c *ChainSource) agentKeyAt(ctx context.Context, block *big.Int, agentKey, keyID canonical.Digest) (Key, error) {
	out, err := c.reg.AgentKeys(&bind.CallOpts{Context: ctx, BlockNumber: block}, agentKey, keyID)
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
// unknown key does not turn into a flood of RPC calls); revoked keys are final
// (revokedAt cannot change once set).
//
// The cache is a bounded LRU, so lookups of junk key ids evict only the least
// recently used entries, never the whole cache. Concurrent lookups of the same
// (agent, key_id) share one RPC. Lookups that find no key are rate-limited per
// agent: beyond NegativeBurst, further uncached lookups of that agent are
// answered "not registered" (which the daemon rejects as retryable) without an
// RPC until the agent's budget refills at NegativeRate per second.
type Cache struct {
	src         Source
	ttl         time.Duration
	negativeTTL time.Duration
	now         func() time.Time

	// MaxEntries bounds the cached keys; NegativeRate and NegativeBurst bound
	// lookups per agent that find no key. Set before first use.
	MaxEntries    int
	NegativeRate  float64
	NegativeBurst float64

	flight singleflight.Group

	mu      sync.Mutex
	entries *lru[[64]byte, cacheEntry]
	budgets *lru[canonical.Digest, *bucket]
}

type cacheEntry struct {
	key     Key
	expires time.Time // zero: never
}

// Defaults for Cache limits.
const (
	DefaultMaxEntries    = 1 << 16
	DefaultNegativeRate  = 1.0 // per second, per agent
	DefaultNegativeBurst = 20
	maxBudgets           = 1 << 14
)

// NewCache wraps src. ttl applies to registered keys, negativeTTL to unknown ones.
func NewCache(src Source, ttl, negativeTTL time.Duration) *Cache {
	return &Cache{
		src: src, ttl: ttl, negativeTTL: negativeTTL, now: time.Now,
		MaxEntries: DefaultMaxEntries, NegativeRate: DefaultNegativeRate, NegativeBurst: DefaultNegativeBurst,
	}
}

// AgentKey implements Source.
func (c *Cache) AgentKey(ctx context.Context, agentKey, keyID canonical.Digest) (Key, error) {
	var id [64]byte
	copy(id[:32], agentKey[:])
	copy(id[32:], keyID[:])
	now := c.now()
	c.mu.Lock()
	c.init()
	e, ok := c.entries.get(id)
	if ok && (e.expires.IsZero() || now.Before(e.expires)) {
		c.mu.Unlock()
		return e.key, nil
	}
	limited := !c.budget(agentKey, now).available(now)
	c.mu.Unlock()
	if limited {
		// This agent keeps asking for keys that do not exist: answer
		// "not registered" without an RPC until its budget refills.
		return Key{}, nil
	}

	v, err, _ := c.flight.Do(string(id[:]), func() (any, error) {
		// The caller's context must not cancel the lookup shared by others.
		lctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		return c.src.AgentKey(lctx, agentKey, keyID)
	})
	if err != nil {
		return Key{}, err
	}
	k := v.(Key)
	e = cacheEntry{key: k}
	switch {
	case !k.Registered():
		e.expires = now.Add(c.negativeTTL)
	case !k.Revoked():
		e.expires = now.Add(c.ttl)
	}
	c.mu.Lock()
	if !k.Registered() {
		c.budget(agentKey, now).take(now)
	}
	c.entries.put(id, e)
	c.mu.Unlock()
	return k, nil
}

// init sets up the LRUs (caller holds mu).
func (c *Cache) init() {
	if c.entries == nil {
		c.entries = newLRU[[64]byte, cacheEntry](max(c.MaxEntries, 1))
		c.budgets = newLRU[canonical.Digest, *bucket](maxBudgets)
	}
}

// budget returns the agent's negative-lookup bucket (caller holds mu).
func (c *Cache) budget(agentKey canonical.Digest, now time.Time) *bucket {
	b, ok := c.budgets.get(agentKey)
	if !ok {
		b = &bucket{rate: c.NegativeRate, burst: c.NegativeBurst, tokens: c.NegativeBurst, last: now}
		c.budgets.put(agentKey, b)
	}
	return b
}

// bucket is a token bucket.
type bucket struct {
	rate, burst, tokens float64
	last                time.Time
}

func (b *bucket) refill(now time.Time) {
	if dt := now.Sub(b.last).Seconds(); dt > 0 {
		b.tokens = min(b.burst, b.tokens+dt*b.rate)
	}
	b.last = now
}

func (b *bucket) available(now time.Time) bool { b.refill(now); return b.tokens >= 1 }

func (b *bucket) take(now time.Time) { b.refill(now); b.tokens = max(0, b.tokens-1) }

// RevocationCheck answers engine.KeyChecker from a Source (it should be
// uncached, so a revocation is seen as soon as it is on chain) and a clock.
type RevocationCheck struct {
	Src Source
	// Now returns the current time in Unix seconds; the chain's latest block
	// timestamp is a good choice, since that is what the anchor will carry.
	Now func(ctx context.Context) (uint64, error)
}

// RevokedNow implements engine.KeyChecker.
func (r RevocationCheck) RevokedNow(ctx context.Context, agentKey, keyID canonical.Digest) (bool, error) {
	k, err := r.Src.AgentKey(ctx, agentKey, keyID)
	if err != nil || !k.Revoked() {
		return false, err
	}
	now, err := r.Now(ctx)
	if err != nil {
		return false, err
	}
	return k.RevokedBy(now), nil
}
