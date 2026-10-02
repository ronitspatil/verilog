package anchor

import (
	"context"
	"math/big"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient/simulated"
)

// preconfRPC serves preconfirmations as Base's flashblocks endpoint does:
// while zeroHash is set, a mined transaction's receipt has a zero block hash
// (it is not in a sealed block yet); while staleNonce is set the "latest"
// nonce lags one transaction behind, and while stalePending is set so does
// the "pending" nonce.
type preconfRPC struct {
	simulated.Client
	zeroHash     atomic.Bool
	staleNonce   atomic.Bool
	stalePending atomic.Bool
	preconfs     atomic.Int32 // preconfirmation receipts served
}

func (p *preconfRPC) TransactionReceipt(ctx context.Context, h common.Hash) (*types.Receipt, error) {
	r, err := p.Client.TransactionReceipt(ctx, h)
	if err != nil || !p.zeroHash.Load() {
		return r, err
	}
	cp := *r
	cp.BlockHash = common.Hash{}
	p.preconfs.Add(1)
	return &cp, nil
}

func (p *preconfRPC) NonceAt(ctx context.Context, a common.Address, block *big.Int) (uint64, error) {
	n, err := p.Client.NonceAt(ctx, a, block)
	if err == nil && block == nil && p.staleNonce.Load() && n > 0 {
		n--
	}
	return n, err
}

func (p *preconfRPC) PendingNonceAt(ctx context.Context, a common.Address) (uint64, error) {
	n, err := p.Client.PendingNonceAt(ctx, a)
	if err == nil && p.stalePending.Load() && n > 0 {
		n--
	}
	return n, err
}

type anchorOut struct {
	res Result
	err error
}

// anchorAsync starts c.Anchor(req) and mines one block once its transaction
// is in the pool.
func anchorAsync(t *testing.T, env *simEnv, c *EthChain, req Request) <-chan anchorOut {
	t.Helper()
	ch := make(chan anchorOut, 1)
	go func() { r, err := c.Anchor(context.Background(), req); ch <- anchorOut{r, err} }()
	ctx := context.Background()
	waitFor(t, "the anchor transaction in the pool", func() bool {
		pending, _ := env.client.PendingNonceAt(ctx, env.addr)
		mined, _ := env.client.NonceAt(ctx, env.addr, nil)
		return pending > mined
	})
	env.sim.Commit()
	return ch
}

// waitPreconfs waits until the anchorer has read n more preconfirmation
// receipts, checking that Anchor has not returned meanwhile.
func waitPreconfs(t *testing.T, rpc *preconfRPC, n int32, ch <-chan anchorOut) {
	t.Helper()
	want := rpc.preconfs.Load() + n
	deadline := time.Now().Add(10 * time.Second)
	for rpc.preconfs.Load() < want {
		select {
		case o := <-ch:
			t.Fatalf("Anchor returned on a preconfirmation receipt: %+v %v", o.res, o.err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for preconfirmation receipts")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func checkNoReorg(t *testing.T, logs string) {
	t.Helper()
	if strings.Contains(logs, "reorg") || strings.Contains(logs, "level=WARN") {
		t.Fatalf("a preconfirmation was taken for a reorg:\n%s", logs)
	}
	if n := strings.Count(logs, `msg="anchor: transaction sent"`); n != 1 {
		t.Fatalf("%d transactions sent, want 1 (no resend, no replacement):\n%s", n, logs)
	}
}

// A preconfirmation receipt (zero block hash) with a lagging nonce is not a
// mined anchor and not a reorg: the anchorer waits for the sealed block,
// records its hash, never resends or replaces, and the root is anchored once.
func TestPreconfirmationIsNotMinedOrReorged(t *testing.T) {
	key, _ := crypto.GenerateKey()
	env := newSimEnvWith(t, key, false)
	rpc := &preconfRPC{Client: env.client}
	c, logs := newChain(t, env, rpc, Options{Finality: depth(2), PendingFile: filepath.Join(t.TempDir(), PendingFileName)})
	rpc.zeroHash.Store(true)
	rpc.staleNonce.Store(true)

	ch := anchorAsync(t, env, c, testReq)
	waitPreconfs(t, rpc, 2, ch)
	rpc.zeroHash.Store(false) // the block is sealed; the nonce still lags
	o := <-ch
	if o.err != nil {
		t.Fatal(o.err)
	}
	res := o.res
	canon, err := env.client.HeaderByNumber(context.Background(), new(big.Int).SetUint64(res.BlockNumber))
	if err != nil {
		t.Fatal(err)
	}
	if res.BlockHash != canon.Hash().Hex() || res.EpochID != 1 {
		t.Fatalf("result %+v, canonical block hash %s", res, canon.Hash())
	}
	// The lagging nonce says the anchor's nonce is unused: not a reorg.
	for i := 0; i < 3; i++ {
		if st, _ := final(t, c, testReq); st != Pending {
			t.Fatalf("final before depth 2: %v", st)
		}
	}
	rpc.staleNonce.Store(false)
	var st Status
	var got Result
	for i := 0; i < 10 && st != Final; i++ {
		env.sim.Commit()
		st, got = final(t, c, testReq)
	}
	if st != Final || got.BlockHash != res.BlockHash || got.EpochID != 1 {
		t.Fatalf("final %v %+v, mined %+v\n%s", st, got, res, logs)
	}
	checkNoReorg(t, logs.String())
	if latestEpochOf(t, env, testReq.AgentKey) != 1 || nonceOf(t, env) != 2 {
		t.Fatalf("epochs %d nonce %d: want exactly one anchor", latestEpochOf(t, env, testReq.AgentKey), nonceOf(t, env))
	}
}

// While the node's nonce lags a mined anchor, the next anchor still takes
// the next nonce: it never reuses one that may land.
func TestLaggingNonceIsNotReused(t *testing.T) {
	key, _ := crypto.GenerateKey()
	env := newSimEnvWith(t, key, false)
	rpc := &preconfRPC{Client: env.client}
	c, logs := newChain(t, env, rpc, Options{Finality: depth(2)})
	res1 := anchorMined(t, env, c, testReq)
	rpc.staleNonce.Store(true)
	rpc.stalePending.Store(true)
	req2 := Request{AgentKey: testReq.AgentKey, Root: crypto.Keccak256Hash([]byte("root-2")), Count: 1}
	res2 := anchorMined(t, env, c, req2)
	if res1.EpochID != 1 || res2.EpochID != 2 || c.mined[1].tx.Nonce() != 2 {
		t.Fatalf("first %+v, second %+v nonce %d", res1, res2, c.mined[1].tx.Nonce())
	}
	if strings.Contains(logs.String(), "reorg") {
		t.Fatalf("logs:\n%s", logs)
	}
}

// The daemon restarts while its in-flight anchor has only a preconfirmation
// receipt: the restarted anchorer waits for that transaction instead of
// replacing it or anchoring again, and the root is anchored once.
func TestRestartWithPreconfirmedAnchor(t *testing.T) {
	key, _ := crypto.GenerateKey()
	env := newSimEnvWith(t, key, false)
	rpc := &preconfRPC{Client: env.client}
	rpc.zeroHash.Store(true)
	rpc.staleNonce.Store(true)
	file := filepath.Join(t.TempDir(), PendingFileName)
	first, firstLogs := newChain(t, env, rpc, Options{Finality: depth(2), PendingFile: file, ConfirmTimeout: 1500 * time.Millisecond})
	if o := <-anchorAsync(t, env, first, testReq); o.err == nil {
		t.Fatalf("mined on a preconfirmation: %+v", o.res)
	}
	if f := readFile(t, file); f.Pending == nil || len(f.Mined) != 0 {
		t.Fatalf("record %+v: want the in-flight transaction only", f)
	}
	checkNoReorg(t, firstLogs.String())

	// "kill" and restart while the receipt is still a preconfirmation.
	second, logs := newChain(t, env, rpc, Options{Finality: depth(2), PendingFile: file})
	ch := make(chan anchorOut, 1)
	go func() { r, err := second.Anchor(context.Background(), testReq); ch <- anchorOut{r, err} }()
	waitPreconfs(t, rpc, 2, ch)
	rpc.zeroHash.Store(false)
	o := <-ch
	if o.err != nil || o.res.EpochID != 1 {
		t.Fatalf("resumed %+v %v", o.res, o.err)
	}
	if strings.Contains(logs.String(), "transaction sent") || strings.Contains(logs.String(), "reorg") {
		t.Fatalf("the preconfirmed transaction was sent again or taken for a reorg:\n%s", logs)
	}
	rpc.staleNonce.Store(false)
	var st Status
	for i := 0; i < 10 && st != Final; i++ {
		env.sim.Commit()
		st, _ = final(t, second, testReq)
	}
	if st != Final || latestEpochOf(t, env, testReq.AgentKey) != 1 || nonceOf(t, env) != 2 {
		t.Fatalf("final %v, epochs %d, nonce %d: want one anchor", st, latestEpochOf(t, env, testReq.AgentKey), nonceOf(t, env))
	}
}
