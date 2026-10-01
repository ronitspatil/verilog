package anchor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient/simulated"

	"github.com/ronitspatil/verilog/daemon/internal/finality"
	"github.com/ronitspatil/verilog/daemon/internal/signer"
)

// ------------------------------------------------------------ worker stages

// finalityChain is a fake Chain whose anchors become final after a number
// of finality checks, or must be anchored again.
type finalityChain struct {
	mu       sync.Mutex
	epoch    uint64
	anchors  []Request          // Anchor calls, in order
	results  map[Request]Result // mined anchors
	pending  map[Request]int    // finality checks left before Final
	reanchor map[Request]int    // Reanchor answers left
	done     []Request          // order of completion (via Release)
}

func newFinalityChain() *finalityChain {
	return &finalityChain{results: map[Request]Result{}, pending: map[Request]int{}, reanchor: map[Request]int{}}
}

func (f *finalityChain) Anchor(_ context.Context, req Request) (Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.anchors = append(f.anchors, req)
	f.epoch++
	f.results[req] = Result{EpochID: f.epoch, TxHash: "0x01"}
	return f.results[req], nil
}

func (f *finalityChain) Final(_ context.Context, req Request) (Status, Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.reanchor[req] > 0 {
		f.reanchor[req]--
		delete(f.results, req)
		return Reanchor, Result{}, nil
	}
	if f.pending[req] > 0 {
		f.pending[req]--
		return Pending, f.results[req], nil
	}
	res := f.results[req]
	res.Finality = "depth:1"
	return Final, res, nil
}

func (f *finalityChain) Release(req Request) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.done = append(f.done, req)
	return nil
}

func (f *finalityChain) snapshot() (anchors, done []Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Request(nil), f.anchors...), append([]Request(nil), f.done...)
}

func runWorker(t *testing.T, w *Worker) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() { defer close(stopped); w.Run(ctx) }()
	return func() { cancel(); <-stopped }
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// Later epochs are sent while an earlier one awaits finality, but jobs
// complete only once final, and in queue order.
func TestWorkerPipelinesAndCompletesInOrder(t *testing.T) {
	chain := newFinalityChain()
	reqs := []Request{{Root: [32]byte{1}}, {Root: [32]byte{2}}, {Root: [32]byte{3}}}
	chain.pending[reqs[0]] = 5
	var mu sync.Mutex
	var finished []uint64
	var results []Result
	w := NewWorker(chain, WorkerOptions{FinalityPoll: 5 * time.Millisecond}, nil)
	for _, r := range reqs {
		w.Enqueue(Job{Request: r, Label: "x", Done: func(_ context.Context, res Result) error {
			mu.Lock()
			defer mu.Unlock()
			finished = append(finished, res.EpochID)
			results = append(results, res)
			return nil
		}})
	}
	stop := runWorker(t, w)
	defer stop()
	waitFor(t, "all anchors sent", func() bool { a, _ := chain.snapshot(); return len(a) == 3 })
	mu.Lock()
	if len(finished) != 0 {
		t.Fatalf("a job completed before the first anchor was final: %v", finished)
	}
	mu.Unlock()
	waitFor(t, "completion", func() bool { mu.Lock(); defer mu.Unlock(); return len(finished) == 3 })
	mu.Lock()
	defer mu.Unlock()
	if finished[0] != 1 || finished[1] != 2 || finished[2] != 3 || results[0].Finality != "depth:1" {
		t.Fatalf("completed %v %+v", finished, results)
	}
	if _, done := chain.snapshot(); len(done) != 3 || done[0] != reqs[0] {
		t.Fatalf("released %v", done)
	}
	if w.Pending() != 0 {
		t.Fatalf("pending %d", w.Pending())
	}
}

// An anchor that is gone (Reanchor) is anchored again before its job
// completes; later jobs still complete after it.
func TestWorkerReanchors(t *testing.T) {
	chain := newFinalityChain()
	a, b := Request{Root: [32]byte{1}}, Request{Root: [32]byte{2}}
	chain.reanchor[a] = 1
	var mu sync.Mutex
	var order []Request
	w := NewWorker(chain, WorkerOptions{FinalityPoll: 2 * time.Millisecond}, nil)
	for _, r := range []Request{a, b} {
		w.Enqueue(Job{Request: r, Done: func(context.Context, Result) error {
			mu.Lock()
			defer mu.Unlock()
			order = append(order, r)
			return nil
		}})
	}
	stop := runWorker(t, w)
	defer stop()
	waitFor(t, "completion", func() bool { mu.Lock(); defer mu.Unlock(); return len(order) == 2 })
	anchors, _ := chain.snapshot()
	if n := len(anchors); n != 3 || anchors[0] != a || (anchors[1] != a && anchors[2] != a) {
		t.Fatalf("anchor calls %v: want a twice and b once", anchors)
	}
	mu.Lock()
	defer mu.Unlock()
	if order[0] != a || order[1] != b {
		t.Fatalf("completion order %v", order)
	}
}

// An anchor that never becomes final is logged at ERROR and kept.
func TestWorkerFinalityTimeoutLogsAndKeeps(t *testing.T) {
	chain := newFinalityChain()
	req := Request{Root: [32]byte{9}}
	chain.pending[req] = 1 << 30
	logs := &syncBuffer{}
	w := NewWorker(chain, WorkerOptions{FinalityPoll: 2 * time.Millisecond, FinalityTimeout: 30 * time.Millisecond},
		slog.New(slog.NewTextHandler(logs, nil)))
	w.Enqueue(Job{Request: req, Label: "agent[seq 1-1]", Done: func(context.Context, Result) error {
		t.Error("completed an anchor that is not final")
		return nil
	}})
	stop := runWorker(t, w)
	waitFor(t, "two timeout errors", func() bool {
		return strings.Count(logs.String(), `level=ERROR msg="anchor: epoch not final yet`) >= 2
	})
	stop()
	if w.Pending() != 1 {
		t.Fatalf("pending %d: the job must never be dropped", w.Pending())
	}
}

// ------------------------------------------------------------ simulated chain

func depth(n uint64) finality.Mode { return finality.Mode{Kind: finality.Depth, Depth: n} }

func newChain(t *testing.T, env *simEnv, backend Backend, opts Options) (*EthChain, *syncBuffer) {
	t.Helper()
	logs := &syncBuffer{}
	if backend == nil {
		backend = env.client
	}
	if opts.ConfirmTimeout == 0 {
		opts.ConfirmTimeout = 30 * time.Second
	}
	c, err := NewEthChain(context.Background(), backend, env.contract, signer.NewLocal(env.key), opts,
		slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	if err != nil {
		t.Fatal(err)
	}
	return c, logs
}

// anchorMined anchors req on a chain without automatic mining, committing
// a block whenever a transaction waits, until the anchor is mined.
func anchorMined(t *testing.T, env *simEnv, c *EthChain, req Request) Result {
	t.Helper()
	type out struct {
		res Result
		err error
	}
	ch := make(chan out, 1)
	go func() { r, err := c.Anchor(context.Background(), req); ch <- out{r, err} }()
	for {
		select {
		case o := <-ch:
			if o.err != nil {
				t.Fatal(o.err)
			}
			return o.res
		case <-time.After(20 * time.Millisecond):
			// Mine only while a transaction waits, so the head stays close
			// to the anchor's block.
			ctx := context.Background()
			pending, _ := env.client.PendingNonceAt(ctx, env.addr)
			if mined, _ := env.client.NonceAt(ctx, env.addr, nil); pending > mined {
				env.sim.Commit()
			}
		}
	}
}

func head(t *testing.T, env *simEnv) *types.Header {
	t.Helper()
	h, err := env.client.HeaderByNumber(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func final(t *testing.T, c *EthChain, req Request) (Status, Result) {
	t.Helper()
	st, res, err := c.Final(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	return st, res
}

// reorgOut makes the parent of block n the head (the block holding the
// anchor leaves the canonical chain) and drops the transactions the reorg
// returned to the pool, as a node that does not re-inject them would.
func reorgOut(t *testing.T, env *simEnv, n uint64) common.Hash {
	t.Helper()
	blk, err := env.client.HeaderByNumber(context.Background(), new(big.Int).SetUint64(n))
	if err != nil {
		t.Fatal(err)
	}
	if err := env.sim.Fork(blk.ParentHash); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond) // let the pool re-inject, then drop them
	env.sim.Rollback()
	// The pool handles the new head asynchronously and, on a slow machine,
	// after the rollback: it then still has the old head's nonce, or re-injects
	// the dropped transaction. Drop again until it matches the chain.
	ctx := context.Background()
	for deadline := time.Now().Add(10 * time.Second); ; {
		pending, _ := env.client.PendingNonceAt(ctx, env.addr)
		if mined, _ := env.client.NonceAt(ctx, env.addr, nil); pending == mined {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the pool did not settle after the reorg")
		}
		time.Sleep(50 * time.Millisecond)
		env.sim.Rollback()
	}
	return blk.Hash()
}

func latestEpochOf(t *testing.T, env *simEnv, agent [32]byte) uint64 {
	t.Helper()
	n, err := env.reg.LatestEpoch(&bind.CallOpts{}, agent)
	if err != nil {
		t.Fatal(err)
	}
	return n.Uint64()
}

func nonceOf(t *testing.T, env *simEnv) uint64 {
	t.Helper()
	n, err := env.client.NonceAt(context.Background(), env.addr, nil)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// An anchor is final once depth blocks are built on it; it is then re-read
// at the final block.
func TestFinalWaitsForDepth(t *testing.T) {
	key, _ := crypto.GenerateKey()
	env := newSimEnvWith(t, key, false)
	file := filepath.Join(t.TempDir(), PendingFileName)
	c, _ := newChain(t, env, nil, Options{Finality: depth(3), PendingFile: file})
	res := anchorMined(t, env, c, testReq)
	if res.BlockHash == "" || res.EpochID != 1 {
		t.Fatalf("mined result %+v", res)
	}
	for head(t, env).Number.Uint64() < res.BlockNumber+3 {
		if st, _ := final(t, c, testReq); st != Pending {
			t.Fatalf("final at head %d, block %d: want pending until depth 3", head(t, env).Number, res.BlockNumber)
		}
		env.sim.Commit()
	}
	st, got := final(t, c, testReq)
	if st != Final || got.Finality != "depth:3" || got.FinalBlockNumber < res.BlockNumber || got.FinalBlockHash == "" ||
		got.BlockHash != res.BlockHash || got.EpochID != 1 {
		t.Fatalf("final %v %+v", st, got)
	}
	if f := readFile(t, file); len(f.Mined) != 1 || f.Mined[0].BlockHash != common.HexToHash(res.BlockHash) {
		t.Fatalf("record %+v: the mined anchor must stay recorded until released", f)
	}
	if err := c.Release(testReq); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("record not removed after release")
	}
}

// The simulated beacon finalizes at 32-block boundaries; the "finalized"
// tag (the default) waits for it.
func TestFinalUsesFinalizedTag(t *testing.T) {
	key, _ := crypto.GenerateKey()
	env := newSimEnvWith(t, key, false)
	c, _ := newChain(t, env, nil, Options{})
	if _, err := c.opts.Finality.Check(context.Background(), env.client); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 40; i++ { // the first 32 blocks are final at once
		env.sim.Commit()
	}
	res := anchorMined(t, env, c, testReq)
	if st, _ := final(t, c, testReq); st != Pending {
		t.Fatalf("final right after mining: %v", st)
	}
	for i := 0; i < 70; i++ {
		env.sim.Commit()
	}
	st, got := final(t, c, testReq)
	if st != Final || got.Finality != "finalized" || got.FinalBlockNumber < res.BlockNumber || got.FinalBlockNumber%32 != 0 {
		t.Fatalf("final %v %+v", st, got)
	}
}

// A reorg removes the block holding the anchor and the node drops the
// transaction: the anchorer logs it at WARN with the block hashes, sends the
// same transaction again and confirms it once final. The root is anchored
// once.
func TestReorgRemovesAnchorAndItIsSentAgain(t *testing.T) {
	key, _ := crypto.GenerateKey()
	env := newSimEnvWith(t, key, false)
	c, logs := newChain(t, env, nil, Options{Finality: depth(2), PendingFile: filepath.Join(t.TempDir(), PendingFileName)})
	res := anchorMined(t, env, c, testReq)
	env.sim.Commit()
	old := reorgOut(t, env, res.BlockNumber)
	if old.Hex() != res.BlockHash {
		t.Fatalf("block hash %s, result %s", old, res.BlockHash)
	}
	if latestEpochOf(t, env, testReq.AgentKey) != 0 {
		t.Fatal("the reorg did not remove the anchor")
	}
	if st, _ := final(t, c, testReq); st != Pending {
		t.Fatalf("final after the reorg: %v", st)
	}
	out := logs.String()
	if !strings.Contains(out, `level=WARN msg="anchor: reorg removed the anchor transaction; sending it again"`) ||
		!strings.Contains(out, "block_hash="+res.BlockHash) || !strings.Contains(out, "canonical_block_hash=") {
		t.Fatalf("logs:\n%s", out)
	}
	var got Result
	for i := 0; i < 10; i++ {
		env.sim.Commit()
		var st Status
		if st, got = final(t, c, testReq); st == Final {
			break
		}
	}
	if got.Finality != "depth:2" || got.EpochID != 1 {
		t.Fatalf("not final after the anchor was re-mined: %+v\n%s", got, logs)
	}
	canon, _ := env.client.HeaderByNumber(context.Background(), new(big.Int).SetUint64(got.BlockNumber))
	if canon.Hash().Hex() != got.BlockHash {
		t.Fatalf("final block hash %s is not canonical (%s)", got.BlockHash, canon.Hash())
	}
	if latestEpochOf(t, env, testReq.AgentKey) != 1 || nonceOf(t, env) != 2 {
		t.Fatalf("epochs %d nonce %d: the root must be anchored once, by the same transaction",
			latestEpochOf(t, env, testReq.AgentKey), nonceOf(t, env))
	}
}

// While an earlier anchor is reorged out, the next request never takes its
// nonce: once the earlier one is sent again, both land in order.
func TestReorgKeepsNonceOrderWhilePipelining(t *testing.T) {
	key, _ := crypto.GenerateKey()
	env := newSimEnvWith(t, key, false)
	file := filepath.Join(t.TempDir(), PendingFileName)
	c, logs := newChain(t, env, nil, Options{Finality: depth(2), PendingFile: file})
	t.Cleanup(func() {
		if t.Failed() {
			t.Log(logs)
		}
	})
	req2 := Request{AgentKey: testReq.AgentKey, Root: crypto.Keccak256Hash([]byte("root-2")), Count: 1}
	res1 := anchorMined(t, env, c, testReq)
	reorgOut(t, env, res1.BlockNumber)

	// The next epoch is sent while the first is gone: it must take nonce 2.
	c.opts.ConfirmTimeout = 1500 * time.Millisecond
	if _, err := c.Anchor(context.Background(), req2); err == nil {
		t.Fatal("the second anchor was mined before the first was sent again")
	}
	if rec := readRecord(t, file); rec.Nonce != 2 {
		t.Fatalf("second anchor nonce %d, want 2 (nonce 1 belongs to the reorged-out first anchor)", rec.Nonce)
	}
	if st, _ := final(t, c, testReq); st != Pending { // resends the first anchor
		t.Fatalf("%v", st)
	}
	// Wait until the pool holds the resent first anchor before mining.
	first := c.mined[0].tx.Hash()
	for deadline := time.Now().Add(10 * time.Second); ; {
		if _, isPending, err := env.client.TransactionByHash(context.Background(), first); err == nil && isPending {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the first anchor was not sent again")
		}
		time.Sleep(50 * time.Millisecond)
		final(t, c, testReq)
	}
	c.opts.ConfirmTimeout = 30 * time.Second
	res2 := anchorMined(t, env, c, req2)
	env.sim.Commit()
	env.sim.Commit()
	st, got1 := final(t, c, testReq)
	if st != Final || got1.EpochID != 1 || res2.EpochID != 2 {
		t.Fatalf("first %v %+v, second %+v: epochs must keep their order", st, got1, res2)
	}
}

// The daemon crashes between mined and final, and a reorg removes the
// anchor while it is down: the restarted anchorer resumes the recorded
// anchor without sending a new transaction, finds it reorged out, sends it
// again and confirms finality.
func TestRestartBetweenMinedAndFinal(t *testing.T) {
	key, _ := crypto.GenerateKey()
	env := newSimEnvWith(t, key, false)
	file := filepath.Join(t.TempDir(), PendingFileName)
	first, _ := newChain(t, env, nil, Options{Finality: depth(2), PendingFile: file})
	res := anchorMined(t, env, first, testReq)
	if f := readFile(t, file); f.Pending != nil || len(f.Mined) != 1 || f.Mined[0].EpochID != 1 || len(f.Mined[0].RawTx) == 0 {
		t.Fatalf("record after mining: %+v", f)
	}
	// "kill": first is never used again. A reorg while the daemon is down.
	reorgOut(t, env, res.BlockNumber)

	second, logs := newChain(t, env, nil, Options{Finality: depth(2), PendingFile: file})
	if !strings.Contains(logs.String(), "anchor: resuming an anchor awaiting finality") {
		t.Fatalf("logs:\n%s", logs)
	}
	got, err := second.Anchor(context.Background(), testReq)
	if err != nil || got != res {
		t.Fatalf("resumed %+v %v, want the recorded %+v", got, err, res)
	}
	if strings.Contains(logs.String(), "transaction sent") {
		t.Fatal("a recorded anchor was sent again as a new transaction")
	}
	var st Status
	for i := 0; i < 10 && st != Final; i++ {
		st, got = final(t, second, testReq)
		env.sim.Commit()
	}
	if st != Final || !strings.Contains(logs.String(), "reorg removed the anchor transaction") {
		t.Fatalf("%v %+v\n%s", st, got, logs)
	}
	if latestEpochOf(t, env, testReq.AgentKey) != 1 || nonceOf(t, env) != 2 {
		t.Fatal("the root was anchored more than once")
	}
	if err := second.Release(testReq); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("record not removed after release")
	}
}

// After a crash between the job's completion and Release, the restarted
// worker forgets the anchor of the completed job (it is no longer queued).
func TestRetainForgetsCompletedAnchors(t *testing.T) {
	key, _ := crypto.GenerateKey()
	env := newSimEnvWith(t, key, false)
	file := filepath.Join(t.TempDir(), PendingFileName)
	c, _ := newChain(t, env, nil, Options{Finality: depth(2), PendingFile: file})
	anchorMined(t, env, c, testReq)
	if err := c.Retain([]Request{testReq}); err != nil || len(c.mined) != 1 {
		t.Fatalf("retained %d %v", len(c.mined), err)
	}
	if err := c.Retain(nil); err != nil || len(c.mined) != 0 {
		t.Fatalf("retained %d %v", len(c.mined), err)
	}
	if _, err := os.Stat(file); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("record not removed")
	}
}

// lyingCalls answers every contract call with zeros while lie is set, as
// an RPC endpoint serving stale or forged state would.
type lyingCalls struct {
	simulated.Client
	lie atomic.Bool
}

func (l *lyingCalls) CallContract(ctx context.Context, msg ethereum.CallMsg, block *big.Int) ([]byte, error) {
	if l.lie.Load() {
		return make([]byte, 96), nil
	}
	return l.Client.CallContract(ctx, msg, block)
}

// The anchor read at the final block does not match the receipt: nothing is
// confirmed, the epoch is anchored again, and the new anchor is confirmed.
func TestFinalMismatchOnReReadReanchors(t *testing.T) {
	key, _ := crypto.GenerateKey()
	env := newSimEnvWith(t, key, false)
	lying := &lyingCalls{Client: env.client}
	c, logs := newChain(t, env, lying, Options{Finality: depth(2)})
	res := anchorMined(t, env, c, testReq)
	env.sim.Commit()
	env.sim.Commit()
	lying.lie.Store(true)
	if st, _ := final(t, c, testReq); st != Reanchor {
		t.Fatalf("final with a mismatching re-read: %v", st)
	}
	if !strings.Contains(logs.String(), `level=ERROR msg="anchor: the anchor read at the final block does not match the receipt; anchoring the epoch again"`) {
		t.Fatalf("logs:\n%s", logs)
	}
	res2 := anchorMined(t, env, c, testReq)
	if res2.EpochID != 2 || res2.TxHash == res.TxHash {
		t.Fatalf("re-anchor %+v", res2)
	}
	lying.lie.Store(false)
	env.sim.Commit()
	env.sim.Commit()
	if st, got := final(t, c, testReq); st != Final || got.EpochID != 2 {
		t.Fatalf("final %v %+v", st, got)
	}
}

// The anchor's nonce ends up used by another transaction of the anchoring
// key in a final block: the epoch is anchored again with a new nonce.
func TestNonceUsedByAnotherTransactionReanchors(t *testing.T) {
	key, _ := crypto.GenerateKey()
	env := newSimEnvWith(t, key, false)
	c, logs := newChain(t, env, nil, Options{Finality: depth(2)})
	res := anchorMined(t, env, c, testReq)
	reorgOut(t, env, res.BlockNumber)

	ctx := context.Background()
	h := head(t, env)
	chainID, _ := env.client.ChainID(ctx)
	other := types.MustSignNewTx(key, types.LatestSignerForChainID(chainID), &types.DynamicFeeTx{
		ChainID: chainID, Nonce: 1, GasTipCap: big.NewInt(2e9),
		GasFeeCap: new(big.Int).Add(new(big.Int).Mul(h.BaseFee, big.NewInt(4)), big.NewInt(2e9)),
		Gas:       21000, To: &common.Address{1}, Value: big.NewInt(1),
	})
	if err := env.client.SendTransaction(ctx, other); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		env.sim.Commit()
	}
	if st, _ := final(t, c, testReq); st != Reanchor {
		t.Fatalf("final with the nonce taken: %v\n%s", st, logs)
	}
	if !strings.Contains(logs.String(), "the anchor's nonce was used by another transaction in a final block") {
		t.Fatalf("logs:\n%s", logs)
	}
	res2 := anchorMined(t, env, c, testReq)
	if res2.EpochID != 1 || latestEpochOf(t, env, testReq.AgentKey) != 1 {
		t.Fatalf("re-anchor %+v", res2)
	}
}

// A version 1 record (the in-flight transaction only) is still read.
func TestPendingRecordVersion1IsRead(t *testing.T) {
	key, _ := crypto.GenerateKey()
	env := newSimEnvWith(t, key, false)
	file := filepath.Join(t.TempDir(), PendingFileName)
	first, _ := newChain(t, env, nil, Options{ConfirmTimeout: 100 * time.Millisecond, PendingFile: file})
	if _, err := first.Anchor(context.Background(), testReq); err == nil {
		t.Fatal("expected a timeout")
	}
	f := readFile(t, file)
	v1, _ := json.Marshal(pendingRecordV1{txRecord: *f.Pending, Version: 1, ChainID: f.ChainID, Contract: f.Contract, From: f.From})
	if err := os.WriteFile(file, v1, 0o600); err != nil {
		t.Fatal(err)
	}
	second, _ := newChain(t, env, nil, Options{PendingFile: file})
	if second.pending == nil || second.pending.tx.Hash() != f.Pending.TxHash || !bytes.Equal(mustRaw(second.pending.tx), f.Pending.RawTx) {
		t.Fatalf("v1 record not restored: %+v", second.pending)
	}
}

func mustRaw(tx *types.Transaction) []byte { b, _ := tx.MarshalBinary(); return b }
