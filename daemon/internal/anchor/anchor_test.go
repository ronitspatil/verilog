package anchor

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient/simulated"

	"github.com/ronitspatil/verilog/daemon/internal/merkle"
	"github.com/ronitspatil/verilog/daemon/internal/registry"
	"github.com/ronitspatil/verilog/daemon/internal/signer"
	"github.com/ronitspatil/verilog/daemon/internal/signer/gcpkmsfake"
	"github.com/ronitspatil/verilog/daemon/internal/signer/kmsfake"
)

// ------------------------------------------------------------------ worker

type flakyChain struct {
	mu       sync.Mutex
	failures map[[32]byte]int
	calls    []Request
	epoch    uint64
	results  map[Request]Result
}

func (f *flakyChain) Final(_ context.Context, req Request) (Status, Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return Final, f.results[req], nil
}

func (f *flakyChain) Release(Request) error { return nil }

func (f *flakyChain) Anchor(_ context.Context, req Request) (Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, req)
	if f.failures[req.Root] > 0 {
		f.failures[req.Root]--
		return Result{}, errors.New("rpc unavailable")
	}
	f.epoch++
	if f.results == nil {
		f.results = map[Request]Result{}
	}
	f.results[req] = Result{EpochID: f.epoch}
	return f.results[req], nil
}

func TestWorkerRetriesAndPreservesOrder(t *testing.T) {
	chain := &flakyChain{failures: map[[32]byte]int{{1}: 2}}
	w := NewWorker(chain, WorkerOptions{Backoff: Backoff{Initial: time.Millisecond, Max: 4 * time.Millisecond}}, nil)
	var mu sync.Mutex
	var done []uint64
	finalizeFailures := 1
	all := make(chan struct{})
	for i := byte(1); i <= 3; i++ {
		root := [32]byte{i}
		w.Enqueue(Job{Request: Request{Root: root, Count: 1}, Done: func(_ context.Context, r Result) error {
			mu.Lock()
			defer mu.Unlock()
			if root == [32]byte{2} && finalizeFailures > 0 {
				finalizeFailures--
				return errors.New("disk full")
			}
			done = append(done, r.EpochID)
			if len(done) == 3 {
				close(all)
			}
			return nil
		}})
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	select {
	case <-all:
	case <-time.After(5 * time.Second):
		t.Fatal("jobs did not complete")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(done) != 3 || done[0] != 1 || done[1] != 2 || done[2] != 3 {
		t.Fatalf("done = %v", done)
	}
	// Root 1 failed twice; root 2's finalize failure must not re-anchor it.
	if len(chain.calls) != 5 {
		t.Fatalf("chain calls = %d, want 5", len(chain.calls))
	}
}

func TestWorkerKeepsJobsOnShutdown(t *testing.T) {
	chain := &flakyChain{failures: map[[32]byte]int{{1}: 1 << 30}}
	w := NewWorker(chain, WorkerOptions{Backoff: Backoff{Initial: time.Millisecond, Max: time.Millisecond}}, nil)
	w.Enqueue(Job{Request: Request{Root: [32]byte{1}}, Done: func(context.Context, Result) error { return nil }})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	w.Run(ctx)
	if w.Pending() != 1 {
		t.Fatalf("pending = %d, want 1 (job must not be dropped)", w.Pending())
	}
}

// --------------------------------------------------------- simulated chain

type simEnv struct {
	sim      *simulated.Backend
	client   simulated.Client
	key      *ecdsa.PrivateKey
	addr     common.Address
	contract common.Address
	reg      *registry.VeriLogRegistry
	stop     func()

	mining   chan struct{} // closed once automatic mining runs
	startMin func()
}

// newSimEnv deploys the registry with a fresh anchorer key and mines a block
// every 50ms.
func newSimEnv(t *testing.T) *simEnv {
	key, _ := crypto.GenerateKey()
	return newSimEnvWith(t, key, true)
}

// newSimEnvWith deploys the registry with key as the anchorer. Without
// automine, blocks are mined only after env.startMining().
func newSimEnvWith(t *testing.T, key *ecdsa.PrivateKey, automine bool) *simEnv {
	t.Helper()
	from := crypto.PubkeyToAddress(key.PublicKey)
	sim := simulated.NewBackend(types.GenesisAlloc{from: {Balance: new(big.Int).Lsh(big.NewInt(1), 100)}})
	client := sim.Client()
	chainID, _ := client.ChainID(context.Background())
	opts, _ := bind.NewKeyedTransactorWithChainID(key, chainID)
	// The admin (key admin) is a separate account; the anchorer never holds it.
	admin := common.HexToAddress("0x000000000000000000000000000000000000ad01")
	addr, _, reg, err := registry.DeployVeriLogRegistry(opts, client, admin, from)
	if err != nil {
		t.Fatal(err)
	}
	sim.Commit()

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	mining := make(chan struct{})
	wg.Add(1)
	go func() { // mine a block every 50ms
		defer wg.Done()
		select {
		case <-ctx.Done():
			return
		case <-mining:
		}
		tk := time.NewTicker(50 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tk.C:
				sim.Commit()
			}
		}
	}()
	env := &simEnv{sim: sim, client: client, addr: from, contract: addr, reg: reg,
		key: key, mining: mining}
	var once sync.Once
	env.startMin = func() { once.Do(func() { close(mining) }) }
	if automine {
		env.startMin()
	}
	env.stop = func() { cancel(); wg.Wait(); sim.Close() }
	t.Cleanup(env.stop)
	return env
}

func TestEthChainAnchorsAndVerifiesOnChain(t *testing.T) {
	env := newSimEnv(t)
	anchorAndVerify(t, env, signer.NewLocal(env.key))
}

// The production path: the anchoring key lives in (fake) KMS, which returns
// DER SPKI and DER signatures, high-s included.
func TestEthChainAnchorsWithKMSSigner(t *testing.T) {
	fake := kmsfake.New("alias/verilog-anchorer")
	env := newSimEnvWith(t, fake.Key, true)
	kmsSigner, err := signer.NewKMS(context.Background(), fake, "alias/verilog-anchorer", signer.KMSOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if kmsSigner.Address() != env.addr {
		t.Fatalf("KMS address %s, want %s", kmsSigner.Address(), env.addr)
	}
	anchorAndVerify(t, env, kmsSigner)
	if fake.HighSReturned == 0 {
		t.Fatal("no high-s signature was exercised")
	}
}

// The Google Cloud KMS path: PEM public key, CRC32C-checked DER
// signatures, high-s included.
func TestEthChainAnchorsWithGCPKMSSigner(t *testing.T) {
	const name = "projects/verilog/locations/us-east1/keyRings/verilog/cryptoKeys/anchorer/cryptoKeyVersions/1"
	fake := gcpkmsfake.New(name)
	env := newSimEnvWith(t, fake.Key, true)
	gcpSigner, err := signer.NewGCPKMS(context.Background(), fake, name, signer.KMSOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if gcpSigner.Address() != env.addr {
		t.Fatalf("Cloud KMS address %s, want %s", gcpSigner.Address(), env.addr)
	}
	anchorAndVerify(t, env, gcpSigner)
	if fake.HighSReturned == 0 {
		t.Fatal("no high-s signature was exercised")
	}
}

func anchorAndVerify(t *testing.T, env *simEnv, sgn signer.Signer) {
	t.Helper()
	ctx := context.Background()
	chain, err := NewEthChain(ctx, env.client, env.contract, sgn, Options{ConfirmTimeout: 30 * time.Second}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := chain.CheckRole(ctx); err != nil {
		t.Fatal(err)
	}

	// A Go-built tree of 5 leaves.
	var digests [][32]byte
	for i := 0; i < 5; i++ {
		digests = append(digests, sha256.Sum256([]byte{byte(i)}))
	}
	leaves := merkle.LeavesFromDigests(digests)
	tree, _ := merkle.Build(leaves)
	agent := crypto.Keccak256Hash([]byte("agent-alpha"))

	res, err := chain.Anchor(ctx, Request{AgentKey: agent, Root: tree.Root(), Count: 5})
	if err != nil {
		t.Fatal(err)
	}
	if res.EpochID != 1 || res.TxHash == "" || res.BlockNumber == 0 {
		t.Fatalf("unexpected result %+v", res)
	}

	call := &bind.CallOpts{Context: ctx}
	for i := range leaves {
		proof, _ := tree.Proof(i)
		p := make([][32]byte, len(proof))
		copy(p, proof)
		ok, err := env.reg.VerifyAnchoredLeaf(call, agent, big.NewInt(1), leaves[i], p)
		if err != nil || !ok {
			t.Fatalf("leaf %d: on-chain verification failed: %v", i, err)
		}
		bad := leaves[i]
		bad[31] ^= 1
		if ok, _ := env.reg.VerifyAnchoredLeaf(call, agent, big.NewInt(1), bad, p); ok {
			t.Fatalf("leaf %d: tampered leaf verified on chain", i)
		}
	}

	// Second epoch increments.
	root2 := leaves[0] // a 1-leaf tree's root is its leaf
	res2, err := chain.Anchor(ctx, Request{AgentKey: agent, Root: root2, Count: 1})
	if err != nil || res2.EpochID != 2 {
		t.Fatalf("second anchor: %+v %v", res2, err)
	}

	// Retrying an already-anchored request is idempotent (crash recovery).
	res3, err := chain.Anchor(ctx, Request{AgentKey: agent, Root: root2, Count: 1})
	if err != nil || res3.EpochID != 2 || res3.TxHash != res2.TxHash {
		t.Fatalf("idempotent retry: %+v %v (want epoch 2, tx %s)", res3, err, res2.TxHash)
	}
	latest, _ := env.reg.LatestEpoch(call, agent)
	if latest.Uint64() != 2 {
		t.Fatalf("latest epoch = %s, want 2", latest)
	}
}

func TestEthChainRejectsSignerWithoutRole(t *testing.T) {
	env := newSimEnv(t)
	ctx := context.Background()
	other, _ := crypto.GenerateKey()
	chain, err := NewEthChain(ctx, env.client, env.contract, signer.NewLocal(other), Options{ConfirmTimeout: 5 * time.Second}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := chain.CheckRole(ctx); err == nil {
		t.Fatal("expected missing role error")
	}
}

func TestEthChainRequiresContract(t *testing.T) {
	env := newSimEnv(t)
	if _, err := NewEthChain(context.Background(), env.client, common.HexToAddress("0x1234"), signer.NewLocal(env.key), Options{ConfirmTimeout: time.Second}, nil); err == nil {
		t.Fatal("expected error for address without code")
	}
}
