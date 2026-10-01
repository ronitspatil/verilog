package anchor

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient/simulated"

	"github.com/ronitspatil/verilog/daemon/internal/signer"
)

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// dropSends fails the next n broadcasts, as if the daemon died after
// persisting the transaction but before it reached the node.
type dropSends struct {
	simulated.Client
	n int
}

func (d *dropSends) SendTransaction(ctx context.Context, tx *types.Transaction) error {
	if d.n > 0 {
		d.n--
		return errors.New("connection reset (daemon killed)")
	}
	return d.Client.SendTransaction(ctx, tx)
}

var testReq = Request{
	AgentKey: crypto.Keccak256Hash([]byte("agent-restart")),
	Root:     crypto.Keccak256Hash([]byte("root-1")),
	Count:    3,
}

func readRecord(t *testing.T, path string) pendingRecord {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("pending record: %v", err)
	}
	var r pendingRecord
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

// checkAnchoredOnce asserts the agent has exactly one epoch and the
// anchorer used exactly one nonce after the deployment.
func checkAnchoredOnce(t *testing.T, env *simEnv, pendingFile string) {
	t.Helper()
	time.Sleep(300 * time.Millisecond) // let any second transaction be mined
	ctx := context.Background()
	latest, err := env.reg.LatestEpoch(&bind.CallOpts{Context: ctx}, testReq.AgentKey)
	if err != nil || latest.Uint64() != 1 {
		t.Fatalf("latest epoch = %v (%v), want 1: the root was anchored more than once", latest, err)
	}
	nonce, err := env.client.PendingNonceAt(ctx, env.addr)
	if err != nil || nonce != 2 { // 0: deployment, 1: the anchor
		t.Fatalf("anchorer nonce = %d (%v), want 2", nonce, err)
	}
	if _, err := os.Stat(pendingFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending record not removed after confirmation: %v", err)
	}
}

// The daemon is killed after broadcasting and before the receipt; the
// restarted daemon finds the transaction still unmined and replaces it with
// the same nonce instead of anchoring the root a second time.
func TestRestartBetweenSendAndReceiptReplacesWithSameNonce(t *testing.T) {
	key, _ := crypto.GenerateKey()
	env := newSimEnvWith(t, key, false)
	ctx := context.Background()
	file := filepath.Join(t.TempDir(), PendingFileName)

	first, err := NewEthChain(ctx, env.client, env.contract, signer.NewLocal(key), Options{ConfirmTimeout: 300 * time.Millisecond, PendingFile: file}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Anchor(ctx, testReq); err == nil {
		t.Fatal("expected a confirmation timeout (no blocks are mined)")
	}
	rec := readRecord(t, file)
	if rec.Nonce != 1 || rec.AgentKey != testReq.AgentKey || rec.Root != testReq.Root || rec.Count != 3 || len(rec.TxHashes) != 1 {
		t.Fatalf("record %+v", rec)
	}
	// "kill": first is never used again.

	logs := &syncBuffer{}
	second, err := NewEthChain(ctx, env.client, env.contract, signer.NewLocal(key),
		Options{ConfirmTimeout: 30 * time.Second, PendingFile: file}, slog.New(slog.NewTextHandler(logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	time.AfterFunc(500*time.Millisecond, env.startMin) // after the replacement is sent
	res, err := second.Anchor(ctx, testReq)
	if err != nil {
		t.Fatal(err)
	}
	if res.EpochID != 1 || res.TxHash == rec.TxHash.Hex() {
		t.Fatalf("result %+v: want epoch 1 from the replacement transaction", res)
	}
	if !strings.Contains(logs.String(), "resuming pending transaction") || !strings.Contains(logs.String(), "replaces=1") {
		t.Fatalf("logs:\n%s", logs)
	}
	checkAnchoredOnce(t, env, file)
	if _, err := env.client.TransactionReceipt(ctx, rec.TxHash); !errors.Is(err, ethereum.NotFound) {
		t.Fatalf("the replaced transaction was mined too: %v", err)
	}
}

// The transaction is mined while the daemon is down: the restarted daemon
// resumes from its receipt without sending anything.
func TestRestartAfterMinedResumesFromReceipt(t *testing.T) {
	key, _ := crypto.GenerateKey()
	env := newSimEnvWith(t, key, false)
	ctx := context.Background()
	file := filepath.Join(t.TempDir(), PendingFileName)

	first, _ := NewEthChain(ctx, env.client, env.contract, signer.NewLocal(key), Options{ConfirmTimeout: 200 * time.Millisecond, PendingFile: file}, nil)
	if _, err := first.Anchor(ctx, testReq); err == nil {
		t.Fatal("expected a confirmation timeout")
	}
	rec := readRecord(t, file)
	env.startMin()
	if _, err := bind.WaitMinedHash(ctx, env.client, rec.TxHash); err != nil {
		t.Fatal(err)
	}

	second, err := NewEthChain(ctx, env.client, env.contract, signer.NewLocal(key), Options{ConfirmTimeout: 5 * time.Second, PendingFile: file}, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := second.Anchor(ctx, testReq)
	if err != nil || res.EpochID != 1 || res.TxHash != rec.TxHash.Hex() {
		t.Fatalf("result %+v %v, want epoch 1 from %s", res, err, rec.TxHash)
	}
	checkAnchoredOnce(t, env, file)
}

// The daemon dies after persisting the transaction but before the node got
// it: the restarted daemon sends with the recorded nonce.
func TestRestartAfterPersistBeforeBroadcast(t *testing.T) {
	key, _ := crypto.GenerateKey()
	env := newSimEnvWith(t, key, true)
	ctx := context.Background()
	file := filepath.Join(t.TempDir(), PendingFileName)

	first, _ := NewEthChain(ctx, &dropSends{Client: env.client, n: 1}, env.contract, signer.NewLocal(key),
		Options{ConfirmTimeout: time.Second, PendingFile: file}, nil)
	if _, err := first.Anchor(ctx, testReq); err == nil || !strings.Contains(err.Error(), "daemon killed") {
		t.Fatalf("err = %v", err)
	}
	if rec := readRecord(t, file); rec.Nonce != 1 {
		t.Fatalf("record nonce %d", rec.Nonce)
	}
	second, _ := NewEthChain(ctx, env.client, env.contract, signer.NewLocal(key), Options{ConfirmTimeout: 30 * time.Second, PendingFile: file}, nil)
	if res, err := second.Anchor(ctx, testReq); err != nil || res.EpochID != 1 {
		t.Fatalf("result %+v %v", res, err)
	}
	checkAnchoredOnce(t, env, file)
}

func TestPendingRecordForAnotherSignerIsSetAside(t *testing.T) {
	key, _ := crypto.GenerateKey()
	env := newSimEnvWith(t, key, false)
	ctx := context.Background()
	file := filepath.Join(t.TempDir(), PendingFileName)
	first, _ := NewEthChain(ctx, env.client, env.contract, signer.NewLocal(key), Options{ConfirmTimeout: 100 * time.Millisecond, PendingFile: file}, nil)
	first.Anchor(ctx, testReq)

	other, _ := crypto.GenerateKey()
	c, err := NewEthChain(ctx, env.client, env.contract, signer.NewLocal(other), Options{PendingFile: file}, nil)
	if err != nil || c.pending != nil {
		t.Fatalf("pending %v err %v", c.pending, err)
	}
	if _, err := os.Stat(file + ".stale"); err != nil {
		t.Fatal(err)
	}

	os.WriteFile(file, []byte("{garbage"), 0o600)
	if _, err := NewEthChain(ctx, env.client, env.contract, signer.NewLocal(key), Options{PendingFile: file}, nil); err == nil {
		t.Fatal("accepted an unreadable pending record")
	}
}

// Retries bump fees until the ceiling, then stop bumping, log at ERROR and
// keep waiting (rebroadcasting) at the cap. The epoch is never dropped.
func TestFeeCeiling(t *testing.T) {
	key, _ := crypto.GenerateKey()
	env := newSimEnvWith(t, key, false)
	ctx := context.Background()
	head, _ := env.client.HeaderByNumber(ctx, nil)
	tip, _ := env.client.SuggestGasTipCap(ctx)
	natural := new(big.Int).Add(new(big.Int).Mul(head.BaseFee, big.NewInt(2)), tip)
	maxFee := new(big.Int).Div(new(big.Int).Mul(natural, big.NewInt(12)), big.NewInt(10)) // room for one bump only

	logs := &syncBuffer{}
	file := filepath.Join(t.TempDir(), PendingFileName)
	c, err := NewEthChain(ctx, env.client, env.contract, signer.NewLocal(key),
		Options{ConfirmTimeout: 200 * time.Millisecond, MaxFeeCap: maxFee, PendingFile: file}, slog.New(slog.NewTextHandler(logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 1; attempt <= 4; attempt++ {
		if _, err := c.Anchor(ctx, testReq); err == nil {
			t.Fatalf("attempt %d: expected a timeout", attempt)
		}
	}
	rec := readRecord(t, file)
	if len(rec.TxHashes) != 2 {
		t.Fatalf("%d versions sent, want 2 (one bump, then capped)", len(rec.TxHashes))
	}
	if rec.GasFeeCap.ToInt().Cmp(maxFee) != 0 {
		t.Fatalf("fee cap %s, want the ceiling %s", rec.GasFeeCap.ToInt(), maxFee)
	}
	out := logs.String()
	if !strings.Contains(out, `level=ERROR msg="anchor: fee ceiling reached; fees capped"`) ||
		strings.Count(out, `level=ERROR msg="anchor: fee ceiling reached; not bumping fees`) != 2 {
		t.Fatalf("logs:\n%s", out)
	}

	env.startMin()
	c.opts.ConfirmTimeout = 30 * time.Second
	res, err := c.Anchor(ctx, testReq)
	if err != nil || res.EpochID != 1 {
		t.Fatalf("result %+v %v", res, err)
	}
	checkAnchoredOnce(t, env, file)
}

func TestApplyCeiling(t *testing.T) {
	c := &EthChain{opts: Options{MaxFeeCap: big.NewInt(100), MaxTipCap: big.NewInt(10)}}
	for _, tc := range []struct {
		tip, fee, wantTip, wantFee int64
		capped                     bool
	}{
		{5, 50, 5, 50, false},
		{20, 50, 10, 50, true},
		{5, 500, 5, 100, true},
		{200, 500, 10, 100, true},
	} {
		tip, fee, capped := c.applyCeiling(big.NewInt(tc.tip), big.NewInt(tc.fee))
		if tip.Int64() != tc.wantTip || fee.Int64() != tc.wantFee || capped != tc.capped {
			t.Errorf("%+v: got %s %s %v", tc, tip, fee, capped)
		}
	}
	c.opts = Options{MaxFeeCap: big.NewInt(8)}
	if tip, fee, _ := c.applyCeiling(big.NewInt(10), big.NewInt(50)); tip.Int64() != 8 || fee.Int64() != 8 {
		t.Errorf("tip must not exceed the capped fee: %s %s", tip, fee)
	}
	if minReplacement(big.NewInt(100)).Int64() != 110 || minReplacement(big.NewInt(101)).Int64() != 112 {
		t.Error("minReplacement")
	}
	if _, err := NewEthChain(context.Background(), nil, common.Address{}, signer.NewLocal(mustKey()),
		Options{MaxFeeCap: big.NewInt(1), MaxTipCap: big.NewInt(2)}, nil); err == nil {
		t.Error("accepted a tip ceiling above the fee ceiling")
	}
}

func mustKey() *ecdsa.PrivateKey { k, _ := crypto.GenerateKey(); return k }
