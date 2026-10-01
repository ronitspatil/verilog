package anchor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/ronitspatil/verilog/daemon/internal/registry"
	"github.com/ronitspatil/verilog/daemon/internal/signer"
)

// Backend is the subset of an Ethereum client the anchorer needs.
// *ethclient.Client and the simulated backend's client implement it.
type Backend interface {
	bind.ContractBackend
	bind.DeployBackend
	ChainID(ctx context.Context) (*big.Int, error)
}

// Options configures an EthChain.
type Options struct {
	// ConfirmTimeout bounds the wait for one transaction's receipt.
	ConfirmTimeout time.Duration
	// MaxFeeCap and MaxTipCap (wei) cap maxFeePerGas and
	// maxPriorityFeePerGas. Nil means no ceiling.
	MaxFeeCap *big.Int
	MaxTipCap *big.Int
	// PendingFile, when set, persists the in-flight transaction before it
	// is broadcast, so a restarted daemon reuses its nonce instead of
	// anchoring the same root again.
	PendingFile string
}

// EthChain anchors roots with EIP-1559 transactions to a VeriLogRegistry.
//
// It is not safe for concurrent use; Worker calls it from one goroutine.
type EthChain struct {
	backend  Backend
	contract *registry.VeriLogRegistry
	address  common.Address
	signer   signer.Signer
	from     common.Address
	chainID  *big.Int
	opts     Options
	log      *slog.Logger

	// pending is the in-flight transaction (every version sent with its
	// nonce) and the request it carries. A retry of the same request checks
	// it before sending again and, if it is still unmined, replaces it with
	// the same nonce and higher fees, so a request is never anchored twice.
	// With Options.PendingFile it survives restarts.
	pending *pendingTx
	// nonceGone counts consecutive "nonce too low" answers for pending
	// while none of its transactions has a receipt.
	nonceGone int
}

type pendingTx struct {
	req    Request
	tx     *types.Transaction // latest version
	hashes []common.Hash      // every version sent with this nonce
}

// NewEthChain builds an anchorer. The chain ID is fetched from the backend;
// a pending transaction left by a previous run is loaded from
// opts.PendingFile.
func NewEthChain(ctx context.Context, backend Backend, contract common.Address, s signer.Signer,
	opts Options, logger *slog.Logger) (*EthChain, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if opts.ConfirmTimeout <= 0 {
		opts.ConfirmTimeout = 2 * time.Minute
	}
	if opts.MaxFeeCap != nil && opts.MaxTipCap != nil && opts.MaxTipCap.Cmp(opts.MaxFeeCap) > 0 {
		return nil, fmt.Errorf("anchor: max priority fee %s exceeds max fee %s", opts.MaxTipCap, opts.MaxFeeCap)
	}
	chainID, err := backend.ChainID(ctx)
	if err != nil {
		return nil, fmt.Errorf("anchor: fetching chain id: %w", err)
	}
	code, err := backend.CodeAt(ctx, contract, nil)
	if err != nil {
		return nil, fmt.Errorf("anchor: reading contract code: %w", err)
	}
	if len(code) == 0 {
		return nil, fmt.Errorf("anchor: no contract deployed at %s on chain %s", contract, chainID)
	}
	reg, err := registry.NewVeriLogRegistry(contract, backend)
	if err != nil {
		return nil, err
	}
	c := &EthChain{
		backend:  backend,
		contract: reg,
		address:  contract,
		signer:   s,
		from:     s.Address(),
		chainID:  chainID,
		opts:     opts,
		log:      logger,
	}
	if err := c.loadPending(); err != nil {
		return nil, err
	}
	return c, nil
}

// ChainID returns the chain ID reported by the RPC endpoint.
func (c *EthChain) ChainID() *big.Int { return new(big.Int).Set(c.chainID) }

// From returns the signer address.
func (c *EthChain) From() common.Address { return c.from }

// CheckRole verifies that the signer holds ANCHORER_ROLE.
func (c *EthChain) CheckRole(ctx context.Context) error {
	opts := &bind.CallOpts{Context: ctx}
	role, err := c.contract.ANCHORERROLE(opts)
	if err != nil {
		return fmt.Errorf("anchor: reading ANCHORER_ROLE: %w", err)
	}
	ok, err := c.contract.HasRole(opts, role, c.from)
	if err != nil {
		return fmt.Errorf("anchor: checking role: %w", err)
	}
	if !ok {
		return fmt.Errorf("anchor: signer %s does not hold ANCHORER_ROLE on %s", c.from, c.address)
	}
	return nil
}

// Anchor submits anchorEpoch and waits for the receipt.
func (c *EthChain) Anchor(ctx context.Context, req Request) (Result, error) {
	if c.pending != nil && c.pending.req != req {
		// The worker only moves past a request once it is confirmed, so a
		// pending transaction for another request has been mined.
		c.log.Info("anchor: discarding pending transaction of a completed request", "tx", c.pending.tx.Hash(), "nonce", c.pending.tx.Nonce())
		if err := c.clearPending(); err != nil {
			return Result{}, err
		}
	}
	// 1. A previous attempt (or an earlier version of it, or one sent before
	//    a restart) may have been mined after we stopped waiting.
	if res, ok, err := c.pendingReceipt(ctx, req); err != nil || ok {
		return res, err
	}
	// 2. The root may already be anchored (e.g. crash after confirmation but
	//    before the checkpoint was written).
	if res, ok, err := c.alreadyAnchored(ctx, req); err != nil {
		return Result{}, err
	} else if ok {
		return res, c.clearPending()
	}
	// 3. Send (replace, or rebroadcast at the fee ceiling) and wait.
	tx, err := c.send(ctx, req)
	if err != nil {
		return Result{}, err
	}

	wctx, cancel := context.WithTimeout(ctx, c.opts.ConfirmTimeout)
	defer cancel()
	rcpt, err := bind.WaitMined(wctx, c.backend, tx)
	if err != nil {
		return Result{}, fmt.Errorf("awaiting confirmation of %s: %w", tx.Hash(), err)
	}
	return c.fromReceipt(req, rcpt)
}

// pendingReceipt looks for a receipt of any version of the pending
// transaction.
func (c *EthChain) pendingReceipt(ctx context.Context, req Request) (Result, bool, error) {
	if c.pending == nil {
		return Result{}, false, nil
	}
	for _, h := range c.pending.hashes {
		rcpt, err := c.backend.TransactionReceipt(ctx, h)
		switch {
		case err == nil:
			res, err := c.fromReceipt(req, rcpt)
			return res, true, err
		case !errors.Is(err, ethereum.NotFound):
			return Result{}, false, fmt.Errorf("receipt of %s: %w", h, err)
		}
	}
	return Result{}, false, nil
}

func (c *EthChain) fromReceipt(req Request, rcpt *types.Receipt) (Result, error) {
	if err := c.clearPending(); err != nil {
		return Result{}, err
	}
	if rcpt.Status != types.ReceiptStatusSuccessful {
		return Result{}, fmt.Errorf("anchor transaction %s reverted in block %s", rcpt.TxHash, rcpt.BlockNumber)
	}
	for _, lg := range rcpt.Logs {
		if lg.Address != c.address {
			continue
		}
		ev, err := c.contract.ParseLogAnchored(*lg)
		if err != nil {
			continue
		}
		if ev.AgentId != req.AgentKey || ev.MerkleRoot != req.Root {
			continue
		}
		return Result{EpochID: ev.EpochId.Uint64(), TxHash: rcpt.TxHash.Hex(), BlockNumber: rcpt.BlockNumber.Uint64()}, nil
	}
	return Result{}, fmt.Errorf("receipt of %s has no matching LogAnchored event", rcpt.TxHash)
}

func (c *EthChain) alreadyAnchored(ctx context.Context, req Request) (Result, bool, error) {
	opts := &bind.CallOpts{Context: ctx}
	latest, err := c.contract.LatestEpoch(opts, req.AgentKey)
	if err != nil {
		return Result{}, false, fmt.Errorf("reading latestEpoch: %w", err)
	}
	if latest.Sign() == 0 {
		return Result{}, false, nil
	}
	a, err := c.contract.AgentAnchors(opts, req.AgentKey, latest)
	if err != nil {
		return Result{}, false, fmt.Errorf("reading agentAnchors: %w", err)
	}
	if a.MerkleRoot != req.Root || a.LogCount != req.Count {
		return Result{}, false, nil
	}
	res := Result{EpochID: latest.Uint64()}
	it, err := c.contract.FilterLogAnchored(&bind.FilterOpts{Context: ctx}, [][32]byte{req.AgentKey}, []*big.Int{latest})
	if err != nil {
		c.log.Warn("anchor: root already anchored but its transaction could not be located", "epoch", latest, "err", err)
		return res, true, nil
	}
	defer it.Close()
	for it.Next() {
		res.TxHash = it.Event.Raw.TxHash.Hex()
		res.BlockNumber = it.Event.Raw.BlockNumber
	}
	c.log.Info("anchor: root already anchored on chain, recovering", "epoch", latest, "tx", res.TxHash)
	return res, true, nil
}

// send signs and broadcasts anchorEpoch. When a previous transaction for the
// same request is still pending, it is replaced (same nonce, fees +25%); if
// the fee ceiling leaves no room for a valid replacement, the pending
// transaction is rebroadcast unchanged instead. A new transaction is
// persisted before it is broadcast.
func (c *EthChain) send(ctx context.Context, req Request) (*types.Transaction, error) {
	head, err := c.backend.HeaderByNumber(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("reading head: %w", err)
	}
	if head.BaseFee == nil {
		return nil, errors.New("RPC chain does not support EIP-1559 (no base fee)")
	}
	tip, err := c.backend.SuggestGasTipCap(ctx)
	if err != nil {
		return nil, fmt.Errorf("suggesting tip: %w", err)
	}
	feeCap := new(big.Int).Add(new(big.Int).Mul(head.BaseFee, big.NewInt(2)), tip)

	var nonce uint64
	if c.pending != nil {
		old := c.pending.tx
		nonce = old.Nonce()
		tip = maxBig(tip, bump(old.GasTipCap()))
		feeCap = maxBig(feeCap, bump(old.GasFeeCap()))
	} else if nonce, err = c.backend.PendingNonceAt(ctx, c.from); err != nil {
		return nil, fmt.Errorf("reading nonce: %w", err)
	}
	tip, feeCap, capped := c.applyCeiling(tip, feeCap)
	if c.pending != nil {
		old := c.pending.tx
		if tip.Cmp(minReplacement(old.GasTipCap())) < 0 || feeCap.Cmp(minReplacement(old.GasFeeCap())) < 0 {
			c.log.Error("anchor: fee ceiling reached; not bumping fees, waiting for the pending transaction",
				"tx", old.Hash(), "nonce", nonce, "tip_wei", old.GasTipCap(), "max_fee_wei", old.GasFeeCap(),
				"base_fee_wei", head.BaseFee, "agent_key", common.Hash(req.AgentKey), "root", common.Hash(req.Root))
			if err := c.broadcast(ctx, old); err != nil {
				return nil, err
			}
			return old, nil
		}
	}
	if capped {
		c.log.Error("anchor: fee ceiling reached; fees capped",
			"nonce", nonce, "tip_wei", tip, "max_fee_wei", feeCap, "base_fee_wei", head.BaseFee,
			"agent_key", common.Hash(req.AgentKey), "root", common.Hash(req.Root))
	}

	opts, err := signer.TransactOpts(ctx, c.signer, c.chainID)
	if err != nil {
		return nil, err
	}
	opts.NoSend = true
	opts.Nonce = new(big.Int).SetUint64(nonce)
	opts.GasTipCap, opts.GasFeeCap = tip, feeCap
	tx, err := c.contract.AnchorEpoch(opts, req.AgentKey, req.Root, req.Count)
	if err != nil {
		return nil, fmt.Errorf("building anchorEpoch transaction: %w", err)
	}

	p := &pendingTx{req: req, tx: tx}
	if c.pending != nil {
		p.hashes = append(p.hashes, c.pending.hashes...)
	}
	p.hashes = append(p.hashes, tx.Hash())
	if err := c.savePending(p); err != nil { // before the broadcast: never send what a restart cannot see
		return nil, err
	}
	c.pending = p
	if err := c.broadcast(ctx, tx); err != nil {
		return nil, err
	}
	c.log.Info("anchor: transaction sent", "tx", tx.Hash(), "nonce", tx.Nonce(), "replaces", len(p.hashes)-1,
		"tip_wei", tip, "max_fee_wei", feeCap, "agent_key", common.Hash(req.AgentKey), "root", common.Hash(req.Root), "count", req.Count)
	return tx, nil
}

// broadcast sends tx. "Already known" is success. "Nonce too low" means the
// nonce was used: by a version of this transaction (whose receipt the next
// attempt finds) or, if no version is ever mined, by another transaction. In
// that case the pending transaction is dropped on the second consecutive
// such answer and the next attempt starts with a fresh nonce.
func (c *EthChain) broadcast(ctx context.Context, tx *types.Transaction) error {
	err := c.backend.SendTransaction(ctx, tx)
	if err == nil || strings.Contains(err.Error(), "already known") {
		c.nonceGone = 0
		return nil
	}
	if strings.Contains(strings.ToLower(err.Error()), "nonce too low") && c.pending != nil {
		c.nonceGone++
		if c.nonceGone >= 2 {
			c.log.Error("anchor: the pending transaction's nonce was used by another transaction; starting over with a fresh nonce",
				"nonce", tx.Nonce(), "tx", tx.Hash())
			if cerr := c.clearPending(); cerr != nil {
				return cerr
			}
		}
	}
	return fmt.Errorf("sending %s: %w", tx.Hash(), err)
}

// applyCeiling caps tip and feeCap at the configured maxima and keeps
// tip <= feeCap. capped reports whether a ceiling applied.
func (c *EthChain) applyCeiling(tip, feeCap *big.Int) (*big.Int, *big.Int, bool) {
	capped := false
	if c.opts.MaxTipCap != nil && tip.Cmp(c.opts.MaxTipCap) > 0 {
		tip, capped = new(big.Int).Set(c.opts.MaxTipCap), true
	}
	if c.opts.MaxFeeCap != nil && feeCap.Cmp(c.opts.MaxFeeCap) > 0 {
		feeCap, capped = new(big.Int).Set(c.opts.MaxFeeCap), true
	}
	if tip.Cmp(feeCap) > 0 {
		tip = new(big.Int).Set(feeCap)
	}
	return tip, feeCap, capped
}

// bump returns v * 1.25 + 1 (geth requires >= 10% for replacement).
func bump(v *big.Int) *big.Int {
	out := new(big.Int).Mul(v, big.NewInt(125))
	out.Div(out, big.NewInt(100))
	return out.Add(out, big.NewInt(1))
}

// minReplacement is the lowest fee a node accepts to replace a transaction
// paying v (geth and anvil: +10%, rounded up).
func minReplacement(v *big.Int) *big.Int {
	out := new(big.Int).Mul(v, big.NewInt(110))
	out.Add(out, big.NewInt(99))
	return out.Div(out, big.NewInt(100))
}

func maxBig(a, b *big.Int) *big.Int {
	if a.Cmp(b) >= 0 {
		return new(big.Int).Set(a)
	}
	return new(big.Int).Set(b)
}
