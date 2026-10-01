package anchor

import (
	"context"
	"crypto/ecdsa"
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
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ronitspatil/verilog/daemon/internal/registry"
)

// Backend is the subset of an Ethereum client the anchorer needs.
// *ethclient.Client and the simulated backend's client implement it.
type Backend interface {
	bind.ContractBackend
	bind.DeployBackend
	ChainID(ctx context.Context) (*big.Int, error)
}

// EthChain anchors roots with EIP-1559 transactions to a VeriLogRegistry.
//
// It is not safe for concurrent use; Worker calls it from one goroutine.
type EthChain struct {
	backend        Backend
	contract       *registry.VeriLogRegistry
	address        common.Address
	key            *ecdsa.PrivateKey
	from           common.Address
	chainID        *big.Int
	confirmTimeout time.Duration
	log            *slog.Logger

	// pending is the last sent, unconfirmed transaction and the request it
	// carries. A retry of the same request checks it before sending again and,
	// if it is still unmined, replaces it with the same nonce and higher fees,
	// so a request is never anchored twice by this process.
	pending *pendingTx
}

type pendingTx struct {
	req Request
	tx  *types.Transaction
}

// NewEthChain builds an anchorer. The chain ID is fetched from the backend.
func NewEthChain(ctx context.Context, backend Backend, contract common.Address, key *ecdsa.PrivateKey,
	confirmTimeout time.Duration, logger *slog.Logger) (*EthChain, error) {
	if logger == nil {
		logger = slog.Default()
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
	return &EthChain{
		backend:        backend,
		contract:       reg,
		address:        contract,
		key:            key,
		from:           crypto.PubkeyToAddress(key.PublicKey),
		chainID:        chainID,
		confirmTimeout: confirmTimeout,
		log:            logger,
	}, nil
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
		c.pending = nil
	}
	// 1. A previous attempt may have been mined after we stopped waiting.
	if c.pending != nil {
		rcpt, err := c.backend.TransactionReceipt(ctx, c.pending.tx.Hash())
		switch {
		case err == nil:
			return c.fromReceipt(req, rcpt)
		case !errors.Is(err, ethereum.NotFound):
			return Result{}, fmt.Errorf("receipt of %s: %w", c.pending.tx.Hash(), err)
		}
	}
	// 2. The root may already be anchored (e.g. crash after confirmation but
	//    before the checkpoint was written).
	if res, ok, err := c.alreadyAnchored(ctx, req); err != nil {
		return Result{}, err
	} else if ok {
		c.pending = nil
		return res, nil
	}
	// 3. Send (or replace) and wait.
	tx, err := c.send(ctx, req)
	if err != nil {
		return Result{}, err
	}
	c.log.Info("anchor: transaction sent", "tx", tx.Hash(), "nonce", tx.Nonce(), "agent_key", common.Hash(req.AgentKey), "root", common.Hash(req.Root), "count", req.Count)

	wctx, cancel := context.WithTimeout(ctx, c.confirmTimeout)
	defer cancel()
	rcpt, err := bind.WaitMined(wctx, c.backend, tx)
	if err != nil {
		return Result{}, fmt.Errorf("awaiting confirmation of %s: %w", tx.Hash(), err)
	}
	return c.fromReceipt(req, rcpt)
}

func (c *EthChain) fromReceipt(req Request, rcpt *types.Receipt) (Result, error) {
	if rcpt.Status != types.ReceiptStatusSuccessful {
		c.pending = nil
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
		c.pending = nil
		return Result{EpochID: ev.EpochId.Uint64(), TxHash: rcpt.TxHash.Hex(), BlockNumber: rcpt.BlockNumber.Uint64()}, nil
	}
	c.pending = nil
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
// same request is still pending, it is replaced (same nonce, fees +25%).
func (c *EthChain) send(ctx context.Context, req Request) (*types.Transaction, error) {
	opts, err := bind.NewKeyedTransactorWithChainID(c.key, c.chainID)
	if err != nil {
		return nil, err
	}
	opts.Context = ctx
	opts.NoSend = true

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

	if c.pending != nil {
		old := c.pending.tx
		opts.Nonce = new(big.Int).SetUint64(old.Nonce())
		tip = maxBig(tip, bump(old.GasTipCap()))
		feeCap = maxBig(feeCap, bump(old.GasFeeCap()))
		if feeCap.Cmp(tip) < 0 {
			feeCap = new(big.Int).Set(tip)
		}
	} else {
		nonce, err := c.backend.PendingNonceAt(ctx, c.from)
		if err != nil {
			return nil, fmt.Errorf("reading nonce: %w", err)
		}
		opts.Nonce = new(big.Int).SetUint64(nonce)
	}
	opts.GasTipCap, opts.GasFeeCap = tip, feeCap

	tx, err := c.contract.AnchorEpoch(opts, req.AgentKey, req.Root, req.Count)
	if err != nil {
		return nil, fmt.Errorf("building anchorEpoch transaction: %w", err)
	}
	if err := c.backend.SendTransaction(ctx, tx); err != nil && !strings.Contains(err.Error(), "already known") {
		return nil, fmt.Errorf("sending %s: %w", tx.Hash(), err)
	}
	c.pending = &pendingTx{req: req, tx: tx}
	return tx, nil
}

// bump returns v * 1.25 + 1 (geth requires >= 10% for replacement).
func bump(v *big.Int) *big.Int {
	out := new(big.Int).Mul(v, big.NewInt(125))
	out.Div(out, big.NewInt(100))
	return out.Add(out, big.NewInt(1))
}

func maxBig(a, b *big.Int) *big.Int {
	if a.Cmp(b) >= 0 {
		return new(big.Int).Set(a)
	}
	return new(big.Int).Set(b)
}
