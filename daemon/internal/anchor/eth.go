package anchor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/ronitspatil/verilog/daemon/internal/finality"
	"github.com/ronitspatil/verilog/daemon/internal/registry"
	"github.com/ronitspatil/verilog/daemon/internal/signer"
)

// Backend is the subset of an Ethereum client the anchorer needs.
// *ethclient.Client and the simulated backend's client implement it.
type Backend interface {
	bind.ContractBackend
	bind.DeployBackend
	ChainID(ctx context.Context) (*big.Int, error)
	NonceAt(ctx context.Context, account common.Address, blockNumber *big.Int) (uint64, error)
	TransactionByHash(ctx context.Context, hash common.Hash) (*types.Transaction, bool, error)
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
	// is broadcast, and every mined anchor until it is final, so a restarted
	// daemon reuses its nonce instead of anchoring the same root again and
	// still confirms finality before the WAL is compacted.
	PendingFile string
	// Finality decides when a mined anchor is final (zero: finalized).
	Finality finality.Mode
}

// EthChain anchors roots with EIP-1559 transactions to a VeriLogRegistry.
//
// Anchoring is pipelined: once a transaction is mined, the next request may
// be sent while the earlier anchor awaits finality. Nonce ordering stays safe
// because (1) every transaction is persisted before it is broadcast, (2) a new
// transaction never takes a nonce at or below one awaiting finality, and (3) an
// anchor removed by a reorg is answered by broadcasting the same signed
// transaction again (and, if it does not return, replacing it with the same
// nonce and higher fees), so per-agent epochs keep their order. Only when the
// nonce of an anchor ends up used by another transaction in a final block (a
// second user of the anchoring key) is the request anchored again with a new
// nonce.
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
	// mined are the anchors mined but not yet released (final and
	// completed), in the order they were mined. With Options.PendingFile
	// they survive restarts.
	mined []*minedTx
}

type pendingTx struct {
	req    Request
	tx     *types.Transaction // latest version; nil for an anchor recovered from chain state without its transaction
	hashes []common.Hash      // every version sent with this nonce
}

// minedTx is a mined anchor awaiting finality.
type minedTx struct {
	pendingTx
	res     Result
	reorged bool // its nonce is no longer used on the canonical chain
	polls   int  // finality checks since it was reorged out
}

// reorgReplaceAfter is the number of finality checks a reorged-out
// transaction is rebroadcast unchanged before it is replaced with higher fees.
const reorgReplaceAfter = 3

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

// Anchor submits anchorEpoch for req and waits until it is mined. A request
// already mined (before a restart, say) returns its recorded anchor.
func (c *EthChain) Anchor(ctx context.Context, req Request) (Result, error) {
	if m := c.findMined(req); m != nil {
		return m.res, nil
	}
	if c.pending != nil && c.pending.req != req {
		// A transaction for another request is in flight: after a restart
		// the queue order can differ from the order requests were sent in.
		// Its nonce comes first, so it is completed first; its job finds
		// the mined anchor when it comes up.
		c.log.Info("anchor: completing the in-flight transaction of another epoch first",
			"tx", c.pending.tx.Hash(), "nonce", c.pending.tx.Nonce(), "agent_key", common.Hash(c.pending.req.AgentKey))
		if _, err := c.mine(ctx, c.pending.req); err != nil {
			return Result{}, fmt.Errorf("in-flight transaction of another epoch: %w", err)
		}
	}
	return c.mine(ctx, req)
}

func (c *EthChain) mine(ctx context.Context, req Request) (Result, error) {
	// 1. A previous attempt (or an earlier version of it, or one sent before
	//    a restart) may have been mined after we stopped waiting, or may be
	//    preconfirmed: it is about to land, so it is awaited, not replaced.
	res, ok, preconf, err := c.pendingReceipt(ctx, req)
	if err != nil || ok {
		return res, err
	}
	if !preconf {
		// 2. The root may already be anchored (e.g. crash after the receipt
		//    but before the mined anchor was recorded).
		if res, ok, err := c.alreadyAnchored(ctx, req); err != nil || ok {
			return res, err
		}
		// 3. Send (replace, or rebroadcast at the fee ceiling).
		if _, err := c.sendVersion(ctx, req, c.pending, func(p *pendingTx) error {
			c.pending = p
			return c.save()
		}); err != nil {
			return Result{}, err
		}
	}
	// 4. Wait until a version is in a canonical block.
	wctx, cancel := context.WithTimeout(ctx, c.opts.ConfirmTimeout)
	defer cancel()
	rcpt, err := c.awaitCanonical(wctx, c.pending.hashes)
	if err != nil {
		return Result{}, fmt.Errorf("awaiting confirmation of %s: %w", c.pending.tx.Hash(), err)
	}
	return c.recordMined(req, rcpt)
}

// receiptPoll is how often awaitCanonical asks for a receipt.
const receiptPoll = time.Second

// awaitCanonical polls until one of hashes has a canonical receipt.
func (c *EthChain) awaitCanonical(ctx context.Context, hashes []common.Hash) (*types.Receipt, error) {
	t := time.NewTicker(receiptPoll)
	defer t.Stop()
	for {
		rcpt, _, err := c.receiptOf(ctx, hashes)
		if err == nil && rcpt != nil {
			return rcpt, nil
		}
		if err != nil {
			c.log.Debug("anchor: reading the receipt", "err", err)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-t.C:
		}
	}
}

// pendingReceipt looks for a canonical receipt of any version of the
// pending transaction of req. preconf reports a receipt that is not (yet)
// in a canonical block.
func (c *EthChain) pendingReceipt(ctx context.Context, req Request) (res Result, ok, preconf bool, err error) {
	if c.pending == nil || c.pending.req != req {
		return Result{}, false, false, nil
	}
	rcpt, preconf, err := c.receiptOf(ctx, c.pending.hashes)
	if err != nil || rcpt == nil {
		return Result{}, false, preconf, err
	}
	res, err = c.recordMined(req, rcpt)
	return res, true, false, err
}

// receiptOf returns the receipt of whichever of hashes is mined in a
// canonical block, or nil. A receipt counts only if its block hash is set
// and the canonical header at its number has that hash: RPC endpoints that
// serve preconfirmations (Base flashblocks) return receipts with a zero
// block hash for transactions not yet in a sealed block, and a lagging or
// reorging node can return a receipt from a block no longer canonical.
// preconf reports such a receipt: the transaction is pending, not mined and
// not reorged out.
func (c *EthChain) receiptOf(ctx context.Context, hashes []common.Hash) (rcpt *types.Receipt, preconf bool, err error) {
	for _, h := range hashes {
		r, err := c.backend.TransactionReceipt(ctx, h)
		switch {
		case errors.Is(err, ethereum.NotFound):
			continue
		case err != nil:
			return nil, preconf, fmt.Errorf("receipt of %s: %w", h, err)
		}
		ok, err := c.canonical(ctx, r.BlockNumber, r.BlockHash)
		if err != nil {
			return nil, preconf, err
		}
		if ok {
			return r, false, nil
		}
		preconf = true
	}
	return nil, preconf, nil
}

// canonical reports whether the block hash is the canonical block at
// number. A zero hash, a missing number or a missing block is not.
func (c *EthChain) canonical(ctx context.Context, number *big.Int, hash common.Hash) (bool, error) {
	if hash == (common.Hash{}) || number == nil {
		return false, nil
	}
	h, err := c.backend.HeaderByNumber(ctx, number)
	switch {
	case errors.Is(err, ethereum.NotFound):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("reading block %s: %w", number, err)
	}
	return h.Hash() == hash, nil
}

// resultFrom checks a receipt of req's transaction and reads its anchor.
func (c *EthChain) resultFrom(req Request, rcpt *types.Receipt) (Result, error) {
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
		return Result{EpochID: ev.EpochId.Uint64(), TxHash: rcpt.TxHash.Hex(),
			BlockNumber: rcpt.BlockNumber.Uint64(), BlockHash: rcpt.BlockHash.Hex()}, nil
	}
	return Result{}, fmt.Errorf("receipt of %s has no matching LogAnchored event", rcpt.TxHash)
}

// recordMined turns the pending transaction of req into a mined anchor
// awaiting finality, in one write of the pending record.
func (c *EthChain) recordMined(req Request, rcpt *types.Receipt) (Result, error) {
	res, err := c.resultFrom(req, rcpt)
	if err != nil {
		if cerr := c.clearPending(); cerr != nil {
			return Result{}, cerr
		}
		return Result{}, err
	}
	m := &minedTx{pendingTx: pendingTx{req: req, hashes: []common.Hash{rcpt.TxHash}}, res: res}
	if c.pending != nil && c.pending.req == req {
		m.pendingTx = *c.pending
	}
	c.pending, c.nonceGone = nil, 0
	c.mined = append(c.mined, m)
	if err := c.save(); err != nil {
		return Result{}, err
	}
	c.log.Info("anchor: transaction mined, awaiting finality", "tx", res.TxHash, "block", res.BlockNumber,
		"block_hash", res.BlockHash, "epoch", res.EpochID, "finality", c.opts.Finality, "agent_key", common.Hash(req.AgentKey))
	return res, nil
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
	m := &minedTx{pendingTx: pendingTx{req: req}, res: Result{EpochID: latest.Uint64()}}
	if c.pending != nil && c.pending.req == req {
		m.pendingTx = *c.pending
	}
	if it, err := c.contract.FilterLogAnchored(&bind.FilterOpts{Context: ctx}, [][32]byte{req.AgentKey}, []*big.Int{latest}); err != nil {
		c.log.Warn("anchor: root already anchored but its transaction could not be located", "epoch", latest, "err", err)
	} else {
		var raw types.Log
		for it.Next() {
			raw = it.Event.Raw
		}
		it.Close()
		if raw.TxHash != (common.Hash{}) {
			if ok, err := c.canonical(ctx, new(big.Int).SetUint64(raw.BlockNumber), raw.BlockHash); err != nil {
				return Result{}, false, err
			} else if !ok {
				return Result{}, false, fmt.Errorf("root already anchored by %s, which is not in a canonical block yet", raw.TxHash)
			}
			m.res.TxHash, m.res.BlockNumber, m.res.BlockHash = raw.TxHash.Hex(), raw.BlockNumber, raw.BlockHash.Hex()
		}
	}
	if m.res.TxHash != "" && (m.tx == nil || !containsHash(m.hashes, common.HexToHash(m.res.TxHash))) {
		// Keep the transaction that holds the anchor, to resend it after a reorg.
		m.tx, m.hashes = nil, []common.Hash{common.HexToHash(m.res.TxHash)}
		if tx, _, err := c.backend.TransactionByHash(ctx, common.HexToHash(m.res.TxHash)); err == nil {
			m.tx = tx
		}
	}
	c.pending, c.nonceGone = nil, 0
	c.mined = append(c.mined, m)
	if err := c.save(); err != nil {
		return Result{}, false, err
	}
	c.log.Info("anchor: root already anchored on chain, recovering", "epoch", latest, "tx", m.res.TxHash, "block", m.res.BlockNumber)
	return m.res, true, nil
}

func containsHash(hs []common.Hash, h common.Hash) bool {
	for _, x := range hs {
		if x == h {
			return true
		}
	}
	return false
}

func (c *EthChain) findMined(req Request) *minedTx {
	for _, m := range c.mined {
		if m.req == req {
			return m
		}
	}
	return nil
}

// nextNonce is the lowest nonce a new transaction may take: above the
// in-flight transaction and every anchor awaiting finality, so a reorg never
// hands a later epoch the nonce (and the place) of an earlier one, and a
// node whose nonce view lags (a preconfirmation not yet counted) never makes
// a new transaction reuse the nonce of one that may still land.
func (c *EthChain) nextNonce() uint64 {
	var n uint64
	if c.pending != nil && c.pending.tx != nil {
		n = c.pending.tx.Nonce() + 1
	}
	for _, m := range c.mined {
		if m.tx != nil {
			n = max(n, m.tx.Nonce()+1)
		}
	}
	return n
}

// Final reports whether the mined anchor of req is final. Before saying so
// it checks that the transaction is in a canonical block at or below the
// final block and re-reads agentAnchors(agentId, epochId) at the final
// block. It also resends every anchor a reorg removed.
func (c *EthChain) Final(ctx context.Context, req Request) (Status, Result, error) {
	m := c.findMined(req)
	if m == nil {
		return Reanchor, Result{}, nil
	}
	point, err := c.opts.Finality.Point(ctx, c.backend)
	if err != nil {
		return Pending, m.res, err
	}
	if err := c.resendReorged(ctx); err != nil {
		return Pending, m.res, err
	}
	if m.tx == nil {
		return c.finalFromState(ctx, m, point)
	}
	rcpt, _, err := c.receiptOf(ctx, m.hashes)
	if err != nil {
		return Pending, m.res, err
	}
	if rcpt == nil {
		used, err := c.backend.NonceAt(ctx, c.from, point.Number)
		if err != nil {
			return Pending, m.res, fmt.Errorf("reading the final nonce: %w", err)
		}
		if used > m.tx.Nonce() {
			c.log.Error("anchor: the anchor's nonce was used by another transaction in a final block; anchoring the epoch again "+
				"(is another process using the anchoring key?)", "nonce", m.tx.Nonce(), "tx", m.res.TxHash, "epoch", m.res.EpochID,
				"agent_key", common.Hash(req.AgentKey))
			return c.drop(m)
		}
		return Pending, m.res, nil
	}
	if rcpt.BlockHash.Hex() != m.res.BlockHash {
		res, err := c.resultFrom(req, rcpt)
		if err != nil {
			c.log.Error("anchor: after a reorg the anchor transaction no longer anchors the root; anchoring the epoch again",
				"tx", rcpt.TxHash, "block", rcpt.BlockNumber, "block_hash", rcpt.BlockHash, "err", err)
			return c.drop(m)
		}
		if knownBlock(m.res) {
			c.log.Warn("anchor: reorg moved the anchor transaction to another block", "tx", res.TxHash,
				"old_block", m.res.BlockNumber, "old_block_hash", m.res.BlockHash, "old_epoch", m.res.EpochID,
				"new_block", res.BlockNumber, "new_block_hash", res.BlockHash, "new_epoch", res.EpochID)
		} else { // recorded from a preconfirmation by an earlier version
			c.log.Info("anchor: anchor transaction sealed", "tx", res.TxHash,
				"block", res.BlockNumber, "block_hash", res.BlockHash, "epoch", res.EpochID)
		}
		m.res, m.reorged, m.polls = res, false, 0
		if err := c.save(); err != nil {
			return Pending, m.res, err
		}
	}
	if rcpt.BlockNumber.Cmp(point.Number) > 0 {
		return Pending, m.res, nil
	}
	return c.confirmAt(ctx, m, point)
}

// confirmAt re-reads the anchor at the final block: Final if it matches.
func (c *EthChain) confirmAt(ctx context.Context, m *minedTx, point *types.Header) (Status, Result, error) {
	ok, err := c.anchoredAt(ctx, m.req, m.res.EpochID, point.Number)
	if err != nil {
		return Pending, m.res, err
	}
	if !ok {
		c.log.Error("anchor: the anchor read at the final block does not match the receipt; anchoring the epoch again",
			"epoch", m.res.EpochID, "tx", m.res.TxHash, "block", m.res.BlockNumber, "final_block", point.Number,
			"final_block_hash", point.Hash(), "agent_key", common.Hash(m.req.AgentKey), "root", common.Hash(m.req.Root))
		return c.drop(m)
	}
	// The final block must still be canonical after the read (depth mode).
	if h, err := c.backend.HeaderByNumber(ctx, point.Number); err != nil {
		return Pending, m.res, fmt.Errorf("reading block %s: %w", point.Number, err)
	} else if h.Hash() != point.Hash() {
		return Pending, m.res, nil
	}
	res := m.res
	res.Finality = c.opts.Finality.String()
	res.FinalBlockNumber = point.Number.Uint64()
	res.FinalBlockHash = point.Hash().Hex()
	return Final, res, nil
}

// finalFromState judges an anchor recovered without its transaction by
// chain state alone.
func (c *EthChain) finalFromState(ctx context.Context, m *minedTx, point *types.Header) (Status, Result, error) {
	if ok, err := c.anchoredAt(ctx, m.req, m.res.EpochID, point.Number); err != nil {
		return Pending, m.res, err
	} else if ok {
		return c.confirmAt(ctx, m, point)
	}
	if ok, err := c.anchoredAt(ctx, m.req, m.res.EpochID, nil); err != nil || ok {
		return Pending, m.res, err
	}
	c.log.Warn("anchor: reorg removed an anchor recovered from chain state; anchoring the epoch again",
		"epoch", m.res.EpochID, "tx", m.res.TxHash, "block", m.res.BlockNumber, "block_hash", m.res.BlockHash)
	return c.drop(m)
}

// anchoredAt reports whether agentAnchors(agentId, epoch) at block holds
// req's root and count (block nil: the head).
func (c *EthChain) anchoredAt(ctx context.Context, req Request, epoch uint64, block *big.Int) (bool, error) {
	a, err := c.contract.AgentAnchors(&bind.CallOpts{Context: ctx, BlockNumber: block}, req.AgentKey, new(big.Int).SetUint64(epoch))
	if err != nil {
		return false, fmt.Errorf("reading agentAnchors at block %v: %w", block, err)
	}
	return a.MerkleRoot == req.Root && a.LogCount == req.Count, nil
}

// knownBlock reports whether res records a block hash (an anchor recorded
// by an earlier version from a preconfirmation receipt has none).
func knownBlock(res Result) bool {
	return res.BlockHash != "" && common.HexToHash(res.BlockHash) != (common.Hash{})
}

// reorgedOut reports whether a reorg removed the mined anchor m: none of its
// versions has a canonical receipt or a preconfirmation receipt, and the
// block it was recorded in is no longer canonical. The account nonce at the
// head is not used: endpoints serving preconfirmations report a mined
// transaction before the "latest" nonce counts it.
func (c *EthChain) reorgedOut(ctx context.Context, m *minedTx) (bool, error) {
	rcpt, preconf, err := c.receiptOf(ctx, m.hashes)
	if err != nil || rcpt != nil || preconf {
		return false, err
	}
	if !knownBlock(m.res) {
		return false, nil
	}
	ok, err := c.canonical(ctx, new(big.Int).SetUint64(m.res.BlockNumber), common.HexToHash(m.res.BlockHash))
	return !ok && err == nil, err
}

// resendReorged finds the mined anchors a reorg removed, logs each once at
// WARN, and sends the same signed transaction again. If the oldest has not
// returned after a few checks, it is replaced (same nonce, higher fees).
func (c *EthChain) resendReorged(ctx context.Context) error {
	var withTx []*minedTx
	for _, m := range c.mined {
		if m.tx != nil {
			withTx = append(withTx, m)
		}
	}
	sort.Slice(withTx, func(i, j int) bool { return withTx[i].tx.Nonce() < withTx[j].tx.Nonce() })
	first := true
	for _, m := range withTx {
		gone, err := c.reorgedOut(ctx, m)
		if err != nil {
			return err
		}
		if !gone {
			m.reorged, m.polls = false, 0 // the receipt check decides by which transaction
			continue
		}
		if !m.reorged {
			canonical := "none"
			if h, err := c.backend.HeaderByNumber(ctx, new(big.Int).SetUint64(m.res.BlockNumber)); err == nil {
				canonical = h.Hash().Hex()
			}
			c.log.Warn("anchor: reorg removed the anchor transaction; sending it again", "tx", m.res.TxHash,
				"nonce", m.tx.Nonce(), "block", m.res.BlockNumber, "block_hash", m.res.BlockHash,
				"canonical_block_hash", canonical, "epoch", m.res.EpochID, "agent_key", common.Hash(m.req.AgentKey))
			m.reorged = true
		}
		m.polls++
		if first && m.polls > reorgReplaceAfter {
			m.polls = 0
			if _, err := c.sendVersion(ctx, m.req, &m.pendingTx, func(p *pendingTx) error {
				m.pendingTx = *p
				return c.save()
			}); err != nil {
				c.log.Warn("anchor: replacing a reorged-out transaction failed", "nonce", m.tx.Nonce(), "err", err)
			}
		} else if err := c.broadcast(ctx, m.tx, nil); err != nil {
			c.log.Debug("anchor: resending a reorged-out transaction", "tx", m.tx.Hash(), "err", err)
		}
		first = false
	}
	return nil
}

// drop forgets a mined anchor that is gone for good.
func (c *EthChain) drop(m *minedTx) (Status, Result, error) {
	if err := c.forget(m.req); err != nil {
		return Pending, m.res, err
	}
	return Reanchor, m.res, nil
}

func (c *EthChain) forget(req Request) error {
	for i, m := range c.mined {
		if m.req == req {
			c.mined = append(c.mined[:i], c.mined[i+1:]...)
			return c.save()
		}
	}
	return nil
}

// Release forgets req's anchor once its job is complete.
func (c *EthChain) Release(req Request) error { return c.forget(req) }

// Retain forgets the anchors of requests that are no longer queued: their
// jobs completed before a crash that came before Release.
func (c *EthChain) Retain(reqs []Request) error {
	keep := make(map[Request]bool, len(reqs))
	for _, r := range reqs {
		keep[r] = true
	}
	kept := c.mined[:0]
	for _, m := range c.mined {
		if keep[m.req] {
			kept = append(kept, m)
		} else {
			c.log.Info("anchor: forgetting the anchor of a completed epoch", "epoch", m.res.EpochID, "tx", m.res.TxHash)
		}
	}
	if len(kept) == len(c.mined) {
		return nil
	}
	c.mined = kept
	return c.save()
}

// sendVersion signs and broadcasts anchorEpoch for req. When prev (an
// unmined transaction for req) is set, it is replaced (same nonce, fees
// +25%); if the fee ceiling leaves no room for a valid replacement, prev is
// rebroadcast unchanged instead. A new version is handed to install, which
// must persist it, before it is broadcast.
func (c *EthChain) sendVersion(ctx context.Context, req Request, prev *pendingTx, install func(*pendingTx) error) (*types.Transaction, error) {
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
	if prev != nil {
		old := prev.tx
		nonce = old.Nonce()
		tip = maxBig(tip, bump(old.GasTipCap()))
		feeCap = maxBig(feeCap, bump(old.GasFeeCap()))
	} else if nonce, err = c.backend.PendingNonceAt(ctx, c.from); err != nil {
		return nil, fmt.Errorf("reading nonce: %w", err)
	} else {
		nonce = max(nonce, c.nextNonce())
	}
	tip, feeCap, capped := c.applyCeiling(tip, feeCap)
	if prev != nil {
		old := prev.tx
		if tip.Cmp(minReplacement(old.GasTipCap())) < 0 || feeCap.Cmp(minReplacement(old.GasFeeCap())) < 0 {
			c.log.Error("anchor: fee ceiling reached; not bumping fees, waiting for the pending transaction",
				"tx", old.Hash(), "nonce", nonce, "tip_wei", old.GasTipCap(), "max_fee_wei", old.GasFeeCap(),
				"base_fee_wei", head.BaseFee, "agent_key", common.Hash(req.AgentKey), "root", common.Hash(req.Root))
			if err := c.broadcast(ctx, old, prev); err != nil {
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
	if prev != nil {
		p.hashes = append(p.hashes, prev.hashes...)
	}
	p.hashes = append(p.hashes, tx.Hash())
	if err := install(p); err != nil { // before the broadcast: never send what a restart cannot see
		return nil, err
	}
	if err := c.broadcast(ctx, tx, p); err != nil {
		return nil, err
	}
	c.log.Info("anchor: transaction sent", "tx", tx.Hash(), "nonce", tx.Nonce(), "replaces", len(p.hashes)-1,
		"tip_wei", tip, "max_fee_wei", feeCap, "agent_key", common.Hash(req.AgentKey), "root", common.Hash(req.Root), "count", req.Count)
	return tx, nil
}

// broadcast sends tx. "Already known" is success. "Nonce too low" means the
// nonce was used: by a version of this transaction (whose receipt the next
// attempt finds) or, if no version is ever mined, by another transaction. In
// that case the in-flight transaction (p is c.pending) is dropped on the
// second consecutive such answer and the next attempt starts with a fresh
// nonce. Anchors awaiting finality are never dropped here: Final decides.
func (c *EthChain) broadcast(ctx context.Context, tx *types.Transaction, p *pendingTx) error {
	err := c.backend.SendTransaction(ctx, tx)
	if err == nil || strings.Contains(err.Error(), "already known") {
		if p != nil && p == c.pending {
			c.nonceGone = 0
		}
		return nil
	}
	if strings.Contains(strings.ToLower(err.Error()), "nonce too low") && p != nil && p == c.pending {
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
