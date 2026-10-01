package anchor

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/ronitspatil/verilog/daemon/internal/store"
)

// PendingFileName is the pending-transaction record inside the data dir.
const PendingFileName = "anchor-pending.json"

// pendingRecord is the on-disk form of pendingTx. The signed transaction is
// public once broadcast, so the file holds no secret.
type pendingRecord struct {
	Version   int            `json:"version"`
	ChainID   string         `json:"chain_id"`
	Contract  common.Address `json:"contract"`
	From      common.Address `json:"from"`
	AgentKey  common.Hash    `json:"agent_key"`
	Root      common.Hash    `json:"root"`
	Count     uint32         `json:"count"`
	Nonce     uint64         `json:"nonce"`
	GasTipCap *hexutil.Big   `json:"gas_tip_cap"`
	GasFeeCap *hexutil.Big   `json:"gas_fee_cap"`
	TxHash    common.Hash    `json:"tx_hash"`   // latest version
	TxHashes  []common.Hash  `json:"tx_hashes"` // every version sent with this nonce
	RawTx     hexutil.Bytes  `json:"raw_tx"`    // latest version, signed
}

func (c *EthChain) savePending(p *pendingTx) error {
	if c.opts.PendingFile == "" {
		return nil
	}
	raw, err := p.tx.MarshalBinary()
	if err != nil {
		return fmt.Errorf("anchor: encoding pending transaction: %w", err)
	}
	b, err := json.MarshalIndent(pendingRecord{
		Version:   1,
		ChainID:   c.chainID.String(),
		Contract:  c.address,
		From:      c.from,
		AgentKey:  p.req.AgentKey,
		Root:      p.req.Root,
		Count:     p.req.Count,
		Nonce:     p.tx.Nonce(),
		GasTipCap: (*hexutil.Big)(p.tx.GasTipCap()),
		GasFeeCap: (*hexutil.Big)(p.tx.GasFeeCap()),
		TxHash:    p.tx.Hash(),
		TxHashes:  p.hashes,
		RawTx:     raw,
	}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.opts.PendingFile), 0o700); err != nil {
		return fmt.Errorf("anchor: persisting pending transaction: %w", err)
	}
	if err := store.WriteFileAtomic(c.opts.PendingFile, append(b, '\n')); err != nil {
		return fmt.Errorf("anchor: persisting pending transaction: %w", err)
	}
	return nil
}

func (c *EthChain) clearPending() error {
	c.pending = nil
	c.nonceGone = 0
	if c.opts.PendingFile == "" {
		return nil
	}
	if err := os.Remove(c.opts.PendingFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("anchor: removing pending transaction record: %w", err)
	}
	return nil
}

// loadPending restores the pending transaction of a previous run. A record
// for another chain, contract or signer is set aside (renamed) with a
// warning: its nonce belongs to a different account or chain.
func (c *EthChain) loadPending() error {
	if c.opts.PendingFile == "" {
		return nil
	}
	b, err := os.ReadFile(c.opts.PendingFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("anchor: reading pending transaction: %w", err)
	}
	var r pendingRecord
	if err := json.Unmarshal(b, &r); err != nil || r.Version != 1 {
		return fmt.Errorf("anchor: %s is unreadable (version %d, %v); inspect it before removing it", c.opts.PendingFile, r.Version, err)
	}
	if r.ChainID != c.chainID.String() || r.Contract != c.address || r.From != c.from {
		aside := c.opts.PendingFile + ".stale"
		c.log.Warn("anchor: pending transaction belongs to another chain, contract or signer; setting it aside",
			"file", aside, "chain_id", r.ChainID, "contract", r.Contract, "from", r.From, "tx", r.TxHash)
		return os.Rename(c.opts.PendingFile, aside)
	}
	tx := new(types.Transaction)
	if err := tx.UnmarshalBinary(r.RawTx); err != nil {
		return fmt.Errorf("anchor: decoding pending transaction in %s: %w", c.opts.PendingFile, err)
	}
	if tx.Hash() != r.TxHash || tx.Nonce() != r.Nonce {
		return fmt.Errorf("anchor: pending transaction in %s does not match its record", c.opts.PendingFile)
	}
	hashes := r.TxHashes
	if len(hashes) == 0 {
		hashes = []common.Hash{r.TxHash}
	}
	c.pending = &pendingTx{req: Request{AgentKey: r.AgentKey, Root: r.Root, Count: r.Count}, tx: tx, hashes: hashes}
	c.log.Info("anchor: resuming pending transaction from a previous run", "tx", r.TxHash, "nonce", r.Nonce,
		"versions", len(hashes), "agent_key", r.AgentKey, "root", r.Root)
	return nil
}
