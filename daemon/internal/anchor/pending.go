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

// pendingVersion is the current record format: 2 adds the anchors mined but
// not yet final. Version 1 (the in-flight transaction only, at top level) is
// still read.
const pendingVersion = 2

// pendingFile is the on-disk form of the anchorer's state: the in-flight
// transaction and the anchors awaiting finality. Signed transactions are
// public once broadcast, so the file holds no secret.
type pendingFile struct {
	Version  int            `json:"version"`
	ChainID  string         `json:"chain_id"`
	Contract common.Address `json:"contract"`
	From     common.Address `json:"from"`
	// Pending is the in-flight transaction, not mined yet.
	Pending *txRecord `json:"pending,omitempty"`
	// Mined are the anchors mined but not yet final (or not yet released),
	// in the order they were mined.
	Mined []minedRecord `json:"mined,omitempty"`
}

type txRecord struct {
	AgentKey  common.Hash   `json:"agent_key"`
	Root      common.Hash   `json:"root"`
	Count     uint32        `json:"count"`
	Nonce     uint64        `json:"nonce"`
	GasTipCap *hexutil.Big  `json:"gas_tip_cap,omitempty"`
	GasFeeCap *hexutil.Big  `json:"gas_fee_cap,omitempty"`
	TxHash    common.Hash   `json:"tx_hash"`          // latest version
	TxHashes  []common.Hash `json:"tx_hashes"`        // every version sent with this nonce
	RawTx     hexutil.Bytes `json:"raw_tx,omitempty"` // latest version, signed; empty if unknown
}

type minedRecord struct {
	txRecord
	EpochID     uint64      `json:"epoch_id"`
	MinedTxHash common.Hash `json:"mined_tx_hash"` // the version that was mined
	BlockNumber uint64      `json:"block_number"`
	BlockHash   common.Hash `json:"block_hash"`
}

// pendingRecordV1 is the version 1 format.
type pendingRecordV1 struct {
	txRecord
	Version  int            `json:"version"`
	ChainID  string         `json:"chain_id"`
	Contract common.Address `json:"contract"`
	From     common.Address `json:"from"`
}

func toRecord(p *pendingTx) (txRecord, error) {
	r := txRecord{AgentKey: p.req.AgentKey, Root: p.req.Root, Count: p.req.Count, TxHashes: p.hashes}
	if p.tx != nil {
		raw, err := p.tx.MarshalBinary()
		if err != nil {
			return r, fmt.Errorf("anchor: encoding pending transaction: %w", err)
		}
		r.Nonce, r.TxHash, r.RawTx = p.tx.Nonce(), p.tx.Hash(), raw
		r.GasTipCap, r.GasFeeCap = (*hexutil.Big)(p.tx.GasTipCap()), (*hexutil.Big)(p.tx.GasFeeCap())
	}
	return r, nil
}

func (c *EthChain) fromRecord(r txRecord) (pendingTx, error) {
	p := pendingTx{req: Request{AgentKey: r.AgentKey, Root: r.Root, Count: r.Count}, hashes: r.TxHashes}
	if len(r.RawTx) > 0 {
		tx := new(types.Transaction)
		if err := tx.UnmarshalBinary(r.RawTx); err != nil {
			return p, fmt.Errorf("anchor: decoding pending transaction in %s: %w", c.opts.PendingFile, err)
		}
		if tx.Hash() != r.TxHash || tx.Nonce() != r.Nonce {
			return p, fmt.Errorf("anchor: pending transaction in %s does not match its record", c.opts.PendingFile)
		}
		p.tx = tx
		if len(p.hashes) == 0 {
			p.hashes = []common.Hash{r.TxHash}
		}
	}
	return p, nil
}

// save persists the in-flight transaction and the mined anchors, or removes
// the record when there are none.
func (c *EthChain) save() error {
	if c.opts.PendingFile == "" {
		return nil
	}
	if c.pending == nil && len(c.mined) == 0 {
		if err := os.Remove(c.opts.PendingFile); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("anchor: removing pending transaction record: %w", err)
		}
		return nil
	}
	f := pendingFile{Version: pendingVersion, ChainID: c.chainID.String(), Contract: c.address, From: c.from}
	if c.pending != nil {
		r, err := toRecord(c.pending)
		if err != nil {
			return err
		}
		f.Pending = &r
	}
	for _, m := range c.mined {
		r, err := toRecord(&m.pendingTx)
		if err != nil {
			return err
		}
		f.Mined = append(f.Mined, minedRecord{txRecord: r, EpochID: m.res.EpochID, MinedTxHash: common.HexToHash(m.res.TxHash),
			BlockNumber: m.res.BlockNumber, BlockHash: common.HexToHash(m.res.BlockHash)})
	}
	b, err := json.MarshalIndent(f, "", "  ")
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

// clearPending forgets the in-flight transaction.
func (c *EthChain) clearPending() error {
	c.pending = nil
	c.nonceGone = 0
	return c.save()
}

// loadPending restores the in-flight transaction and the anchors awaiting
// finality of a previous run. A record for another chain, contract or signer
// is set aside (renamed) with a warning: its nonces belong to a different
// account or chain.
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
	var f pendingFile
	err = json.Unmarshal(b, &f)
	if err == nil && f.Version == 1 {
		var v1 pendingRecordV1
		if err = json.Unmarshal(b, &v1); err == nil {
			f.Pending = &v1.txRecord
		}
	}
	if err != nil || (f.Version != 1 && f.Version != pendingVersion) {
		return fmt.Errorf("anchor: %s is unreadable (version %d, %v); inspect it before removing it", c.opts.PendingFile, f.Version, err)
	}
	if f.ChainID != c.chainID.String() || f.Contract != c.address || f.From != c.from {
		aside := c.opts.PendingFile + ".stale"
		c.log.Warn("anchor: pending transaction belongs to another chain, contract or signer; setting it aside",
			"file", aside, "chain_id", f.ChainID, "contract", f.Contract, "from", f.From)
		return os.Rename(c.opts.PendingFile, aside)
	}
	if f.Pending != nil {
		p, err := c.fromRecord(*f.Pending)
		if err != nil {
			return err
		}
		if p.tx == nil {
			return fmt.Errorf("anchor: pending transaction in %s has no signed transaction", c.opts.PendingFile)
		}
		c.pending = &p
		c.log.Info("anchor: resuming pending transaction from a previous run", "tx", p.tx.Hash(), "nonce", p.tx.Nonce(),
			"versions", len(p.hashes), "agent_key", f.Pending.AgentKey, "root", f.Pending.Root)
	}
	for _, r := range f.Mined {
		p, err := c.fromRecord(r.txRecord)
		if err != nil {
			return err
		}
		m := &minedTx{pendingTx: p, res: Result{EpochID: r.EpochID, BlockNumber: r.BlockNumber}}
		if r.MinedTxHash != (common.Hash{}) {
			m.res.TxHash = r.MinedTxHash.Hex()
		}
		if r.BlockHash != (common.Hash{}) {
			m.res.BlockHash = r.BlockHash.Hex()
		}
		c.mined = append(c.mined, m)
		c.log.Info("anchor: resuming an anchor awaiting finality from a previous run", "tx", m.res.TxHash,
			"block", r.BlockNumber, "epoch", r.EpochID, "agent_key", r.AgentKey)
	}
	return nil
}
