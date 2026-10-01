// Package signer provides the anchoring key behind a small interface, so the
// daemon can sign transactions with a local secp256k1 key (development) or
// with a key that never leaves AWS KMS (production).
package signer

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// Signer signs 32-byte digests with the anchoring key.
type Signer interface {
	// Address is the Ethereum address of the key.
	Address() common.Address
	// SignHash returns a 65-byte [R || S || V] signature over hash with
	// V in {0, 1} and S in the lower half of the curve order (EIP-2), the
	// format go-ethereum's Transaction.WithSignature expects.
	SignHash(ctx context.Context, hash [32]byte) ([]byte, error)
}

// Local signs with an in-memory private key.
type Local struct {
	key  *ecdsa.PrivateKey
	addr common.Address
}

// NewLocal wraps key.
func NewLocal(key *ecdsa.PrivateKey) *Local {
	return &Local{key: key, addr: crypto.PubkeyToAddress(key.PublicKey)}
}

// Address implements Signer.
func (l *Local) Address() common.Address { return l.addr }

// SignHash implements Signer.
func (l *Local) SignHash(_ context.Context, hash [32]byte) ([]byte, error) {
	return crypto.Sign(hash[:], l.key)
}

// TransactOpts returns transaction options whose Signer signs with s for
// chainID (EIP-1559 and legacy transactions alike). ctx bounds each signing
// call; bind.TransactOpts.Signer itself takes no context.
func TransactOpts(ctx context.Context, s Signer, chainID *big.Int) (*bind.TransactOpts, error) {
	if chainID == nil {
		return nil, errors.New("signer: nil chain id")
	}
	txSigner := types.LatestSignerForChainID(chainID)
	from := s.Address()
	return &bind.TransactOpts{
		From:    from,
		Context: ctx,
		Signer: func(addr common.Address, tx *types.Transaction) (*types.Transaction, error) {
			if addr != from {
				return nil, bind.ErrNotAuthorized
			}
			sig, err := s.SignHash(ctx, txSigner.Hash(tx))
			if err != nil {
				return nil, err
			}
			signed, err := tx.WithSignature(txSigner, sig)
			if err != nil {
				return nil, fmt.Errorf("signer: applying signature: %w", err)
			}
			// Defence in depth: the recovered sender must be our address.
			if got, err := types.Sender(txSigner, signed); err != nil || got != from {
				return nil, fmt.Errorf("signer: signature recovers to %s, want %s (%v)", got, from, err)
			}
			return signed, nil
		},
	}, nil
}
