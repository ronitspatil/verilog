// Package kmsfake is an in-memory stand-in for the AWS KMS signing API, for
// tests only. It holds a secp256k1 key and returns real DER
// SubjectPublicKeyInfo and DER ECDSA signatures, so the signer's parsing,
// low-s normalization and recovery code runs exactly as against KMS.
package kmsfake

import (
	"context"
	"crypto/ecdsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// Fake implements signer.KMSClient.
type Fake struct {
	mu sync.Mutex

	Key      *ecdsa.PrivateKey
	KeyID    string
	KeySpec  kmstypes.KeySpec
	KeyUsage kmstypes.KeyUsageType
	// HighS selects, per Sign call (0-based), whether to return the
	// high-s form of the signature. Nil alternates low, high, low, ...
	HighS func(call int) bool

	// Errors returned by the next calls, consumed in order.
	GetPublicKeyErrs []error
	SignErrs         []error

	GetPublicKeyCalls int
	SignCalls         int
	HighSReturned     int // signatures returned in high-s form
}

// New returns a fake holding a fresh key with the right spec and usage.
func New(keyID string) *Fake {
	key, err := crypto.GenerateKey()
	if err != nil {
		panic(err)
	}
	return &Fake{Key: key, KeyID: keyID, KeySpec: kmstypes.KeySpecEccSecgP256k1, KeyUsage: kmstypes.KeyUsageTypeSignVerify}
}

// MarshalSPKI encodes a secp256k1 public key as DER SubjectPublicKeyInfo,
// the format KMS GetPublicKey returns.
func MarshalSPKI(pub *ecdsa.PublicKey) []byte {
	type algo struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.ObjectIdentifier
	}
	point := crypto.FromECDSAPub(pub)
	der, err := asn1.Marshal(struct {
		Algorithm algo
		PublicKey asn1.BitString
	}{
		Algorithm: algo{asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}, asn1.ObjectIdentifier{1, 3, 132, 0, 10}},
		PublicKey: asn1.BitString{Bytes: point, BitLength: 8 * len(point)},
	})
	if err != nil {
		panic(err)
	}
	return der
}

func (f *Fake) checkKey(id *string) error {
	if aws.ToString(id) != f.KeyID {
		return &kmstypes.NotFoundException{Message: aws.String(fmt.Sprintf("key %q does not exist", aws.ToString(id)))}
	}
	return nil
}

// GetPublicKey implements signer.KMSClient.
func (f *Fake) GetPublicKey(ctx context.Context, in *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.GetPublicKeyCalls++
	if len(f.GetPublicKeyErrs) > 0 {
		err := f.GetPublicKeyErrs[0]
		f.GetPublicKeyErrs = f.GetPublicKeyErrs[1:]
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := f.checkKey(in.KeyId); err != nil {
		return nil, err
	}
	return &kms.GetPublicKeyOutput{
		KeyId:             aws.String(f.KeyID),
		KeySpec:           f.KeySpec,
		KeyUsage:          f.KeyUsage,
		PublicKey:         MarshalSPKI(&f.Key.PublicKey),
		SigningAlgorithms: []kmstypes.SigningAlgorithmSpec{kmstypes.SigningAlgorithmSpecEcdsaSha256},
	}, nil
}

// Sign implements signer.KMSClient for MessageType DIGEST and ECDSA_SHA_256.
func (f *Fake) Sign(ctx context.Context, in *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	call := f.SignCalls
	f.SignCalls++
	if len(f.SignErrs) > 0 {
		err := f.SignErrs[0]
		f.SignErrs = f.SignErrs[1:]
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := f.checkKey(in.KeyId); err != nil {
		return nil, err
	}
	if in.MessageType != kmstypes.MessageTypeDigest || in.SigningAlgorithm != kmstypes.SigningAlgorithmSpecEcdsaSha256 {
		return nil, &kmstypes.InvalidKeyUsageException{Message: aws.String("fake supports only DIGEST / ECDSA_SHA_256")}
	}
	if len(in.Message) != 32 {
		return nil, errors.New("ValidationException: digest must be 32 bytes")
	}
	sig, err := crypto.Sign(in.Message, f.Key) // [R || S || V], low-s
	if err != nil {
		return nil, err
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:64])
	high := call%2 == 1
	if f.HighS != nil {
		high = f.HighS(call)
	}
	if high {
		s.Sub(crypto.S256().Params().N, s)
		f.HighSReturned++
	}
	der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		return nil, err
	}
	return &kms.SignOutput{
		KeyId:            aws.String(f.KeyID),
		Signature:        der,
		SigningAlgorithm: kmstypes.SigningAlgorithmSpecEcdsaSha256,
	}, nil
}
