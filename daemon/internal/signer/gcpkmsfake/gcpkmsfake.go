// Package gcpkmsfake is an in-memory stand-in for the Google Cloud KMS
// signing API, for tests only. It holds a secp256k1 key and returns a real
// PEM SubjectPublicKeyInfo and DER ECDSA signatures with correct CRC32C
// checksums, so the signer's integrity checks, parsing, low-s normalization
// and recovery code run exactly as against Cloud KMS. Corruption modes
// exercise the checksum checks.
package gcpkmsfake

import (
	"context"
	"crypto/ecdsa"
	"encoding/asn1"
	"encoding/pem"
	"hash/crc32"
	"math/big"
	"sync"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/ronitspatil/verilog/daemon/internal/signer/kmsfake"
)

// Corruption damages one response so a checksum check fails.
type Corruption int

const (
	None Corruption = iota
	// PEM flips a byte of the returned PEM (its CRC32C no longer matches).
	PEM
	// PEMChecksum returns a wrong pem_crc32c.
	PEMChecksum
	// Signature flips a byte of the signature (its CRC32C no longer matches).
	Signature
	// SignatureChecksum returns a wrong signature_crc32c.
	SignatureChecksum
	// DigestUnverified reports verified_digest_crc32c = false.
	DigestUnverified
	// Name returns another key version's name.
	Name
)

// Fake implements signer.GCPKMSClient.
type Fake struct {
	mu sync.Mutex

	Key             *ecdsa.PrivateKey
	Name            string // full CryptoKeyVersion resource name
	Algorithm       kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
	ProtectionLevel kmspb.ProtectionLevel
	// State other than ENABLED makes every call fail with FAILED_PRECONDITION.
	State kmspb.CryptoKeyVersion_CryptoKeyVersionState
	// HighS selects, per AsymmetricSign call (0-based), whether to return
	// the high-s form of the signature. Nil alternates low, high, low, ...
	HighS func(call int) bool

	// Errors and corruptions applied to the next calls, consumed in order.
	GetPublicKeyErrs        []error
	SignErrs                []error
	GetPublicKeyCorruptions []Corruption
	SignCorruptions         []Corruption

	GetPublicKeyCalls int
	SignCalls         int
	HighSReturned     int      // signatures returned in high-s form
	Digests           [][]byte // the SHA-256 digests passed to AsymmetricSign, in order
}

// New returns a fake holding a fresh key: an enabled HSM
// EC_SIGN_SECP256K1_SHA256 key version.
func New(name string) *Fake {
	key, err := crypto.GenerateKey()
	if err != nil {
		panic(err)
	}
	return &Fake{
		Key:             key,
		Name:            name,
		Algorithm:       kmspb.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256,
		ProtectionLevel: kmspb.ProtectionLevel_HSM,
		State:           kmspb.CryptoKeyVersion_ENABLED,
	}
}

// MarshalPEM encodes a secp256k1 public key as a PEM SubjectPublicKeyInfo,
// the format Cloud KMS GetPublicKey returns.
func MarshalPEM(pub *ecdsa.PublicKey) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: kmsfake.MarshalSPKI(pub)}))
}

func crc(b []byte) int64 { return int64(crc32.Checksum(b, crc32.MakeTable(crc32.Castagnoli))) }

func pop[T any](q *[]T) (T, bool) {
	var zero T
	if len(*q) == 0 {
		return zero, false
	}
	v := (*q)[0]
	*q = (*q)[1:]
	return v, true
}

func (f *Fake) check(ctx context.Context, name string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if name != f.Name {
		return status.Errorf(codes.NotFound, "CryptoKeyVersion %s not found.", name)
	}
	if f.State != kmspb.CryptoKeyVersion_ENABLED {
		return status.Errorf(codes.FailedPrecondition, "%s is not enabled, current state is: %s.", name, f.State)
	}
	return nil
}

// GetPublicKey implements signer.GCPKMSClient.
func (f *Fake) GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest, _ ...gax.CallOption) (*kmspb.PublicKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.GetPublicKeyCalls++
	if err, ok := pop(&f.GetPublicKeyErrs); ok {
		return nil, err
	}
	corrupt, _ := pop(&f.GetPublicKeyCorruptions)
	if err := f.check(ctx, req.GetName()); err != nil {
		return nil, err
	}
	p := MarshalPEM(&f.Key.PublicKey)
	out := &kmspb.PublicKey{
		Pem:             p,
		PemCrc32C:       wrapperspb.Int64(crc([]byte(p))),
		Algorithm:       f.Algorithm,
		Name:            f.Name,
		ProtectionLevel: f.ProtectionLevel,
	}
	switch corrupt {
	case PEM:
		b := []byte(p)
		b[40] ^= 1
		out.Pem = string(b)
	case PEMChecksum:
		out.PemCrc32C = wrapperspb.Int64(out.PemCrc32C.Value ^ 1)
	case Name:
		out.Name = f.Name + "0"
	}
	return out, nil
}

// AsymmetricSign implements signer.GCPKMSClient. Like Cloud KMS, it signs
// the SHA-256 digest exactly as given, without hashing it again.
func (f *Fake) AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest, _ ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	call := f.SignCalls
	f.SignCalls++
	if err, ok := pop(&f.SignErrs); ok {
		return nil, err
	}
	corrupt, _ := pop(&f.SignCorruptions)
	if err := f.check(ctx, req.GetName()); err != nil {
		return nil, err
	}
	if f.Algorithm != kmspb.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256 {
		return nil, status.Errorf(codes.InvalidArgument, "fake supports only EC_SIGN_SECP256K1_SHA256")
	}
	digest := req.GetDigest().GetSha256()
	if len(digest) != 32 || len(req.GetData()) != 0 {
		return nil, status.Error(codes.InvalidArgument, "a 32-byte SHA-256 digest is required")
	}
	verified := false
	if c := req.GetDigestCrc32C(); c != nil {
		if c.Value != crc(digest) {
			return nil, status.Error(codes.InvalidArgument, "The checksum in field digest_crc32c did not match the data in field digest.")
		}
		verified = true
	}
	f.Digests = append(f.Digests, append([]byte(nil), digest...))
	sig, err := crypto.Sign(digest, f.Key) // [R || S || V], low-s
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
	out := &kmspb.AsymmetricSignResponse{
		Signature:            der,
		SignatureCrc32C:      wrapperspb.Int64(crc(der)),
		VerifiedDigestCrc32C: verified,
		Name:                 f.Name,
		ProtectionLevel:      f.ProtectionLevel,
	}
	switch corrupt {
	case Signature:
		out.Signature = append([]byte(nil), der...)
		out.Signature[len(der)-1] ^= 1
	case SignatureChecksum:
		out.SignatureCrc32C = wrapperspb.Int64(out.SignatureCrc32C.Value ^ 1)
	case DigestUnverified:
		out.VerifiedDigestCrc32C = false
	case Name:
		out.Name = f.Name + "0"
	}
	return out, nil
}
