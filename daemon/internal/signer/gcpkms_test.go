package signer

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/googleapis/gax-go/v2/apierror"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ronitspatil/verilog/daemon/internal/signer/gcpkmsfake"
)

const gcpKey = "projects/verilog-prod/locations/us-east1/keyRings/verilog/cryptoKeys/anchorer/cryptoKeyVersions/1"

func newGCPKMS(t *testing.T, f *gcpkmsfake.Fake) *GCPKMS {
	t.Helper()
	opts := KMSOptions{}
	noSleep(&opts)
	k, err := NewGCPKMS(context.Background(), f, gcpKey, opts)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func gcpErr(c codes.Code) error { return status.Error(c, "simulated "+c.String()) }

func TestGCPKMSAddressAndSignatures(t *testing.T) {
	f := gcpkmsfake.New(gcpKey)
	k := newGCPKMS(t, f)
	want := crypto.PubkeyToAddress(f.Key.PublicKey)
	if k.Address() != want {
		t.Fatalf("address %s, want %s", k.Address(), want)
	}
	if k.ProtectionLevel() != "HSM" {
		t.Fatalf("protection level %s", k.ProtectionLevel())
	}
	if f.GetPublicKeyCalls != 1 || f.SignCalls != 1 {
		t.Fatalf("startup made %d GetPublicKey and %d AsymmetricSign calls, want 1 and 1", f.GetPublicKeyCalls, f.SignCalls)
	}
	f.HighS = func(call int) bool { return call%2 == 0 }
	for i := 0; i < 64; i++ {
		hash := crypto.Keccak256Hash([]byte{byte(i)})
		sig, err := k.SignHash(context.Background(), hash)
		if err != nil {
			t.Fatal(err)
		}
		if len(sig) != 65 || sig[64] > 1 {
			t.Fatalf("bad signature shape %x", sig)
		}
		if new(big.Int).SetBytes(sig[32:64]).Cmp(secp256k1HalfN) > 0 {
			t.Fatalf("signature %d is not low-s", i)
		}
		pub, err := crypto.SigToPub(hash[:], sig)
		if err != nil || crypto.PubkeyToAddress(*pub) != want {
			t.Fatalf("signature %d recovers to the wrong key: %v", i, err)
		}
		local, _ := NewLocal(f.Key).SignHash(context.Background(), hash)
		if !bytes.Equal(local, sig) {
			t.Fatalf("signature %d differs from the local signer", i)
		}
	}
	if f.HighSReturned < 32 {
		t.Fatalf("only %d high-s signatures exercised", f.HighSReturned)
	}
}

// Cloud KMS signs the 32 bytes in Digest.sha256 as given. The signer must
// pass the hash through unchanged (not hash it again): a fixed key and
// digest give a fixed signature.
func TestGCPKMSKnownAnswer(t *testing.T) {
	f := gcpkmsfake.New(gcpKey)
	var err error
	if f.Key, err = crypto.HexToECDSA("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"); err != nil {
		t.Fatal(err)
	}
	f.HighS = func(int) bool { return true } // also exercise normalization
	k := newGCPKMS(t, f)
	if k.Address() != common.HexToAddress("0x2c7536E3605D9C16a7a3D7b1898e529396a65c23") {
		t.Fatalf("address %s", k.Address())
	}
	hash := common.HexToHash("0xa9b26e2c37a9b0d5c7f5e5fa0f3c8f8d1a2b3c4d5e6f708192a3b4c5d6e7f801")
	sig, err := k.SignHash(context.Background(), hash)
	if err != nil {
		t.Fatal(err)
	}
	const want = "adac24268e0bd46d7697ce14365d1a282b1c201ace2626c889129d8d1c5ea95e" +
		"071f0a0db5ef45f8f6f38def50ddf493d30e1b482bd5ce4fbc2dca27a394af19" + "00"
	if hex.EncodeToString(sig) != want {
		t.Fatalf("signature %x, want %s", sig, want)
	}
	if last := f.Digests[len(f.Digests)-1]; !bytes.Equal(last, hash[:]) {
		t.Fatalf("digest sent to KMS %x, want %x", last, hash)
	}
}

func TestGCPKMSTransactOptsSignsTxHashEIP1559(t *testing.T) {
	f := gcpkmsfake.New(gcpKey)
	k := newGCPKMS(t, f)
	chainID := big.NewInt(84532)
	opts, err := TransactOpts(context.Background(), k, chainID)
	if err != nil {
		t.Fatal(err)
	}
	txSigner := types.LatestSignerForChainID(chainID)
	to := common.HexToAddress("0x5FbDB2315678afecb367f032d93F642f64180aa3")
	for i := 0; i < 8; i++ {
		tx := types.NewTx(&types.DynamicFeeTx{ChainID: chainID, Nonce: uint64(i), GasTipCap: big.NewInt(1e9),
			GasFeeCap: big.NewInt(3e9), Gas: 100000, To: &to, Data: []byte{0xde, 0xad, byte(i)}})
		signed, err := opts.Signer(k.Address(), tx)
		if err != nil {
			t.Fatal(err)
		}
		if h := txSigner.Hash(tx); !bytes.Equal(f.Digests[len(f.Digests)-1], h[:]) {
			t.Fatal("Cloud KMS was not asked to sign the transaction hash itself")
		}
		from, err := types.Sender(txSigner, signed)
		if err != nil || from != k.Address() {
			t.Fatalf("sender %s, want %s (%v)", from, k.Address(), err)
		}
	}
}

func TestGCPKMSRejectsWrongKey(t *testing.T) {
	f := gcpkmsfake.New(gcpKey)
	f.Algorithm = kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256
	if _, err := NewGCPKMS(context.Background(), f, gcpKey, KMSOptions{}); err == nil ||
		!strings.Contains(err.Error(), "EC_SIGN_P256_SHA256") || !strings.Contains(err.Error(), "ec-sign-secp256k1-sha256") {
		t.Fatalf("wrong algorithm: %v", err)
	}
	for _, name := range []string{"", "alias/x", "projects/p/locations/l/keyRings/r/cryptoKeys/k",
		"projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1/extra"} {
		if _, err := NewGCPKMS(context.Background(), f, name, KMSOptions{}); err == nil {
			t.Errorf("accepted key name %q", name)
		}
	}
	f = gcpkmsfake.New(gcpKey)
	_, err := NewGCPKMS(context.Background(), f, strings.Replace(gcpKey, "/1", "/2", 1), KMSOptions{})
	var ke *KMSError
	if !errors.As(err, &ke) || ke.Code != "NotFound" || !strings.Contains(err.Error(), "--gcp-kms-key") || ke.Attempts != 1 {
		t.Fatalf("missing key: %v", err)
	}
	f.State = kmspb.CryptoKeyVersion_DESTROYED
	_, err = NewGCPKMS(context.Background(), f, gcpKey, KMSOptions{})
	if !errors.As(err, &ke) || ke.Code != "FailedPrecondition" || !strings.Contains(err.Error(), "destroyed") || ke.Attempts != 1 {
		t.Fatalf("destroyed key: %v", err)
	}
}

func TestGCPKMSChecksIntegrity(t *testing.T) {
	// One corrupted response is retried and the next one accepted.
	for _, c := range []gcpkmsfake.Corruption{gcpkmsfake.PEM, gcpkmsfake.PEMChecksum, gcpkmsfake.Name} {
		f := gcpkmsfake.New(gcpKey)
		f.GetPublicKeyCorruptions = []gcpkmsfake.Corruption{c}
		newGCPKMS(t, f)
		if f.GetPublicKeyCalls != 2 {
			t.Errorf("GetPublicKey corruption %d: %d calls, want 2", c, f.GetPublicKeyCalls)
		}
	}
	f := gcpkmsfake.New(gcpKey)
	k := newGCPKMS(t, f)
	for _, c := range []gcpkmsfake.Corruption{gcpkmsfake.Signature, gcpkmsfake.SignatureChecksum,
		gcpkmsfake.DigestUnverified, gcpkmsfake.Name} {
		f.SignCorruptions = []gcpkmsfake.Corruption{c}
		before := f.SignCalls
		if _, err := k.SignHash(context.Background(), [32]byte{byte(c)}); err != nil {
			t.Fatalf("corruption %d: %v", c, err)
		}
		if f.SignCalls-before != 2 {
			t.Errorf("AsymmetricSign corruption %d: %d calls, want 2", c, f.SignCalls-before)
		}
	}
	// Persistent corruption is fatal, bounded and never yields a signature.
	f.SignCorruptions = []gcpkmsfake.Corruption{gcpkmsfake.Signature, gcpkmsfake.Signature, gcpkmsfake.Signature,
		gcpkmsfake.Signature, gcpkmsfake.Signature}
	sig, err := k.SignHash(context.Background(), [32]byte{9})
	var ke *KMSError
	if sig != nil || !errors.As(err, &ke) || !errors.Is(err, errIntegrity) || ke.Attempts != 5 ||
		!strings.Contains(err.Error(), "signature CRC32C mismatch") {
		t.Fatalf("persistent corruption: %v", err)
	}
	f2 := gcpkmsfake.New(gcpKey)
	f2.GetPublicKeyCorruptions = []gcpkmsfake.Corruption{gcpkmsfake.PEMChecksum, gcpkmsfake.PEMChecksum,
		gcpkmsfake.PEMChecksum, gcpkmsfake.PEMChecksum, gcpkmsfake.PEMChecksum}
	opts := KMSOptions{}
	noSleep(&opts)
	if _, err := NewGCPKMS(context.Background(), f2, gcpKey, opts); !errors.Is(err, errIntegrity) ||
		!strings.Contains(err.Error(), "PEM CRC32C mismatch") {
		t.Fatalf("persistent PEM corruption: %v", err)
	}
}

func TestGCPKMSRetriesTransientErrors(t *testing.T) {
	f := gcpkmsfake.New(gcpKey)
	f.GetPublicKeyErrs = []error{gcpErr(codes.Unavailable), gcpErr(codes.ResourceExhausted)}
	k := newGCPKMS(t, f)
	if f.GetPublicKeyCalls != 3 {
		t.Fatalf("GetPublicKey calls = %d, want 3", f.GetPublicKeyCalls)
	}
	f.SignErrs = []error{gcpErr(codes.ResourceExhausted), gcpErr(codes.Internal), gcpErr(codes.DeadlineExceeded)}
	before := f.SignCalls
	if _, err := k.SignHash(context.Background(), [32]byte{1}); err != nil {
		t.Fatal(err)
	}
	if f.SignCalls-before != 4 {
		t.Fatalf("AsymmetricSign calls = %d, want 4", f.SignCalls-before)
	}
	f.SignErrs = []error{gcpErr(codes.ResourceExhausted), gcpErr(codes.ResourceExhausted), gcpErr(codes.ResourceExhausted),
		gcpErr(codes.ResourceExhausted), gcpErr(codes.ResourceExhausted), gcpErr(codes.ResourceExhausted)}
	_, err := k.SignHash(context.Background(), [32]byte{2})
	var ke *KMSError
	if !errors.As(err, &ke) || !ke.Retryable || ke.Attempts != 5 || ke.Code != "ResourceExhausted" ||
		!strings.HasPrefix(err.Error(), "gcp-kms AsymmetricSign: Cloud KMS quota exceeded (gave up after 5 attempts)") {
		t.Fatalf("exhausted retries: %v", err)
	}
}

func TestGCPKMSDoesNotRetryPermanentErrors(t *testing.T) {
	f := gcpkmsfake.New(gcpKey)
	k := newGCPKMS(t, f)
	disabled, _ := apierror.FromError(func() error {
		st, _ := status.New(codes.PermissionDenied, "Cloud Key Management Service (KMS) API has not been used in project 123 before or it is disabled.").
			WithDetails(&errdetails.ErrorInfo{Reason: "SERVICE_DISABLED", Domain: "googleapis.com"})
		return st.Err()
	}())
	for name, tc := range map[string]struct {
		err  error
		hint string
	}{
		"permission":   {gcpErr(codes.PermissionDenied), "roles/cloudkms.signerVerifier"},
		"api disabled": {disabled, "gcloud services enable cloudkms.googleapis.com"},
		"disabled key": {status.Error(codes.FailedPrecondition, "is not enabled, current state is: DISABLED."), "disabled"},
		"no creds":     {gcpErr(codes.Unauthenticated), "Application Default Credentials"},
		"bad request":  {gcpErr(codes.InvalidArgument), "EC_SIGN_SECP256K1_SHA256"},
	} {
		f.SignErrs = []error{tc.err}
		before := f.SignCalls
		_, err := k.SignHash(context.Background(), [32]byte{3})
		var ke *KMSError
		if !errors.As(err, &ke) || ke.Retryable || !strings.Contains(err.Error(), tc.hint) {
			t.Errorf("%s: %v", name, err)
		}
		if f.SignCalls-before != 1 {
			t.Errorf("%s: retried a permanent error (%d calls)", name, f.SignCalls-before)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := k.SignHash(ctx, [32]byte{4}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: %v", err)
	}
}

func TestGCPKMSSelfTestFailureIsFatal(t *testing.T) {
	f := gcpkmsfake.New(gcpKey)
	f.SignErrs = []error{gcpErr(codes.PermissionDenied)}
	if _, err := NewGCPKMS(context.Background(), f, gcpKey, KMSOptions{}); err == nil || !strings.Contains(err.Error(), "self-test") {
		t.Fatalf("err = %v", err)
	}
	f = gcpkmsfake.New(gcpKey)
	f.SignErrs = []error{gcpErr(codes.PermissionDenied)}
	if _, err := NewGCPKMS(context.Background(), f, gcpKey, KMSOptions{SkipSelfTest: true}); err != nil || f.SignCalls != 0 {
		t.Fatalf("skip self-test: %v (%d sign calls)", err, f.SignCalls)
	}
}
