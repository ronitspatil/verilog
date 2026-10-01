package signer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ronitspatil/verilog/daemon/internal/signer/kmsfake"
)

const keyID = "arn:aws:kms:eu-west-1:111122223333:key/0b7e4c1e-0000-4000-8000-000000000001"

func noSleep(o *KMSOptions) { o.sleep = func(context.Context, time.Duration) error { return nil } }

func newKMS(t *testing.T, f *kmsfake.Fake) *KMS {
	t.Helper()
	opts := KMSOptions{}
	noSleep(&opts)
	k, err := NewKMS(context.Background(), f, keyID, opts)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func throttle() error {
	return &smithy.GenericAPIError{Code: "ThrottlingException", Message: "Rate exceeded"}
}

func TestKMSAddressAndSignatures(t *testing.T) {
	f := kmsfake.New(keyID)
	k := newKMS(t, f)
	want := crypto.PubkeyToAddress(f.Key.PublicKey)
	if k.Address() != want {
		t.Fatalf("address %s, want %s", k.Address(), want)
	}
	if f.SignCalls != 1 {
		t.Fatalf("startup self-test made %d Sign calls, want 1", f.SignCalls)
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
		// Same result as the local signer (both deterministic RFC 6979).
		local, _ := NewLocal(f.Key).SignHash(context.Background(), hash)
		if string(local) != string(sig) {
			t.Fatalf("signature %d differs from the local signer", i)
		}
	}
	if f.HighSReturned < 32 {
		t.Fatalf("only %d high-s signatures exercised", f.HighSReturned)
	}
}

func TestTransactOptsSignsEIP1559(t *testing.T) {
	f := kmsfake.New(keyID)
	k := newKMS(t, f)
	chainID := big.NewInt(31337)
	opts, err := TransactOpts(context.Background(), k, chainID)
	if err != nil {
		t.Fatal(err)
	}
	to := common.HexToAddress("0x5FbDB2315678afecb367f032d93F642f64180aa3")
	for i := 0; i < 8; i++ {
		tx := types.NewTx(&types.DynamicFeeTx{ChainID: chainID, Nonce: uint64(i), GasTipCap: big.NewInt(1e9),
			GasFeeCap: big.NewInt(3e9), Gas: 100000, To: &to, Data: []byte{0xde, 0xad, byte(i)}})
		signed, err := opts.Signer(k.Address(), tx)
		if err != nil {
			t.Fatal(err)
		}
		from, err := types.Sender(types.LatestSignerForChainID(chainID), signed)
		if err != nil || from != k.Address() {
			t.Fatalf("sender %s, want %s (%v)", from, k.Address(), err)
		}
	}
	if _, err := opts.Signer(common.Address{1}, types.NewTx(&types.DynamicFeeTx{ChainID: chainID})); err == nil {
		t.Fatal("signed for a foreign address")
	}
}

func TestKMSRejectsWrongKey(t *testing.T) {
	cases := map[string]func(f *kmsfake.Fake){
		"spec":  func(f *kmsfake.Fake) { f.KeySpec = kmstypes.KeySpecEccNistP256 },
		"usage": func(f *kmsfake.Fake) { f.KeyUsage = kmstypes.KeyUsageTypeEncryptDecrypt },
	}
	for name, mutate := range cases {
		f := kmsfake.New(keyID)
		mutate(f)
		if _, err := NewKMS(context.Background(), f, keyID, KMSOptions{}); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	f := kmsfake.New(keyID)
	_, err := NewKMS(context.Background(), f, "alias/missing", KMSOptions{})
	var ke *KMSError
	if !errors.As(err, &ke) || ke.Code != "NotFoundException" || !strings.Contains(err.Error(), "--kms-key-id") || ke.Attempts != 1 {
		t.Fatalf("missing key: %v", err)
	}
	if _, err := NewKMS(context.Background(), f, "", KMSOptions{}); err == nil {
		t.Fatal("accepted empty key id")
	}
}

func TestParseSPKI(t *testing.T) {
	key, _ := crypto.GenerateKey()
	pub, err := ParseSPKI(kmsfake.MarshalSPKI(&key.PublicKey))
	if err != nil || string(pub) != string(crypto.FromECDSAPub(&key.PublicKey)) {
		t.Fatalf("round trip: %v", err)
	}
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&p256.PublicKey)
	if _, err := ParseSPKI(der); err == nil {
		t.Fatal("accepted a P-256 key")
	}
	good := kmsfake.MarshalSPKI(&key.PublicKey)
	if _, err := ParseSPKI(append(good, 0)); err == nil {
		t.Fatal("accepted trailing data")
	}
	bad := append([]byte{}, good...)
	bad[len(bad)-1] ^= 1 // point off the curve
	if _, err := ParseSPKI(bad); err == nil {
		t.Fatal("accepted a point off the curve")
	}
	if _, err := ParseSPKI([]byte{0x30, 0x01}); err == nil {
		t.Fatal("accepted garbage")
	}
}

func TestEthSignatureRejects(t *testing.T) {
	key, _ := crypto.GenerateKey()
	pub := crypto.FromECDSAPub(&key.PublicKey)
	hash := crypto.Keccak256Hash([]byte("x"))
	sig, _ := crypto.Sign(hash[:], key)
	der := func(r, s *big.Int) []byte { b, _ := asn1.Marshal(struct{ R, S *big.Int }{r, s}); return b }
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:64])
	if _, err := EthSignature(hash, der(r, s), pub); err != nil {
		t.Fatal(err)
	}
	other, _ := crypto.GenerateKey()
	for name, in := range map[string][]byte{
		"garbage":    {0x01, 0x02},
		"trailing":   append(der(r, s), 0),
		"zero r":     der(big.NewInt(0), s),
		"s >= n":     der(r, new(big.Int).Add(secp256k1N, big.NewInt(1))),
		"wrong hash": der(r, new(big.Int).Add(s, big.NewInt(1))),
	} {
		if _, err := EthSignature(hash, in, pub); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := EthSignature(hash, der(r, s), crypto.FromECDSAPub(&other.PublicKey)); err == nil {
		t.Error("accepted a signature by another key")
	}
}

func TestKMSRetriesTransientErrors(t *testing.T) {
	f := kmsfake.New(keyID)
	f.GetPublicKeyErrs = []error{throttle(), &kmstypes.KMSInternalException{Message: aws.String("oops")}}
	k := newKMS(t, f)
	if f.GetPublicKeyCalls != 3 {
		t.Fatalf("GetPublicKey calls = %d, want 3", f.GetPublicKeyCalls)
	}
	f.SignErrs = []error{throttle(), &kmstypes.KeyUnavailableException{}, &smithy.GenericAPIError{Code: "ServiceUnavailable"}}
	before := f.SignCalls
	if _, err := k.SignHash(context.Background(), [32]byte{1}); err != nil {
		t.Fatal(err)
	}
	if f.SignCalls-before != 4 {
		t.Fatalf("Sign calls = %d, want 4", f.SignCalls-before)
	}

	// Bounded: five throttles in a row give up with a clear error.
	f.SignErrs = []error{throttle(), throttle(), throttle(), throttle(), throttle(), throttle()}
	_, err := k.SignHash(context.Background(), [32]byte{2})
	var ke *KMSError
	if !errors.As(err, &ke) || !ke.Retryable || ke.Attempts != 5 || ke.Code != "ThrottlingException" ||
		!strings.Contains(err.Error(), "gave up after 5 attempts") {
		t.Fatalf("exhausted retries: %v", err)
	}
}

func TestKMSDoesNotRetryPermanentErrors(t *testing.T) {
	f := kmsfake.New(keyID)
	k := newKMS(t, f)
	for code, hint := range map[string]string{
		"AccessDeniedException":    "kms:Sign",
		"DisabledException":        "disabled",
		"KMSInvalidStateException": "pending deletion",
	} {
		f.SignErrs = []error{&smithy.GenericAPIError{Code: code, Message: "no"}}
		before := f.SignCalls
		_, err := k.SignHash(context.Background(), [32]byte{3})
		var ke *KMSError
		if !errors.As(err, &ke) || ke.Retryable || ke.Code != code || !strings.Contains(err.Error(), hint) {
			t.Errorf("%s: %v", code, err)
		}
		if f.SignCalls-before != 1 {
			t.Errorf("%s: retried a permanent error (%d calls)", code, f.SignCalls-before)
		}
	}
	// A cancelled context stops at once.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := k.SignHash(ctx, [32]byte{4}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: %v", err)
	}
}

func TestKMSSelfTestFailureIsFatal(t *testing.T) {
	f := kmsfake.New(keyID)
	f.SignErrs = []error{&smithy.GenericAPIError{Code: "AccessDeniedException"}}
	if _, err := NewKMS(context.Background(), f, keyID, KMSOptions{}); err == nil || !strings.Contains(err.Error(), "self-test") {
		t.Fatalf("err = %v", err)
	}
}
