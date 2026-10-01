package signer

import (
	"bytes"
	"context"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// KMSClient is the subset of the AWS KMS API the signer uses. *kms.Client
// implements it; tests use an in-memory fake.
type KMSClient interface {
	GetPublicKey(ctx context.Context, in *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	Sign(ctx context.Context, in *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
}

// KMSOptions tunes calls to KMS. Zero values pick the defaults.
type KMSOptions struct {
	MaxAttempts int           // per operation, including the first (default 5)
	BaseDelay   time.Duration // first retry delay, doubled per retry (default 200ms)
	MaxDelay    time.Duration // cap on one retry delay (default 3s)
	CallTimeout time.Duration // per attempt (default 10s)
	// SkipSelfTest skips the startup test signature.
	SkipSelfTest bool

	sleep func(context.Context, time.Duration) error // tests
}

func (o *KMSOptions) defaults() {
	if o.MaxAttempts <= 0 {
		o.MaxAttempts = 5
	}
	if o.BaseDelay <= 0 {
		o.BaseDelay = 200 * time.Millisecond
	}
	if o.MaxDelay < o.BaseDelay {
		o.MaxDelay = 3 * time.Second
	}
	if o.CallTimeout <= 0 {
		o.CallTimeout = 10 * time.Second
	}
	if o.sleep == nil {
		o.sleep = func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		}
	}
}

// KMS signs with an asymmetric ECC_SECG_P256K1 / SIGN_VERIFY key held in
// AWS KMS. The private key never leaves KMS.
type KMS struct {
	client KMSClient
	keyID  string
	pub    []byte // uncompressed 65-byte public key
	addr   common.Address
	opts   KMSOptions
}

var (
	secp256k1N     = crypto.S256().Params().N
	secp256k1HalfN = new(big.Int).Rsh(secp256k1N, 1)

	oidECPublicKey = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidSecp256k1   = asn1.ObjectIdentifier{1, 3, 132, 0, 10}

	selfTestDigest = crypto.Keccak256Hash([]byte("VeriLog/verilogd/kms-self-test/v1"))
)

// NewAWSKMSClient builds a KMS client from the AWS SDK's default
// configuration chain (environment, shared config and credentials files,
// web identity / IRSA, container and instance roles). When no region is
// configured and keyID is an ARN, the ARN's region is used. SDK-level
// retries are disabled: KMS applies its own bounded retry policy.
func NewAWSKMSClient(ctx context.Context, keyID string) (*kms.Client, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("kms: loading AWS configuration: %w", err)
	}
	if cfg.Region == "" {
		if a, err := arn.Parse(keyID); err == nil {
			cfg.Region = a.Region
		}
	}
	if cfg.Region == "" {
		return nil, errors.New("kms: no AWS region configured (set AWS_REGION, a profile region, or use a key ARN)")
	}
	return kms.NewFromConfig(cfg, func(o *kms.Options) { o.RetryMaxAttempts = 1 }), nil
}

// NewKMS reads the key's public key, checks that it is an
// ECC_SECG_P256K1 SIGN_VERIFY key that supports ECDSA_SHA_256, derives its
// Ethereum address and (unless disabled) makes one test signature.
func NewKMS(ctx context.Context, client KMSClient, keyID string, opts KMSOptions) (*KMS, error) {
	if keyID == "" {
		return nil, errors.New("kms: empty key id")
	}
	opts.defaults()
	k := &KMS{client: client, keyID: keyID, opts: opts}
	out, err := do(ctx, k, "GetPublicKey", func(ctx context.Context) (*kms.GetPublicKeyOutput, error) {
		return client.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(keyID)})
	})
	if err != nil {
		return nil, err
	}
	if out.KeySpec != kmstypes.KeySpecEccSecgP256k1 {
		return nil, fmt.Errorf("kms: key spec is %q, want %q", out.KeySpec, kmstypes.KeySpecEccSecgP256k1)
	}
	if out.KeyUsage != kmstypes.KeyUsageTypeSignVerify {
		return nil, fmt.Errorf("kms: key usage is %q, want %q", out.KeyUsage, kmstypes.KeyUsageTypeSignVerify)
	}
	if len(out.SigningAlgorithms) > 0 && !slices.Contains(out.SigningAlgorithms, kmstypes.SigningAlgorithmSpecEcdsaSha256) {
		return nil, fmt.Errorf("kms: key does not support %s", kmstypes.SigningAlgorithmSpecEcdsaSha256)
	}
	pub, err := ParseSPKI(out.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("kms: public key: %w", err)
	}
	k.pub = pub
	k.addr = common.BytesToAddress(crypto.Keccak256(pub[1:])[12:])
	if !opts.SkipSelfTest {
		if _, err := k.SignHash(ctx, selfTestDigest); err != nil {
			return nil, fmt.Errorf("kms: self-test signature: %w", err)
		}
	}
	return k, nil
}

// Address implements Signer.
func (k *KMS) Address() common.Address { return k.addr }

// SignHash implements Signer: KMS signs the digest (MessageType DIGEST,
// ECDSA_SHA_256), the DER signature is normalized to low-s and the recovery
// id is found by matching the known public key.
func (k *KMS) SignHash(ctx context.Context, hash [32]byte) ([]byte, error) {
	out, err := do(ctx, k, "Sign", func(ctx context.Context) (*kms.SignOutput, error) {
		return k.client.Sign(ctx, &kms.SignInput{
			KeyId:            aws.String(k.keyID),
			Message:          hash[:],
			MessageType:      kmstypes.MessageTypeDigest,
			SigningAlgorithm: kmstypes.SigningAlgorithmSpecEcdsaSha256,
		})
	})
	if err != nil {
		return nil, err
	}
	sig, err := EthSignature(hash, out.Signature, k.pub)
	if err != nil {
		return nil, fmt.Errorf("kms: %w", err)
	}
	return sig, nil
}

// ParseSPKI parses a DER SubjectPublicKeyInfo holding a secp256k1 public key
// and returns the 65-byte uncompressed point.
func ParseSPKI(der []byte) ([]byte, error) {
	var spki struct {
		Algorithm struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.ObjectIdentifier
		}
		PublicKey asn1.BitString
	}
	rest, err := asn1.Unmarshal(der, &spki)
	if err != nil {
		return nil, fmt.Errorf("parsing SubjectPublicKeyInfo: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("trailing data after SubjectPublicKeyInfo")
	}
	if !spki.Algorithm.Algorithm.Equal(oidECPublicKey) || !spki.Algorithm.Parameters.Equal(oidSecp256k1) {
		return nil, fmt.Errorf("not a secp256k1 EC key (algorithm %v, curve %v)", spki.Algorithm.Algorithm, spki.Algorithm.Parameters)
	}
	pub := spki.PublicKey.RightAlign()
	if spki.PublicKey.BitLength != 8*len(pub) {
		return nil, errors.New("public key bit string is not byte aligned")
	}
	if _, err := crypto.UnmarshalPubkey(pub); err != nil { // also checks the point is on the curve
		return nil, fmt.Errorf("invalid secp256k1 point: %w", err)
	}
	return bytes.Clone(pub), nil
}

// EthSignature converts a DER ECDSA (r, s) signature over hash into the
// 65-byte [R || S || V] form: s is normalized to the lower half of the curve
// order (EIP-2) and V is the recovery id that recovers pub.
func EthSignature(hash [32]byte, der, pub []byte) ([]byte, error) {
	var rs struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &rs)
	if err != nil {
		return nil, fmt.Errorf("parsing DER signature: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("trailing data after DER signature")
	}
	for _, v := range []*big.Int{rs.R, rs.S} {
		if v.Sign() <= 0 || v.Cmp(secp256k1N) >= 0 {
			return nil, errors.New("signature value out of range")
		}
	}
	s := rs.S
	if s.Cmp(secp256k1HalfN) > 0 {
		s = new(big.Int).Sub(secp256k1N, s)
	}
	sig := make([]byte, 65)
	rs.R.FillBytes(sig[0:32])
	s.FillBytes(sig[32:64])
	for v := byte(0); v < 2; v++ {
		sig[64] = v
		got, err := crypto.Ecrecover(hash[:], sig)
		if err == nil && bytes.Equal(got, pub) {
			return sig, nil
		}
	}
	return nil, errors.New("signature does not recover to the key's public key")
}

// KMSError is a failed KMS operation after retries.
type KMSError struct {
	Op        string // GetPublicKey or Sign
	Code      string // AWS error code, if any
	Hint      string // what the operator should check
	Attempts  int
	Retryable bool // the last failure was transient (retries exhausted)
	Err       error
}

func (e *KMSError) Error() string {
	msg := "kms " + e.Op
	if e.Hint != "" {
		msg += ": " + e.Hint
	}
	if e.Retryable {
		msg += fmt.Sprintf(" (gave up after %d attempts)", e.Attempts)
	}
	return msg + ": " + e.Err.Error()
}

func (e *KMSError) Unwrap() error { return e.Err }

// retryableCodes are KMS / AWS error codes worth retrying.
var retryableCodes = map[string]bool{
	"ThrottlingException":         true,
	"Throttling":                  true,
	"ThrottledException":          true,
	"TooManyRequestsException":    true,
	"RequestLimitExceeded":        true,
	"LimitExceededException":      true,
	"KMSInternalException":        true,
	"DependencyTimeoutException":  true,
	"KeyUnavailableException":     true,
	"InternalFailure":             true,
	"ServiceUnavailable":          true,
	"ServiceUnavailableException": true,
	"RequestTimeout":              true,
	"RequestTimeoutException":     true,
}

var hints = map[string]string{
	"AccessDeniedException":       "access denied: the daemon's role needs kms:GetPublicKey and kms:Sign on this key",
	"NotFoundException":           "key not found: check --kms-key-id and the AWS region",
	"InvalidArnException":         "invalid key id: use a key ARN, key id or alias/<name>",
	"DisabledException":           "key is disabled",
	"KMSInvalidStateException":    "key is not usable in its current state (pending deletion?)",
	"InvalidKeyUsageException":    "key must be ECC_SECG_P256K1 with usage SIGN_VERIFY",
	"UnrecognizedClientException": "AWS credentials were rejected",
	"InvalidSignatureException":   "AWS credentials were rejected (bad secret or clock skew)",
	"ExpiredTokenException":       "AWS credentials have expired",
	"IncompleteSignature":         "AWS request signing failed",
	"LimitExceededException":      "KMS request quota exceeded",
	"ThrottlingException":         "KMS throttled the request",
}

// classify reports whether err is transient and its AWS error code.
func classify(err error) (retryable bool, code string) {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code = apiErr.ErrorCode()
		if retryableCodes[code] {
			return true, code
		}
	}
	return retry.IsErrorRetryables(retry.DefaultRetryables).IsErrorRetryable(err) == aws.TrueTernary, code
}

// do runs fn with a per-attempt timeout and bounded exponential backoff on
// transient errors. It stops early when ctx ends.
func do[T any](ctx context.Context, k *KMS, op string, fn func(context.Context) (T, error)) (T, error) {
	var zero T
	delay := k.opts.BaseDelay
	for attempt := 1; ; attempt++ {
		actx, cancel := context.WithTimeout(ctx, k.opts.CallTimeout)
		v, err := fn(actx)
		attemptTimedOut := errors.Is(actx.Err(), context.DeadlineExceeded) && ctx.Err() == nil
		cancel()
		if err == nil {
			return v, nil
		}
		if ctx.Err() != nil {
			return zero, &KMSError{Op: op, Attempts: attempt, Err: err}
		}
		retryable, code := classify(err)
		retryable = retryable || attemptTimedOut
		if !retryable || attempt >= k.opts.MaxAttempts {
			return zero, &KMSError{Op: op, Code: code, Hint: hints[code], Attempts: attempt, Retryable: retryable, Err: err}
		}
		if err := k.opts.sleep(ctx, delay); err != nil {
			return zero, &KMSError{Op: op, Code: code, Attempts: attempt, Err: err}
		}
		delay = min(2*delay, k.opts.MaxDelay)
	}
}
