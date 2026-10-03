package signer

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"hash/crc32"
	"regexp"
	"strings"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/googleapis/gax-go/v2"
	"github.com/googleapis/gax-go/v2/apierror"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// GCPKMSClient is the subset of the Google Cloud KMS API the signer uses.
// *kms.KeyManagementClient implements it; tests use an in-memory fake.
type GCPKMSClient interface {
	GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...gax.CallOption) (*kmspb.PublicKey, error)
	AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest, opts ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error)
}

// GCPKeyVersionPattern matches a full CryptoKeyVersion resource name.
var GCPKeyVersionPattern = regexp.MustCompile(`^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+/cryptoKeyVersions/[^/]+$`)

const gcpService = "gcp-kms"

// noGAXRetry disables the client library's own retries: GCPKMS applies its
// own bounded retry policy.
var noGAXRetry = gax.WithRetry(func() gax.Retryer { return nil })

// GCPKMS signs with an EC_SIGN_SECP256K1_SHA256 key version held in Google
// Cloud KMS. The private key never leaves Cloud KMS.
type GCPKMS struct {
	client     GCPKMSClient
	name       string
	pub        []byte // uncompressed 65-byte public key
	addr       common.Address
	protection kmspb.ProtectionLevel
	opts       KMSOptions
}

// NewGCPKMSClient builds a Cloud KMS client that authenticates with
// Application Default Credentials (GOOGLE_APPLICATION_CREDENTIALS, gcloud's
// application-default login, or the attached service account).
func NewGCPKMSClient(ctx context.Context) (*kms.KeyManagementClient, error) {
	c, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcp-kms: creating client (Application Default Credentials): %w", err)
	}
	return c, nil
}

// errIntegrity marks a response that failed a CRC32C or name check; such
// responses are retried.
var errIntegrity = errors.New("response failed an integrity check")

func crc32c(b []byte) int64 { return int64(crc32.Checksum(b, crc32.MakeTable(crc32.Castagnoli))) }

// NewGCPKMS reads the key version's public key, checks its algorithm and
// the response's CRC32C, derives the Ethereum address and (unless disabled)
// makes one test signature.
func NewGCPKMS(ctx context.Context, client GCPKMSClient, name string, opts KMSOptions) (*GCPKMS, error) {
	if !GCPKeyVersionPattern.MatchString(name) {
		return nil, fmt.Errorf("gcp-kms: %q is not a CryptoKeyVersion name "+
			"(projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/V)", name)
	}
	opts.defaults()
	k := &GCPKMS{client: client, name: name, opts: opts}
	out, err := do(ctx, &k.opts, gcpService, "GetPublicKey", classifyGCP, func(ctx context.Context) (*kmspb.PublicKey, error) {
		out, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: name}, noGAXRetry)
		if err != nil {
			return nil, err
		}
		if out.GetName() != name {
			return nil, fmt.Errorf("%w: public key is for %q", errIntegrity, out.GetName())
		}
		if out.GetPemCrc32C() == nil || out.GetPemCrc32C().GetValue() != crc32c([]byte(out.GetPem())) {
			return nil, fmt.Errorf("%w: public key PEM CRC32C mismatch", errIntegrity)
		}
		return out, nil
	})
	if err != nil {
		return nil, err
	}
	if alg := out.GetAlgorithm(); alg != kmspb.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256 {
		return nil, fmt.Errorf("gcp-kms: key algorithm is %s, want %s (create the key with --default-algorithm ec-sign-secp256k1-sha256)",
			alg, kmspb.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256)
	}
	block, rest := pem.Decode([]byte(out.GetPem()))
	if block == nil || block.Type != "PUBLIC KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("gcp-kms: public key is not a single PEM PUBLIC KEY block")
	}
	pub, err := ParseSPKI(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("gcp-kms: public key: %w", err)
	}
	k.pub = pub
	k.addr = common.BytesToAddress(crypto.Keccak256(pub[1:])[12:])
	k.protection = out.GetProtectionLevel()
	if !opts.SkipSelfTest {
		if _, err := k.SignHash(ctx, selfTestDigest); err != nil {
			return nil, fmt.Errorf("gcp-kms: self-test signature: %w", err)
		}
	}
	return k, nil
}

// Address implements Signer.
func (k *GCPKMS) Address() common.Address { return k.addr }

// ProtectionLevel is the key version's protection level (HSM recommended).
func (k *GCPKMS) ProtectionLevel() string { return k.protection.String() }

// SignHash implements Signer. hash is sent as the SHA-256 digest field, so
// Cloud KMS signs exactly these 32 bytes without hashing them again. The
// request and response CRC32Cs are checked, the DER signature is
// normalized to low-s and the recovery id is found by matching the known
// public key.
func (k *GCPKMS) SignHash(ctx context.Context, hash [32]byte) ([]byte, error) {
	digestCRC := crc32c(hash[:])
	out, err := do(ctx, &k.opts, gcpService, "AsymmetricSign", classifyGCP, func(ctx context.Context) (*kmspb.AsymmetricSignResponse, error) {
		out, err := k.client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
			Name:         k.name,
			Digest:       &kmspb.Digest{Digest: &kmspb.Digest_Sha256{Sha256: hash[:]}},
			DigestCrc32C: wrapperspb.Int64(digestCRC),
		}, noGAXRetry)
		if err != nil {
			return nil, err
		}
		if !out.GetVerifiedDigestCrc32C() {
			return nil, fmt.Errorf("%w: Cloud KMS did not verify the digest CRC32C", errIntegrity)
		}
		if out.GetName() != k.name {
			return nil, fmt.Errorf("%w: signature is from %q", errIntegrity, out.GetName())
		}
		if out.GetSignatureCrc32C() == nil || out.GetSignatureCrc32C().GetValue() != crc32c(out.GetSignature()) {
			return nil, fmt.Errorf("%w: signature CRC32C mismatch", errIntegrity)
		}
		return out, nil
	})
	if err != nil {
		return nil, err
	}
	sig, err := EthSignature(hash, out.GetSignature(), k.pub)
	if err != nil {
		return nil, fmt.Errorf("gcp-kms: %w", err)
	}
	return sig, nil
}

// retryableGCPCodes are gRPC codes worth retrying.
var retryableGCPCodes = map[codes.Code]bool{
	codes.Unavailable:       true,
	codes.ResourceExhausted: true,
	codes.DeadlineExceeded:  true,
	codes.Internal:          true,
	codes.Aborted:           true,
}

var gcpHints = map[codes.Code]string{
	codes.PermissionDenied: "permission denied: grant the daemon's service account roles/cloudkms.signerVerifier on this key",
	codes.NotFound:         "key version not found: check --gcp-kms-key",
	codes.FailedPrecondition: "key version is not usable: it may be disabled, destroyed or scheduled for destruction " +
		"(check with gcloud kms keys versions describe)",
	codes.InvalidArgument:   "invalid request: check that the key's algorithm is EC_SIGN_SECP256K1_SHA256",
	codes.Unauthenticated:   "no valid Google credentials: set up Application Default Credentials",
	codes.ResourceExhausted: "Cloud KMS quota exceeded",
	codes.Unavailable:       "Cloud KMS unavailable",
}

// classifyGCP reports whether err is transient, its gRPC code and a hint.
func classifyGCP(err error) (retryable bool, code, hint string) {
	if errors.Is(err, errIntegrity) {
		return true, "", "Cloud KMS response failed its integrity check"
	}
	st, ok := status.FromError(err)
	if !ok {
		return false, "", ""
	}
	c := st.Code()
	hint = gcpHints[c]
	if c == codes.PermissionDenied && apiDisabled(err, st.Message()) {
		hint = "the Cloud KMS API is not enabled for this project: gcloud services enable cloudkms.googleapis.com"
	}
	return retryableGCPCodes[c], c.String(), hint
}

// apiDisabled reports whether a PERMISSION_DENIED error means the Cloud KMS
// API is not enabled for the project.
func apiDisabled(err error, msg string) bool {
	var ae *apierror.APIError
	if errors.As(err, &ae) && ae.Reason() == "SERVICE_DISABLED" {
		return true
	}
	return strings.Contains(msg, "SERVICE_DISABLED") || strings.Contains(msg, "has not been used in project") ||
		strings.Contains(msg, "it is disabled")
}
