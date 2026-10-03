// Package config loads verilogd settings from flags and environment
// variables (flags win) and loads the signing key.
package config

import (
	"crypto/ecdsa"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ronitspatil/verilog/daemon/internal/finality"
)

// Environment variable names.
const (
	EnvPrivateKey = "VERILOG_PRIVATE_KEY"
	EnvKeyFile    = "VERILOG_PRIVATE_KEY_FILE"
)

// Signer backends.
const (
	SignerLocal  = "local"   // key file or VERILOG_PRIVATE_KEY (development)
	SignerAWSKMS = "aws-kms" // key held in AWS KMS (production)
	SignerGCPKMS = "gcp-kms" // key held in Google Cloud KMS (production)
)

// gcpKeyVersion matches a full Cloud KMS CryptoKeyVersion resource name.
var gcpKeyVersion = regexp.MustCompile(`^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+/cryptoKeyVersions/[^/]+$`)

// Config is the daemon configuration.
type Config struct {
	Listen         string
	Transport      Transport // mTLS and gRPC limits (transport.go)
	DataDir        string
	RPCURL         string
	Contract       common.Address
	PrivateKeyFile string
	// InsecureKeyFilePerms accepts a key file readable by group or others.
	InsecureKeyFilePerms bool
	Signer               string // SignerLocal, SignerAWSKMS or SignerGCPKMS
	KMSKeyID             string // key ARN, key id or alias/<name>
	GCPKMSKey            string // full CryptoKeyVersion resource name
	// MaxFeeCap and MaxTipCap (wei) cap maxFeePerGas and maxPriorityFeePerGas.
	MaxFeeCap      *big.Int
	MaxTipCap      *big.Int
	EpochInterval  time.Duration
	EpochMaxLogs   int
	ConfirmTimeout time.Duration
	// Finality decides when an anchor is final (WAL compaction and the
	// evidence bundle wait for it); FinalityPoll is how often it is checked
	// and FinalityTimeout when a slow one is logged at ERROR.
	Finality        finality.Mode
	FinalityPoll    time.Duration
	FinalityTimeout time.Duration
	RetryInitial    time.Duration
	RetryMax        time.Duration
	WALSegmentBytes int64
	CommitBatch     int
	MaxPayloadBytes int
	StreamWindow    int
	LogLevel        slog.Level
	LogFormat       string
	Limits          Limits
	// MetricsListen is the Prometheus /metrics listen address ("": off).
	MetricsListen string
}

// Limits bound unanchored events (see engine.Limits); zero disables one.
type Limits struct {
	MaxAgentEvents   int64
	MaxAgentBytes    int64
	MaxTotalBytes    int64
	MaxAnchorQueue   int
	AgentRate        float64
	AgentBurst       int
	MinFreeDiskBytes uint64
}

// Load parses args (without the program name) with env fallbacks.
func Load(args []string, getenv func(string) string, stderr io.Writer) (*Config, error) {
	fs := flag.NewFlagSet("verilogd", flag.ContinueOnError)
	fs.SetOutput(stderr)
	env := func(name, def string) string {
		if v := getenv(name); v != "" {
			return v
		}
		return def
	}

	var (
		c          Config
		contract   string
		logLevel   string
		interval   = env("VERILOG_EPOCH_INTERVAL", "30s")
		maxLogs    = env("VERILOG_EPOCH_MAX_LOGS", "1000")
		confirm    = env("VERILOG_CONFIRM_TIMEOUT", "2m")
		final      = env("VERILOG_FINALITY", "finalized")
		finalPoll  = env("VERILOG_FINALITY_POLL", "5s")
		finalWait  = env("VERILOG_FINALITY_TIMEOUT", "30m")
		segBytes   = env("VERILOG_WAL_SEGMENT_BYTES", strconv.Itoa(64<<20))
		maxPayload = env("VERILOG_MAX_PAYLOAD_BYTES", strconv.Itoa(1<<20))
		maxFee     = env("VERILOG_MAX_FEE_GWEI", "500")
		maxTip     = env("VERILOG_MAX_PRIORITY_FEE_GWEI", "50")
	)
	fs.StringVar(&c.Listen, "listen", env("VERILOG_LISTEN", "127.0.0.1:50051"), "gRPC listen address (env VERILOG_LISTEN)")
	validateTransport := transportFlags(fs, env, &c.Transport)
	fs.StringVar(&c.DataDir, "data-dir", env("VERILOG_DATA_DIR", "./verilog-data"), "directory for the WAL, checkpoint and evidence bundles (env VERILOG_DATA_DIR)")
	fs.StringVar(&c.RPCURL, "rpc", env("VERILOG_RPC_URL", ""), "EVM JSON-RPC endpoint (env VERILOG_RPC_URL)")
	fs.StringVar(&contract, "contract", env("VERILOG_CONTRACT", ""), "VeriLogRegistry address (env VERILOG_CONTRACT)")
	fs.StringVar(&c.Signer, "signer", env("VERILOG_SIGNER", SignerLocal), "anchoring key backend: local, aws-kms or gcp-kms (env VERILOG_SIGNER)")
	fs.StringVar(&c.KMSKeyID, "kms-key-id", env("VERILOG_KMS_KEY_ID", ""), "AWS KMS key ARN, id or alias/<name> for --signer aws-kms (env VERILOG_KMS_KEY_ID); region and credentials come from the AWS SDK default chain")
	fs.StringVar(&c.GCPKMSKey, "gcp-kms-key", env("VERILOG_GCP_KMS_KEY", ""), "Google Cloud KMS key version for --signer gcp-kms: projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/V (env VERILOG_GCP_KMS_KEY); credentials come from Application Default Credentials")
	fs.StringVar(&c.PrivateKeyFile, "private-key-file", env(EnvKeyFile, ""), "--signer local: file holding the hex signing key, mode 0600 (env "+EnvKeyFile+"); otherwise "+EnvPrivateKey+" is used")
	fs.BoolVar(&c.InsecureKeyFilePerms, "insecure-key-file-perms", false, "development only: accept a key file readable by group or others")
	fs.StringVar(&maxFee, "max-fee-gwei", maxFee, "ceiling on maxFeePerGas in gwei; retries stop bumping fees here (env VERILOG_MAX_FEE_GWEI)")
	fs.StringVar(&maxTip, "max-priority-fee-gwei", maxTip, "ceiling on maxPriorityFeePerGas in gwei (env VERILOG_MAX_PRIORITY_FEE_GWEI)")
	fs.StringVar(&interval, "epoch-interval", interval, "seal each agent's open epoch this often (env VERILOG_EPOCH_INTERVAL)")
	fs.StringVar(&maxLogs, "epoch-max-logs", maxLogs, "seal an agent's epoch once it holds this many events (env VERILOG_EPOCH_MAX_LOGS)")
	fs.StringVar(&confirm, "confirm-timeout", confirm, "max wait for a transaction receipt before retrying (env VERILOG_CONFIRM_TIMEOUT)")
	fs.StringVar(&final, "finality", final, "when an anchor is final: finalized, safe or depth:N; the WAL is compacted and the evidence bundle written only then (env VERILOG_FINALITY)")
	fs.StringVar(&finalPoll, "finality-poll", finalPoll, "how often an anchor awaiting finality is checked (env VERILOG_FINALITY_POLL)")
	fs.StringVar(&finalWait, "finality-timeout", finalWait, "log at ERROR when an anchor is not final this long after it was mined; it is never dropped (env VERILOG_FINALITY_TIMEOUT)")
	fs.DurationVar(&c.RetryInitial, "retry-initial", 1*time.Second, "initial anchoring retry delay")
	fs.DurationVar(&c.RetryMax, "retry-max", 60*time.Second, "maximum anchoring retry delay")
	fs.StringVar(&segBytes, "wal-segment-bytes", segBytes, "rotate WAL segments at this size (env VERILOG_WAL_SEGMENT_BYTES)")
	fs.IntVar(&c.CommitBatch, "commit-batch", 4096, "max events per WAL fsync")
	fs.StringVar(&maxPayload, "max-payload-bytes", maxPayload, "reject events with a larger payload_json (env VERILOG_MAX_PAYLOAD_BYTES)")
	fs.IntVar(&c.StreamWindow, "stream-window", 1024, "max unacknowledged events per ingest stream")
	fs.Int64Var(&c.Limits.MaxAgentEvents, "max-agent-unanchored-events", 100_000, "refuse (retryable) an agent's events while it has this many unanchored events (0: no limit)")
	fs.Int64Var(&c.Limits.MaxAgentBytes, "max-agent-unanchored-bytes", 256<<20, "refuse (retryable) an agent's events while its unanchored events hold this many bytes (0: no limit)")
	fs.Int64Var(&c.Limits.MaxTotalBytes, "max-unanchored-bytes", 4<<30, "refuse (retryable) all events while unanchored events hold this many bytes in total (0: no limit)")
	fs.IntVar(&c.Limits.MaxAnchorQueue, "max-anchor-queue", 1024, "refuse (retryable) all events while this many sealed epochs await a final anchor (0: no limit)")
	fs.Float64Var(&c.Limits.AgentRate, "agent-rate", 0, "per-agent ingest rate limit in events per second (0: off)")
	fs.IntVar(&c.Limits.AgentBurst, "agent-burst", 0, "per-agent burst above --agent-rate (0: one second's worth)")
	fs.Uint64Var(&c.Limits.MinFreeDiskBytes, "min-free-disk-bytes", 1<<30, "refuse (retryable) all events and log at ERROR while the data directory has less free space (0: off)")
	fs.StringVar(&c.MetricsListen, "metrics-listen", env("VERILOG_METRICS_LISTEN", ""), "serve Prometheus metrics at http://<addr>/metrics, e.g. 127.0.0.1:9464 (default off; env VERILOG_METRICS_LISTEN)")
	fs.StringVar(&logLevel, "log-level", env("VERILOG_LOG_LEVEL", "info"), "debug, info, warn or error (env VERILOG_LOG_LEVEL)")
	fs.StringVar(&c.LogFormat, "log-format", env("VERILOG_LOG_FORMAT", "text"), "text or json (env VERILOG_LOG_FORMAT)")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected arguments: %v", fs.Args())
	}

	var err error
	if c.EpochInterval, err = time.ParseDuration(interval); err != nil || c.EpochInterval <= 0 {
		return nil, fmt.Errorf("invalid epoch interval %q", interval)
	}
	if c.EpochMaxLogs, err = strconv.Atoi(maxLogs); err != nil || c.EpochMaxLogs <= 0 || c.EpochMaxLogs > 1<<30 {
		return nil, fmt.Errorf("invalid epoch max logs %q (1..2^30)", maxLogs)
	}
	if c.ConfirmTimeout, err = time.ParseDuration(confirm); err != nil || c.ConfirmTimeout <= 0 {
		return nil, fmt.Errorf("invalid confirm timeout %q", confirm)
	}
	if c.Finality, err = finality.Parse(final); err != nil || c.Finality.Kind == finality.Latest {
		return nil, fmt.Errorf("invalid --finality %q (finalized, safe or depth:N)", final)
	}
	if c.FinalityPoll, err = time.ParseDuration(finalPoll); err != nil || c.FinalityPoll <= 0 {
		return nil, fmt.Errorf("invalid finality poll %q", finalPoll)
	}
	if c.FinalityTimeout, err = time.ParseDuration(finalWait); err != nil || c.FinalityTimeout <= 0 {
		return nil, fmt.Errorf("invalid finality timeout %q", finalWait)
	}
	if c.WALSegmentBytes, err = strconv.ParseInt(segBytes, 10, 64); err != nil || c.WALSegmentBytes < 1<<10 {
		return nil, fmt.Errorf("invalid WAL segment size %q (>= 1024)", segBytes)
	}
	if c.MaxPayloadBytes, err = strconv.Atoi(maxPayload); err != nil || c.MaxPayloadBytes <= 0 || c.MaxPayloadBytes > 64<<20 {
		return nil, fmt.Errorf("invalid max payload bytes %q (1..64MiB)", maxPayload)
	}
	if err := c.LogLevel.UnmarshalText([]byte(logLevel)); err != nil {
		return nil, fmt.Errorf("invalid log level %q", logLevel)
	}
	if c.LogFormat != "text" && c.LogFormat != "json" {
		return nil, fmt.Errorf("invalid log format %q", c.LogFormat)
	}
	if c.RPCURL == "" {
		return nil, errors.New("--rpc (or VERILOG_RPC_URL) is required")
	}
	if !common.IsHexAddress(contract) {
		return nil, errors.New("--contract (or VERILOG_CONTRACT) must be a 0x address")
	}
	c.Contract = common.HexToAddress(contract)
	if err := validateTransport(); err != nil {
		return nil, err
	}
	if l := c.Limits; l.MaxAgentEvents < 0 || l.MaxAgentBytes < 0 || l.MaxTotalBytes < 0 || l.MaxAnchorQueue < 0 ||
		l.AgentRate < 0 || l.AgentBurst < 0 {
		return nil, errors.New("resource limits (--max-*, --agent-rate, --agent-burst) must not be negative")
	}
	if c.CommitBatch <= 0 || c.StreamWindow <= 0 {
		return nil, errors.New("--commit-batch and --stream-window must be positive")
	}
	if c.MaxFeeCap, err = parseGwei(maxFee); err != nil {
		return nil, fmt.Errorf("invalid --max-fee-gwei %q: %w", maxFee, err)
	}
	if c.MaxTipCap, err = parseGwei(maxTip); err != nil {
		return nil, fmt.Errorf("invalid --max-priority-fee-gwei %q: %w", maxTip, err)
	}
	if c.MaxTipCap.Cmp(c.MaxFeeCap) > 0 {
		return nil, errors.New("--max-priority-fee-gwei must not exceed --max-fee-gwei")
	}
	if c.KMSKeyID != "" && c.Signer != SignerAWSKMS {
		return nil, errors.New("--kms-key-id requires --signer aws-kms")
	}
	if c.GCPKMSKey != "" && c.Signer != SignerGCPKMS {
		return nil, errors.New("--gcp-kms-key requires --signer gcp-kms")
	}
	switch c.Signer {
	case SignerLocal:
	case SignerAWSKMS:
		if c.KMSKeyID == "" {
			return nil, errors.New("--signer aws-kms requires --kms-key-id (or VERILOG_KMS_KEY_ID)")
		}
		if c.PrivateKeyFile != "" {
			return nil, errors.New("--private-key-file cannot be used with --signer aws-kms")
		}
	case SignerGCPKMS:
		if c.GCPKMSKey == "" {
			return nil, errors.New("--signer gcp-kms requires --gcp-kms-key (or VERILOG_GCP_KMS_KEY)")
		}
		if !gcpKeyVersion.MatchString(c.GCPKMSKey) {
			return nil, fmt.Errorf("invalid --gcp-kms-key %q: want projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/V", c.GCPKMSKey)
		}
		if c.PrivateKeyFile != "" {
			return nil, errors.New("--private-key-file cannot be used with --signer gcp-kms")
		}
	default:
		return nil, fmt.Errorf("invalid --signer %q (local, aws-kms or gcp-kms)", c.Signer)
	}
	return &c, nil
}

// parseGwei converts a positive decimal gwei amount to wei.
func parseGwei(s string) (*big.Int, error) {
	r, ok := new(big.Rat).SetString(s)
	if !ok || r.Sign() <= 0 {
		return nil, errors.New("must be a positive number of gwei")
	}
	r.Mul(r, new(big.Rat).SetInt64(1e9))
	if !r.IsInt() {
		return nil, errors.New("more precision than 1 wei")
	}
	return new(big.Int).Set(r.Num()), nil
}

// LoadKey reads the local signing key from PrivateKeyFile, else from the
// VERILOG_PRIVATE_KEY environment variable. A key file readable by group or
// others is refused unless InsecureKeyFilePerms is set. Errors never contain
// key material.
func (c *Config) LoadKey(getenv func(string) string, logger *slog.Logger) (*ecdsa.PrivateKey, error) {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	var raw string
	switch {
	case c.PrivateKeyFile != "":
		st, err := os.Stat(c.PrivateKeyFile)
		if err != nil {
			return nil, fmt.Errorf("private key file: %w", err)
		}
		if perm := st.Mode().Perm(); perm&0o077 != 0 && runtime.GOOS != "windows" {
			if !c.InsecureKeyFilePerms {
				return nil, fmt.Errorf("private key file %s has mode %#o and is readable by group or others; run chmod 600 on it "+
					"(or pass --insecure-key-file-perms for development only)", c.PrivateKeyFile, perm)
			}
			logger.Warn("private key file is readable by group or others; accepted because of --insecure-key-file-perms",
				"file", c.PrivateKeyFile, "mode", fmt.Sprintf("%#o", perm))
		}
		b, err := os.ReadFile(c.PrivateKeyFile)
		if err != nil {
			return nil, fmt.Errorf("private key file: %w", err)
		}
		raw = string(b)
	case getenv(EnvPrivateKey) != "":
		raw = getenv(EnvPrivateKey)
		logger.Warn("anchoring key read from the " + EnvPrivateKey + " environment variable; " +
			"prefer --private-key-file (mode 0600) or, in production, --signer aws-kms or gcp-kms")
	default:
		return nil, fmt.Errorf("no signing key: set %s or --private-key-file", EnvPrivateKey)
	}
	raw = strings.TrimPrefix(strings.TrimSpace(raw), "0x")
	key, err := crypto.HexToECDSA(raw)
	if err != nil {
		return nil, errors.New("signing key is not a valid 32-byte hex secp256k1 private key")
	}
	return key, nil
}
