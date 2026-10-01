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
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
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
)

// Config is the daemon configuration.
type Config struct {
	Listen         string
	TLSCert        string
	TLSKey         string
	DataDir        string
	RPCURL         string
	Contract       common.Address
	PrivateKeyFile string
	// InsecureKeyFilePerms accepts a key file readable by group or others.
	InsecureKeyFilePerms bool
	Signer               string // SignerLocal or SignerAWSKMS
	KMSKeyID             string // key ARN, key id or alias/<name>
	// MaxFeeCap and MaxTipCap (wei) cap maxFeePerGas and maxPriorityFeePerGas.
	MaxFeeCap       *big.Int
	MaxTipCap       *big.Int
	EpochInterval   time.Duration
	EpochMaxLogs    int
	ConfirmTimeout  time.Duration
	RetryInitial    time.Duration
	RetryMax        time.Duration
	WALSegmentBytes int64
	CommitBatch     int
	MaxPayloadBytes int
	StreamWindow    int
	LogLevel        slog.Level
	LogFormat       string
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
		segBytes   = env("VERILOG_WAL_SEGMENT_BYTES", strconv.Itoa(64<<20))
		maxPayload = env("VERILOG_MAX_PAYLOAD_BYTES", strconv.Itoa(1<<20))
		maxFee     = env("VERILOG_MAX_FEE_GWEI", "500")
		maxTip     = env("VERILOG_MAX_PRIORITY_FEE_GWEI", "50")
	)
	fs.StringVar(&c.Listen, "listen", env("VERILOG_LISTEN", "127.0.0.1:50051"), "gRPC listen address (env VERILOG_LISTEN)")
	fs.StringVar(&c.TLSCert, "tls-cert", env("VERILOG_TLS_CERT", ""), "PEM certificate for gRPC TLS (env VERILOG_TLS_CERT); plaintext if unset")
	fs.StringVar(&c.TLSKey, "tls-key", env("VERILOG_TLS_KEY", ""), "PEM private key for gRPC TLS (env VERILOG_TLS_KEY)")
	fs.StringVar(&c.DataDir, "data-dir", env("VERILOG_DATA_DIR", "./verilog-data"), "directory for the WAL, checkpoint and evidence bundles (env VERILOG_DATA_DIR)")
	fs.StringVar(&c.RPCURL, "rpc", env("VERILOG_RPC_URL", ""), "EVM JSON-RPC endpoint (env VERILOG_RPC_URL)")
	fs.StringVar(&contract, "contract", env("VERILOG_CONTRACT", ""), "VeriLogRegistry address (env VERILOG_CONTRACT)")
	fs.StringVar(&c.Signer, "signer", env("VERILOG_SIGNER", SignerLocal), "anchoring key backend: local or aws-kms (env VERILOG_SIGNER)")
	fs.StringVar(&c.KMSKeyID, "kms-key-id", env("VERILOG_KMS_KEY_ID", ""), "AWS KMS key ARN, id or alias/<name> for --signer aws-kms (env VERILOG_KMS_KEY_ID); region and credentials come from the AWS SDK default chain")
	fs.StringVar(&c.PrivateKeyFile, "private-key-file", env(EnvKeyFile, ""), "--signer local: file holding the hex signing key, mode 0600 (env "+EnvKeyFile+"); otherwise "+EnvPrivateKey+" is used")
	fs.BoolVar(&c.InsecureKeyFilePerms, "insecure-key-file-perms", false, "development only: accept a key file readable by group or others")
	fs.StringVar(&maxFee, "max-fee-gwei", maxFee, "ceiling on maxFeePerGas in gwei; retries stop bumping fees here (env VERILOG_MAX_FEE_GWEI)")
	fs.StringVar(&maxTip, "max-priority-fee-gwei", maxTip, "ceiling on maxPriorityFeePerGas in gwei (env VERILOG_MAX_PRIORITY_FEE_GWEI)")
	fs.StringVar(&interval, "epoch-interval", interval, "seal each agent's open epoch this often (env VERILOG_EPOCH_INTERVAL)")
	fs.StringVar(&maxLogs, "epoch-max-logs", maxLogs, "seal an agent's epoch once it holds this many events (env VERILOG_EPOCH_MAX_LOGS)")
	fs.StringVar(&confirm, "confirm-timeout", confirm, "max wait for a transaction receipt before retrying (env VERILOG_CONFIRM_TIMEOUT)")
	fs.DurationVar(&c.RetryInitial, "retry-initial", 1*time.Second, "initial anchoring retry delay")
	fs.DurationVar(&c.RetryMax, "retry-max", 60*time.Second, "maximum anchoring retry delay")
	fs.StringVar(&segBytes, "wal-segment-bytes", segBytes, "rotate WAL segments at this size (env VERILOG_WAL_SEGMENT_BYTES)")
	fs.IntVar(&c.CommitBatch, "commit-batch", 4096, "max events per WAL fsync")
	fs.StringVar(&maxPayload, "max-payload-bytes", maxPayload, "reject events with a larger payload_json (env VERILOG_MAX_PAYLOAD_BYTES)")
	fs.IntVar(&c.StreamWindow, "stream-window", 1024, "max unacknowledged events per ingest stream")
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
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return nil, errors.New("--tls-cert and --tls-key must be set together")
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
	switch c.Signer {
	case SignerLocal:
		if c.KMSKeyID != "" {
			return nil, errors.New("--kms-key-id requires --signer aws-kms")
		}
	case SignerAWSKMS:
		if c.KMSKeyID == "" {
			return nil, errors.New("--signer aws-kms requires --kms-key-id (or VERILOG_KMS_KEY_ID)")
		}
		if c.PrivateKeyFile != "" {
			return nil, errors.New("--private-key-file cannot be used with --signer aws-kms")
		}
	default:
		return nil, fmt.Errorf("invalid --signer %q (local or aws-kms)", c.Signer)
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
			"prefer --private-key-file (mode 0600) or, in production, --signer aws-kms")
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
