package config

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Anvil's first well-known development key. Never use it outside local dev.
const devKey = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestLoadFlagsAndEnv(t *testing.T) {
	env := envOf(map[string]string{
		"VERILOG_RPC_URL":        "http://env",
		"VERILOG_CONTRACT":       "0x5FbDB2315678afecb367f032d93F642f64180aa3",
		"VERILOG_EPOCH_INTERVAL": "5s",
	})
	c, err := Load([]string{"--rpc", "http://flag", "--epoch-max-logs", "50", "--insecure-plaintext"}, env, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.RPCURL != "http://flag" || c.EpochInterval != 5*time.Second || c.EpochMaxLogs != 50 {
		t.Fatalf("config %+v", c)
	}
	if c.Contract.Hex() != "0x5FbDB2315678afecb367f032d93F642f64180aa3" {
		t.Fatalf("contract %s", c.Contract.Hex())
	}
	if c.Limits.MaxAgentEvents != 100_000 || c.Limits.MaxAnchorQueue != 1024 || c.Limits.MinFreeDiskBytes != 1<<30 ||
		c.Limits.AgentRate != 0 || c.MetricsListen != "" {
		t.Fatalf("limit defaults %+v %q", c.Limits, c.MetricsListen)
	}
	if c.Finality.String() != "finalized" || c.FinalityPoll != 5*time.Second || c.FinalityTimeout != 30*time.Minute {
		t.Fatalf("finality defaults %v %v %v", c.Finality, c.FinalityPoll, c.FinalityTimeout)
	}
}

func TestLoadFinality(t *testing.T) {
	base := []string{"--rpc", "http://x", "--contract", "0x5FbDB2315678afecb367f032d93F642f64180aa3", "--insecure-plaintext"}
	for flag, want := range map[string]string{"finalized": "finalized", "safe": "safe", "depth:12": "depth:12", "depth:0": "depth:0"} {
		c, err := Load(append(append([]string{}, base...), "--finality", flag), envOf(nil), io.Discard)
		if err != nil || c.Finality.String() != want {
			t.Errorf("--finality %s: %v %v", flag, c, err)
		}
	}
	c, err := Load(base, envOf(map[string]string{"VERILOG_FINALITY": "depth:2", "VERILOG_FINALITY_POLL": "250ms"}), io.Discard)
	if err != nil || c.Finality.String() != "depth:2" || c.FinalityPoll != 250*time.Millisecond {
		t.Fatalf("env: %+v %v", c, err)
	}
}

func TestLoadRejects(t *testing.T) {
	base := []string{"--rpc", "http://x", "--contract", "0x5FbDB2315678afecb367f032d93F642f64180aa3", "--insecure-plaintext"}
	for _, extra := range [][]string{
		{"--epoch-interval", "0s"},
		{"--epoch-max-logs", "0"},
		{"--log-level", "loud"},
		{"--contract", "nope"},
		{"stray"},
		{"--tls-cert", "cert.pem"},
		{"--finality", "latest"},
		{"--finality", "depth:"},
		{"--finality", "depth:-1"},
		{"--finality", "final"},
		{"--finality-poll", "0s"},
		{"--finality-timeout", "soon"},
		{"--max-agent-unanchored-events", "-1"},
		{"--agent-rate", "-2"},
		{"--max-anchor-queue", "x"},
	} {
		if _, err := Load(append(append([]string{}, base...), extra...), envOf(nil), io.Discard); err == nil {
			t.Errorf("accepted %v", extra)
		}
	}
	if _, err := Load(nil, envOf(nil), io.Discard); err == nil {
		t.Error("accepted missing rpc")
	}
}

func TestLoadKey(t *testing.T) {
	c := &Config{}
	k, err := c.LoadKey(envOf(map[string]string{EnvPrivateKey: devKey}), nil)
	if err != nil || k == nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "key")
	os.WriteFile(path, []byte(strings.TrimPrefix(devKey, "0x")+"\n"), 0o600)
	c.PrivateKeyFile = path
	if _, err := c.LoadKey(envOf(nil), nil); err != nil {
		t.Fatal(err)
	}

	c.PrivateKeyFile = ""
	_, err = c.LoadKey(envOf(map[string]string{EnvPrivateKey: "0xdeadbeef-not-a-key"}), nil)
	if err == nil || strings.Contains(err.Error(), "deadbeef") {
		t.Fatalf("bad key error must not echo key material: %v", err)
	}
	if _, err := c.LoadKey(envOf(nil), nil); err == nil {
		t.Fatal("expected missing key error")
	}
}

func TestLoadKeyFilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	os.WriteFile(path, []byte(strings.TrimPrefix(devKey, "0x")), 0o600)
	os.Chmod(path, 0o644)
	c := &Config{PrivateKeyFile: path}
	_, err := c.LoadKey(envOf(nil), nil)
	if err == nil || !strings.Contains(err.Error(), "chmod 600") || !strings.Contains(err.Error(), "--insecure-key-file-perms") {
		t.Fatalf("group/world-readable key file: err = %v", err)
	}
	var logs bytes.Buffer
	c.InsecureKeyFilePerms = true
	if _, err := c.LoadKey(envOf(nil), slog.New(slog.NewTextHandler(&logs, nil))); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), "insecure-key-file-perms") {
		t.Fatalf("no warning: %s", logs.String())
	}
	os.Chmod(path, 0o640)
	c.InsecureKeyFilePerms = false
	if _, err := c.LoadKey(envOf(nil), nil); err == nil {
		t.Fatal("accepted a group-readable key file")
	}
	os.Chmod(path, 0o400)
	if _, err := c.LoadKey(envOf(nil), nil); err != nil {
		t.Fatalf("0400 must be accepted: %v", err)
	}
}

func TestLoadKeyFromEnvWarns(t *testing.T) {
	var logs bytes.Buffer
	c := &Config{}
	if _, err := c.LoadKey(envOf(map[string]string{EnvPrivateKey: devKey}), slog.New(slog.NewTextHandler(&logs, nil))); err != nil {
		t.Fatal(err)
	}
	out := logs.String()
	if !strings.Contains(out, "level=WARN") || !strings.Contains(out, "--private-key-file") || !strings.Contains(out, "aws-kms") {
		t.Fatalf("no warning: %s", out)
	}
	if strings.Contains(out, strings.TrimPrefix(devKey, "0x")) {
		t.Fatal("warning leaks the key")
	}
}

func TestLoadSignerAndFees(t *testing.T) {
	base := []string{"--rpc", "http://x", "--contract", "0x5FbDB2315678afecb367f032d93F642f64180aa3", "--insecure-plaintext"}
	load := func(extra ...string) (*Config, error) {
		return Load(append(append([]string{}, base...), extra...), envOf(nil), io.Discard)
	}
	c, err := load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Signer != SignerLocal || c.MaxFeeCap.String() != "500000000000" || c.MaxTipCap.String() != "50000000000" {
		t.Fatalf("defaults: signer %q fee %s tip %s", c.Signer, c.MaxFeeCap, c.MaxTipCap)
	}
	c, err = load("--signer", "aws-kms", "--kms-key-id", "alias/verilog-anchorer", "--max-fee-gwei", "0.5", "--max-priority-fee-gwei", "0.001")
	if err != nil {
		t.Fatal(err)
	}
	if c.KMSKeyID != "alias/verilog-anchorer" || c.MaxFeeCap.String() != "500000000" || c.MaxTipCap.String() != "1000000" {
		t.Fatalf("config %+v", c)
	}
	c, err = Load(base, envOf(map[string]string{"VERILOG_SIGNER": "aws-kms", "VERILOG_KMS_KEY_ID": "arn:aws:kms:us-east-1:111122223333:key/x"}), io.Discard)
	if err != nil || c.Signer != SignerAWSKMS {
		t.Fatalf("env: %+v %v", c, err)
	}
	for _, extra := range [][]string{
		{"--signer", "aws-kms"},
		{"--signer", "vault"},
		{"--kms-key-id", "alias/x"},
		{"--signer", "aws-kms", "--kms-key-id", "alias/x", "--private-key-file", "k"},
		{"--max-fee-gwei", "0"},
		{"--max-fee-gwei", "-1"},
		{"--max-fee-gwei", "abc"},
		{"--max-fee-gwei", "0.0000000001"},
		{"--max-fee-gwei", "10", "--max-priority-fee-gwei", "20"},
	} {
		if _, err := load(extra...); err == nil {
			t.Errorf("accepted %v", extra)
		}
	}
}
