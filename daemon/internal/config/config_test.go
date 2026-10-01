package config

import (
	"io"
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
	c, err := Load([]string{"--rpc", "http://flag", "--epoch-max-logs", "50"}, env, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.RPCURL != "http://flag" || c.EpochInterval != 5*time.Second || c.EpochMaxLogs != 50 {
		t.Fatalf("config %+v", c)
	}
	if c.Contract.Hex() != "0x5FbDB2315678afecb367f032d93F642f64180aa3" {
		t.Fatalf("contract %s", c.Contract.Hex())
	}
}

func TestLoadRejects(t *testing.T) {
	base := []string{"--rpc", "http://x", "--contract", "0x5FbDB2315678afecb367f032d93F642f64180aa3"}
	for _, extra := range [][]string{
		{"--epoch-interval", "0s"},
		{"--epoch-max-logs", "0"},
		{"--log-level", "loud"},
		{"--contract", "nope"},
		{"stray"},
		{"--tls-cert", "cert.pem"},
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
