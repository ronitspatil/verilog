package redact

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"
)

// Made-up credentials in each provider's URL shape.
var providers = []struct {
	url     string
	secrets []string
	keep    []string
}{
	{"https://mainnet.infura.io/v3/9aa3d95b3bc440fa88ea12eaa4456161", []string{"9aa3d95b3bc440fa88ea12eaa4456161"}, []string{"mainnet.infura.io", "/v3/"}},
	{"https://eth-mainnet.g.alchemy.com/v2/Abc_dEf-123ghIJkl456MNop789qrSTu", []string{"Abc_dEf-123ghIJkl456MNop789qrSTu"}, []string{"eth-mainnet.g.alchemy.com", "/v2/"}},
	{"https://late-wild-sun.quiknode.pro/0f1e2d3c4b5a69788796a5b4c3d2e1f0a9b8c7d6/", []string{"0f1e2d3c4b5a69788796a5b4c3d2e1f0a9b8c7d6"}, []string{"quiknode.pro"}},
	{"https://rpc.ankr.com/eth/4c7a1f0e9d8b7a6c5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1", []string{"4c7a1f0e9d8b7a6c5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1"}, []string{"rpc.ankr.com/eth/"}},
	{"https://nd-123-456-789.p2pify.com/3c6e0b8a9c15224a8228b9a98ca1531d", []string{"3c6e0b8a9c15224a8228b9a98ca1531d"}, []string{"p2pify.com"}},
	{"https://lb.drpc.org/ogrpc?network=ethereum&dkey=AmXq5Lk2pQ9rT7vW3yZ1bC4", []string{"AmXq5Lk2pQ9rT7vW3yZ1bC4"}, []string{"lb.drpc.org/ogrpc"}},
	{"https://node.example.com/rpc?apikey=s3cr3t-key", []string{"s3cr3t-key"}, []string{"node.example.com/rpc"}},
	{"https://operator:hunter2-pass@rpc.example.com:8545", []string{"operator", "hunter2-pass"}, []string{"rpc.example.com:8545"}},
	{"wss://ws.example.com/ws/v3/a1b2c3d4e5f60718293a4b5c6d7e8f90?token=zzTop99", []string{"a1b2c3d4e5f60718293a4b5c6d7e8f90", "zzTop99"}, []string{"ws.example.com/ws/v3/"}},
}

func TestURL(t *testing.T) {
	for _, p := range providers {
		got := URL(p.url)
		for _, s := range p.secrets {
			if strings.Contains(got, s) {
				t.Errorf("URL(%s) = %s leaks %q", p.url, got, s)
			}
		}
		for _, k := range p.keep {
			if !strings.Contains(got, k) {
				t.Errorf("URL(%s) = %s lost %q", p.url, got, k)
			}
		}
		if !strings.Contains(got, Mask) {
			t.Errorf("URL(%s) = %s has no mask", p.url, got)
		}
	}
	if got := URL("http://127.0.0.1:8545"); got != "http://127.0.0.1:8545" {
		t.Errorf("plain URL changed: %s", got)
	}
}

func TestRedactorText(t *testing.T) {
	for _, p := range providers {
		r := New(p.url)
		text := fmt.Sprintf(`dialing RPC: Post %q: dial tcp: lookup failed; url=%s`, p.url, p.url)
		got := r.String(text)
		for _, s := range p.secrets {
			if strings.Contains(got, s) {
				t.Errorf("%s: %q leaks %q", p.url, got, s)
			}
		}
	}
	// Harmless short query values stay readable.
	if got := New("https://lb.drpc.org/ogrpc?network=ethereum&dkey=AmXq5Lk2pQ9rT7vW3yZ1bC4").String("network ethereum"); got != "network ethereum" {
		t.Errorf("over-redacted: %s", got)
	}
}

// A real dial/call error from go-ethereum's HTTP client, as main.go and the
// anchor worker would log it.
func TestRedactsRealRPCErrors(t *testing.T) {
	const rpc = "http://operator:hunter2-pass@127.0.0.1:1/v3/9aa3d95b3bc440fa88ea12eaa4456161?apikey=s3cr3t-key"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := ethclient.DialContext(ctx, rpc)
	if err == nil {
		_, err = c.ChainID(ctx)
		c.Close()
	}
	if err == nil {
		t.Fatal("expected an RPC error")
	}
	r := New(rpc)
	wrapped := r.Error(fmt.Errorf("dialing RPC: %w", err))
	var buf bytes.Buffer
	logger := slog.New(r.Handler(slog.NewTextHandler(&buf, nil)))
	logger.Warn("anchor: attempt failed, retrying "+rpc, "err", err, "rpc", rpc, slog.Group("g", "u", rpc), "any", []string{rpc})
	logger.With("rpc", rpc).Info("chain ready")
	slog.New(r.Handler(slog.NewJSONHandler(&buf, nil))).Error("x", "err", err)
	for _, s := range []string{"operator", "hunter2-pass", "9aa3d95b3bc440fa88ea12eaa4456161", "s3cr3t-key"} {
		if strings.Contains(wrapped.Error(), s) {
			t.Errorf("error leaks %q: %s", s, wrapped)
		}
		if strings.Contains(buf.String(), s) {
			t.Errorf("log leaks %q:\n%s", s, buf.String())
		}
	}
	if !errors.Is(wrapped, err) {
		t.Error("redacted error lost its chain")
	}
	if !strings.Contains(buf.String(), Mask) {
		t.Errorf("no mask in log:\n%s", buf.String())
	}
}
