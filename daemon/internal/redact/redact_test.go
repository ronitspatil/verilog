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

// Made-up credentials in each provider's URL shape: obviously fake values
// (deadbeef..., 0000..., EXAMPLE..., fake-...) with each real key's length
// and character set, so the token heuristics are still exercised but secret
// scanners do not mistake them for real keys.
var providers = []struct {
	url     string
	secrets []string
	keep    []string
}{
	{"https://mainnet.infura.io/v3/deadbeefdeadbeefdeadbeefdeadbeef", []string{"deadbeefdeadbeefdeadbeefdeadbeef"}, []string{"mainnet.infura.io", "/v3/"}},
	{"https://eth-mainnet.g.alchemy.com/v2/EXAMPLE_alchemy-key_000000000000", []string{"EXAMPLE_alchemy-key_000000000000"}, []string{"eth-mainnet.g.alchemy.com", "/v2/"}},
	{"https://late-wild-sun.quiknode.pro/feedfacefeedfacefeedfacefeedfacefeedface/", []string{"feedfacefeedfacefeedfacefeedfacefeedface"}, []string{"quiknode.pro"}},
	{"https://rpc.ankr.com/eth/c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee000", []string{"c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee000"}, []string{"rpc.ankr.com/eth/"}},
	{"https://nd-123-456-789.p2pify.com/00000000000000000000000000000000", []string{"00000000000000000000000000000000"}, []string{"p2pify.com"}},
	{"https://lb.drpc.org/ogrpc?network=ethereum&dkey=EXAMPLE-dkey-0000000000", []string{"EXAMPLE-dkey-0000000000"}, []string{"lb.drpc.org/ogrpc"}},
	{"https://node.example.com/rpc?apikey=fake-key", []string{"fake-key"}, []string{"node.example.com/rpc"}},
	{"https://operator:fake-password@rpc.example.com:8545", []string{"operator", "fake-password"}, []string{"rpc.example.com:8545"}},
	{"wss://ws.example.com/ws/v3/abcdef0123456789abcdef0123456789?token=fake-token", []string{"abcdef0123456789abcdef0123456789", "fake-token"}, []string{"ws.example.com/ws/v3/"}},
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
	if got := New("https://lb.drpc.org/ogrpc?network=ethereum&dkey=EXAMPLE-dkey-0000000000").String("network ethereum"); got != "network ethereum" {
		t.Errorf("over-redacted: %s", got)
	}
}

// A real dial/call error from go-ethereum's HTTP client, as main.go and the
// anchor worker would log it.
func TestRedactsRealRPCErrors(t *testing.T) {
	const rpc = "http://operator:fake-password@127.0.0.1:1/v3/deadbeefdeadbeefdeadbeefdeadbeef?apikey=fake-key"
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
	for _, s := range []string{"operator", "fake-password", "deadbeefdeadbeefdeadbeefdeadbeef", "fake-key"} {
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
