package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/ronitspatil/verilog/daemon/internal/devpki"
	"github.com/ronitspatil/verilog/daemon/internal/metrics"
)

type fakeBalances struct {
	mu    sync.Mutex
	vals  []*big.Int // returned in turn; nil is an error
	calls int
	addr  common.Address
}

func (f *fakeBalances) BalanceAt(_ context.Context, a common.Address, block *big.Int) (*big.Int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addr = a
	v := f.vals[min(f.calls, len(f.vals)-1)]
	f.calls++
	if v == nil || block != nil {
		return nil, errors.New("rpc down")
	}
	return v, nil
}

func (f *fakeBalances) n() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func render(g *alertGauges) string {
	var w metrics.Writer
	g.collect(&w)
	return string(w.Bytes())
}

func TestAlertGaugesBalance(t *testing.T) {
	signer := common.HexToAddress("0x80869fD726F35eDF1Ae55Cb546E9873649Ef5845")
	g := &alertGauges{signer: signer}
	if out := render(g); out != "" {
		t.Fatalf("before the first read: %q", out)
	}
	wei, _ := new(big.Int).SetString("2500000000000000", 10)
	f := &fakeBalances{vals: []*big.Int{wei, nil}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.pollBalance(ctx, f, time.Millisecond, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()
	for f.n() < 3 {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	// A failed read keeps the last value.
	want := "# HELP verilog_signer_balance_wei Balance of the anchoring key (local or KMS), polled every minute.\n" +
		"# TYPE verilog_signer_balance_wei gauge\n" +
		`verilog_signer_balance_wei{address="0x80869fD726F35eDF1Ae55Cb546E9873649Ef5845"} 2.5e+15` + "\n"
	if out := render(g); out != want || f.addr != signer {
		t.Fatalf("got %q (address %s)", out, f.addr)
	}
}

func TestAlertGaugesCertExpiry(t *testing.T) {
	ca, err := devpki.NewCA("test CA")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := ca.Server("localhost")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	// The server certificate first, then its chain: the first one counts.
	path := filepath.Join(dir, "server.pem")
	os.WriteFile(path, append(append([]byte{}, srv.CertPEM...), ca.CertPEM...), 0o644)
	got, err := certNotAfter(path)
	if err != nil || !got.Equal(srv.Cert.NotAfter) {
		t.Fatalf("%v %v, want %v", got, err, srv.Cert.NotAfter)
	}
	g := &alertGauges{certExpires: got}
	want := "verilog_tls_cert_expiry_timestamp_seconds " + strconv.FormatFloat(float64(got.Unix()), 'g', -1, 64) + "\n"
	if out := render(g); !strings.HasSuffix(out, want) || !strings.Contains(out, "# TYPE verilog_tls_cert_expiry_timestamp_seconds gauge") {
		t.Fatalf("%q", out)
	}

	os.WriteFile(path, srv.KeyPEM, 0o600)
	if _, err := certNotAfter(path); err == nil {
		t.Fatal("a key file was accepted as a certificate")
	}
	if _, err := certNotAfter(filepath.Join(dir, "missing.pem")); err == nil {
		t.Fatal("a missing file was accepted")
	}
}
