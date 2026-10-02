package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/ronitspatil/verilog/daemon/internal/metrics"
)

// balancePollInterval is how often the anchoring key's balance is read.
const balancePollInterval = time.Minute

// alertGauges are the metrics read outside the engine, for alerting: the
// anchoring key's balance (polled) and the server certificate's expiry.
type alertGauges struct {
	signer      common.Address
	balance     atomic.Pointer[big.Int] // nil until the first successful read
	certExpires time.Time               // zero without TLS
}

func (g *alertGauges) collect(w *metrics.Writer) {
	if b := g.balance.Load(); b != nil {
		f, _ := new(big.Float).SetInt(b).Float64()
		w.Gauge("verilog_signer_balance_wei", "Balance of the anchoring key (local or KMS), polled every minute.", f,
			"address", g.signer.Hex())
	}
	if !g.certExpires.IsZero() {
		w.Gauge("verilog_tls_cert_expiry_timestamp_seconds", "notAfter of the server TLS certificate (Unix time).",
			float64(g.certExpires.Unix()))
	}
}

// balanceReader is what pollBalance needs (*ethclient.Client implements it).
type balanceReader interface {
	BalanceAt(ctx context.Context, account common.Address, block *big.Int) (*big.Int, error)
}

// pollBalance reads the signer's balance now and every interval until ctx
// ends. A failed read keeps the last value and logs a warning.
func (g *alertGauges) pollBalance(ctx context.Context, r balanceReader, interval time.Duration, logger *slog.Logger) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		b, err := r.BalanceAt(rctx, g.signer, nil)
		cancel()
		switch {
		case err == nil:
			g.balance.Store(b)
		case ctx.Err() == nil:
			logger.Warn("reading the anchoring key's balance failed", "address", g.signer, "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// certNotAfter returns the notAfter of the first certificate in a PEM file
// (the server's own certificate, before any chain).
func certNotAfter(path string) (time.Time, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, err
	}
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return time.Time{}, errors.New("no PEM certificate found")
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return time.Time{}, fmt.Errorf("parsing certificate: %w", err)
		}
		return c.NotAfter, nil
	}
}
