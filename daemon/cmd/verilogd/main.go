// Command verilogd is the VeriLog daemon: it ingests agent events over gRPC,
// commits them into per-agent Merkle trees and anchors epoch roots on chain.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"

	verilogv1 "github.com/ronitspatil/verilog/daemon/gen/verilog/v1"
	"github.com/ronitspatil/verilog/daemon/internal/anchor"
	"github.com/ronitspatil/verilog/daemon/internal/config"
	"github.com/ronitspatil/verilog/daemon/internal/engine"
	"github.com/ronitspatil/verilog/daemon/internal/ingest"
	"github.com/ronitspatil/verilog/daemon/internal/keys"
	"github.com/ronitspatil/verilog/daemon/internal/store"
	"github.com/ronitspatil/verilog/daemon/internal/wal"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "verilogd:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(os.Args[1:], os.Getenv, os.Stderr)
	if err != nil {
		return err
	}
	logger := newLogger(cfg)
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	key, err := cfg.LoadKey(os.Getenv, logger)
	if err != nil {
		return err
	}

	// Chain.
	dialCtx, cancelDial := context.WithTimeout(ctx, 15*time.Second)
	defer cancelDial()
	eth, err := ethclient.DialContext(dialCtx, cfg.RPCURL)
	if err != nil {
		return fmt.Errorf("dialing RPC: %w", err)
	}
	defer eth.Close()
	chain, err := anchor.NewEthChain(dialCtx, eth, cfg.Contract, key, cfg.ConfirmTimeout, logger)
	if err != nil {
		return err
	}
	if err := chain.CheckRole(dialCtx); err != nil {
		return err
	}
	logger.Info("chain ready", "chain_id", chain.ChainID(), "contract", cfg.Contract, "signer", chain.From())
	keySource, err := keys.NewChainSource(cfg.Contract, eth)
	if err != nil {
		return err
	}
	// Agent keys are re-read every minute (revocations), unknown ones after 5s.
	agentKeys := keys.NewCache(keySource, time.Minute, 5*time.Second)

	// Storage and engine.
	lock, err := lockDataDir(cfg.DataDir)
	if err != nil {
		return err
	}
	if lock != nil {
		defer lock.Close()
	}
	st, err := store.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	w, recs, err := wal.Open(cfg.DataDir+"/wal", cfg.WALSegmentBytes, logger)
	if err != nil {
		return err
	}
	defer w.Close()
	worker := anchor.NewWorker(chain, anchor.Backoff{Initial: cfg.RetryInitial, Max: cfg.RetryMax}, logger)
	eng, err := engine.New(engine.Config{
		EpochInterval: cfg.EpochInterval,
		EpochMaxLogs:  cfg.EpochMaxLogs,
		CommitBatch:   cfg.CommitBatch,
		ChainID:       chain.ChainID().String(),
		Contract:      cfg.Contract.Hex(),
	}, w, st, worker, logger)
	if err != nil {
		return err
	}
	if err := eng.Recover(recs); err != nil {
		return err
	}
	recs = nil

	engCtx, cancelEng := context.WithCancel(context.Background())
	defer cancelEng()
	eng.Start(engCtx)
	workerDone := make(chan struct{})
	go func() { defer close(workerDone); worker.Run(engCtx) }()

	// gRPC.
	lis, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	opts := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(cfg.MaxPayloadBytes + 64<<10),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 10 * time.Second, PermitWithoutStream: true}),
		grpc.KeepaliveParams(keepalive.ServerParameters{Time: 30 * time.Second, Timeout: 10 * time.Second}),
	}
	if cfg.TLSCert != "" {
		creds, err := credentials.NewServerTLSFromFile(cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			return fmt.Errorf("loading TLS certificate: %w", err)
		}
		opts = append(opts, grpc.Creds(creds))
	}
	srv := grpc.NewServer(opts...)
	verilogv1.RegisterVeriLogServer(srv, ingest.NewServer(eng, st, ingest.Options{
		MaxPayloadBytes: cfg.MaxPayloadBytes,
		Window:          cfg.StreamWindow,
		Keys:            agentKeys,
	}, logger))
	hs := health.NewServer()
	healthpb.RegisterHealthServer(srv, hs)
	hs.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(lis) }()
	logger.Info("verilogd listening", "addr", lis.Addr().String(), "tls", cfg.TLSCert != "", "data_dir", cfg.DataDir,
		"epoch_interval", cfg.EpochInterval, "epoch_max_logs", cfg.EpochMaxLogs)

	statsTick := time.NewTicker(time.Minute)
	defer statsTick.Stop()
	var runErr error
loop:
	for {
		select {
		case <-ctx.Done():
			logger.Info("shutdown requested")
			break loop
		case err := <-serveErr:
			runErr = fmt.Errorf("gRPC server: %w", err)
			break loop
		case err := <-eng.Fatal():
			runErr = fmt.Errorf("engine: %w", err)
			break loop
		case <-statsTick.C:
			s := eng.Stats()
			logger.Info("stats", "accepted", s.Accepted, "duplicates", s.Duplicates, "sealed_epochs", s.SealedEpochs,
				"anchored_epochs", s.AnchoredEpochs, "anchor_queue", worker.Pending())
		}
	}

	// Shutdown: stop taking streams, let in-flight acks finish, then stop the
	// engine (open epochs and unanchored seals are recovered from the WAL).
	hs.Shutdown()
	stopped := make(chan struct{})
	go func() { srv.GracefulStop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		logger.Warn("graceful stop timed out; closing streams")
		srv.Stop()
	}
	eng.Close()
	cancelEng()
	<-workerDone
	if n := worker.Pending(); n > 0 {
		logger.Info("unanchored sealed epochs will resume on restart", "count", n)
	}
	logger.Info("verilogd stopped")
	if runErr != nil && !errors.Is(runErr, grpc.ErrServerStopped) {
		return runErr
	}
	return nil
}

func newLogger(cfg *config.Config) *slog.Logger {
	opts := &slog.HandlerOptions{Level: cfg.LogLevel}
	if cfg.LogFormat == "json" {
		return slog.New(slog.NewJSONHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, opts))
}
