// Command verilogd is the VeriLog daemon: it ingests agent events over gRPC,
// commits them into per-agent Merkle trees and anchors epoch roots on chain.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	verilogv1 "github.com/ronitspatil/verilog/daemon/gen/verilog/v1"
	"github.com/ronitspatil/verilog/daemon/internal/anchor"
	"github.com/ronitspatil/verilog/daemon/internal/config"
	"github.com/ronitspatil/verilog/daemon/internal/engine"
	"github.com/ronitspatil/verilog/daemon/internal/finality"
	"github.com/ronitspatil/verilog/daemon/internal/ingest"
	"github.com/ronitspatil/verilog/daemon/internal/keys"
	"github.com/ronitspatil/verilog/daemon/internal/redact"
	"github.com/ronitspatil/verilog/daemon/internal/signer"
	"github.com/ronitspatil/verilog/daemon/internal/store"
	"github.com/ronitspatil/verilog/daemon/internal/wal"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "verilogd:", err)
		os.Exit(1)
	}
}

func run() (err error) {
	cfg, err := config.Load(os.Args[1:], os.Getenv, os.Stderr)
	if err != nil {
		return err
	}
	// RPC URLs often embed credentials or API keys: keep them out of every
	// log line and of the error returned to main.
	red := redact.New(cfg.RPCURL)
	defer func() { err = red.Error(err) }()
	logger := newLogger(cfg, red)
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The data dir lock comes first: it also guards the pending-transaction
	// record the anchorer reads at startup.
	lock, err := lockDataDir(cfg.DataDir)
	if err != nil {
		return err
	}
	if lock != nil {
		defer lock.Close()
	}

	sgn, err := newSigner(ctx, cfg, logger)
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
	chain, err := anchor.NewEthChain(dialCtx, eth, cfg.Contract, sgn, anchor.Options{
		ConfirmTimeout: cfg.ConfirmTimeout,
		MaxFeeCap:      cfg.MaxFeeCap,
		MaxTipCap:      cfg.MaxTipCap,
		PendingFile:    filepath.Join(cfg.DataDir, anchor.PendingFileName),
		Finality:       cfg.Finality,
	}, logger)
	if err != nil {
		return err
	}
	if err := chain.CheckRole(dialCtx); err != nil {
		return err
	}
	final, err := cfg.Finality.Check(dialCtx, eth)
	if err != nil {
		return err
	}
	if cfg.Finality.Kind == finality.Depth && cfg.Finality.Depth == 0 {
		logger.Warn("--finality depth:0 treats a mined anchor as final: a reorg can lose anchored events; use only for development")
	}
	logger.Info("chain ready", "rpc", redact.URL(cfg.RPCURL), "chain_id", chain.ChainID(), "contract", cfg.Contract,
		"signer", cfg.Signer, "address", chain.From(), "finality", cfg.Finality, "final_block", final.Number)
	keySource, err := keys.NewChainSource(cfg.Contract, eth)
	if err != nil {
		return err
	}
	// Agent keys are re-read every minute (revocations), unknown ones after 5s.
	agentKeys := keys.NewCache(keySource, time.Minute, 5*time.Second)
	// At seal time keys are read again, uncached, against the chain's clock
	// (the anchor's timestamp will be at least the latest block's).
	sealCheck := keys.RevocationCheck{Src: keySource, Now: func(ctx context.Context) (uint64, error) {
		h, err := eth.HeaderByNumber(ctx, nil)
		if err != nil {
			return 0, err
		}
		return max(h.Time, uint64(time.Now().Unix())), nil
	}}

	// Storage and engine.
	st, err := store.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	w, recs, err := wal.Open(cfg.DataDir+"/wal", cfg.WALSegmentBytes, logger)
	if err != nil {
		return err
	}
	defer w.Close()
	worker := anchor.NewWorker(chain, anchor.WorkerOptions{
		Backoff:         anchor.Backoff{Initial: cfg.RetryInitial, Max: cfg.RetryMax},
		FinalityPoll:    cfg.FinalityPoll,
		FinalityTimeout: cfg.FinalityTimeout,
	}, logger)
	eng, err := engine.New(engine.Config{
		EpochInterval: cfg.EpochInterval,
		EpochMaxLogs:  cfg.EpochMaxLogs,
		CommitBatch:   cfg.CommitBatch,
		ChainID:       chain.ChainID().String(),
		Contract:      cfg.Contract.Hex(),
		KeyCheck:      sealCheck,
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
	// Transport security (mTLS) and limits: transport.go.
	opts, policy, err := transportOptions(cfg.Transport, logger)
	if err != nil {
		return err
	}
	lis, err := listen(cfg.Listen, cfg.Transport)
	if err != nil {
		return err
	}
	// Far above the payload cap, so an oversized payload is answered with
	// a per-event rejection instead of failing the whole stream.
	opts = append(opts, grpc.MaxRecvMsgSize(ingest.MaxRecvMsgSize(cfg.MaxPayloadBytes)))
	srv := grpc.NewServer(opts...)
	verilogv1.RegisterVeriLogServer(srv, ingest.NewServer(eng, st, ingest.Options{
		MaxPayloadBytes: cfg.MaxPayloadBytes,
		Window:          cfg.StreamWindow,
		Keys:            agentKeys,
		Authz:           policy,
		IdleTimeout:     cfg.Transport.StreamIdleTimeout,
	}, logger))
	hs := health.NewServer()
	healthpb.RegisterHealthServer(srv, hs)
	hs.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(lis) }()
	logger.Info("verilogd listening", "addr", lis.Addr().String(), "mtls", cfg.Transport.MTLS(), "data_dir", cfg.DataDir,
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
				"anchored_epochs", s.AnchoredEpochs, "anchor_queue", worker.Pending(), "revoked_excluded", s.RevokedExcluded)
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

// newSigner returns the anchoring key's signer: a local key, or a key held
// in AWS KMS (its private key never reaches this host).
func newSigner(ctx context.Context, cfg *config.Config, logger *slog.Logger) (signer.Signer, error) {
	switch cfg.Signer {
	case config.SignerAWSKMS:
		if os.Getenv(config.EnvPrivateKey) != "" {
			logger.Warn(config.EnvPrivateKey + " is set but ignored with --signer aws-kms; unset it")
		}
		kctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		client, err := signer.NewAWSKMSClient(kctx, cfg.KMSKeyID)
		if err != nil {
			return nil, err
		}
		s, err := signer.NewKMS(kctx, client, cfg.KMSKeyID, signer.KMSOptions{})
		if err != nil {
			return nil, err
		}
		logger.Info("aws-kms signer ready", "address", s.Address())
		return s, nil
	default:
		key, err := cfg.LoadKey(os.Getenv, logger)
		if err != nil {
			return nil, err
		}
		return signer.NewLocal(key), nil
	}
}

func newLogger(cfg *config.Config, red *redact.Redactor) *slog.Logger {
	opts := &slog.HandlerOptions{Level: cfg.LogLevel}
	var h slog.Handler = slog.NewTextHandler(os.Stderr, opts)
	if cfg.LogFormat == "json" {
		h = slog.NewJSONHandler(os.Stderr, opts)
	}
	return slog.New(red.Handler(h))
}
