package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/ronitspatil/verilog/daemon/internal/anchor"
	"github.com/ronitspatil/verilog/daemon/internal/engine"
	"github.com/ronitspatil/verilog/daemon/internal/metrics"
)

// logStats writes the periodic stats line: throughput, queue depth, resource
// usage and backpressure (the same figures as /metrics, in brief).
func logStats(logger *slog.Logger, eng *engine.Engine, worker *anchor.Worker) {
	s, u, ws := eng.Stats(), eng.Usage(), worker.Stats()
	var rejected uint64
	for _, n := range u.Rejected {
		rejected += n
	}
	attrs := []any{"accepted", s.Accepted, "duplicates", s.Duplicates, "sealed_epochs", s.SealedEpochs,
		"anchored_epochs", s.AnchoredEpochs, "anchor_queue", ws.Queued, "awaiting_finality", ws.Mined,
		"finality_lag", ws.FinalityLag.Round(time.Second), "revoked_excluded", s.RevokedExcluded,
		"unanchored_events", u.UnanchoredEvents, "unanchored_bytes", u.UnanchoredBytes, "wal_bytes", u.WALBytes,
		"disk_free_bytes", u.DiskFree, "backpressure_rejections", rejected}
	if top := u.TopAgents(1); len(top) == 1 {
		attrs = append(attrs, "top_agent", top[0], "top_agent_unanchored_bytes", u.Agents[top[0]].Bytes)
	}
	logger.Info("stats", attrs...)
	for _, r := range engine.Reasons {
		if n := u.Rejected[r]; n > 0 {
			logger.Info("stats: backpressure rejections", "reason", r, "total", n)
		}
	}
}

// collect writes every metric.
func collect(w *metrics.Writer, eng *engine.Engine, worker *anchor.Worker) {
	s, u, ws := eng.Stats(), eng.Usage(), worker.Stats()
	w.Counter("verilog_events_accepted_total", "Events accepted (durable in the WAL).", float64(s.Accepted))
	w.Counter("verilog_events_duplicate_total", "Duplicate events acknowledged without being committed again.", float64(s.Duplicates))
	w.Counter("verilog_epochs_sealed_total", "Epochs sealed.", float64(s.SealedEpochs))
	w.Counter("verilog_epochs_anchored_total", "Epochs anchored and final.", float64(s.AnchoredEpochs))
	for _, r := range engine.Reasons {
		w.Counter("verilog_backpressure_rejections_total", "Events refused (retryable) by a resource limit, by reason.",
			float64(u.Rejected[r]), "reason", r)
	}
	w.Gauge("verilog_anchor_queue_epochs", "Sealed epochs whose anchor is not final yet.", float64(ws.Queued))
	w.Gauge("verilog_anchor_awaiting_finality_epochs", "Epochs mined and awaiting finality.", float64(ws.Mined))
	w.Gauge("verilog_finality_lag_seconds", "How long the oldest mined anchor has awaited finality.", ws.FinalityLag.Seconds())
	w.Gauge("verilog_unanchored_events", "Accepted events not anchored yet.", float64(u.UnanchoredEvents))
	w.Gauge("verilog_unanchored_bytes", "Canonical bytes of accepted events not anchored yet.", float64(u.UnanchoredBytes))
	for _, id := range u.TopAgents(len(u.Agents)) {
		w.Gauge("verilog_agent_unanchored_bytes", "Canonical bytes of an agent's events not anchored yet.",
			float64(u.Agents[id].Bytes), "agent_id", id)
	}
	for _, id := range u.TopAgents(len(u.Agents)) {
		w.Gauge("verilog_agent_unanchored_events", "An agent's accepted events not anchored yet.",
			float64(u.Agents[id].Events), "agent_id", id)
	}
	w.Gauge("verilog_wal_bytes", "Size of the WAL segment files.", float64(u.WALBytes))
	w.Gauge("verilog_disk_free_bytes", "Free bytes on the data directory's file system.", float64(u.DiskFree))
	w.Gauge("verilog_disk_total_bytes", "Size of the data directory's file system.", float64(u.DiskTotal))
	low := 0.0
	if u.DiskLow {
		low = 1
	}
	w.Gauge("verilog_disk_low", "1 while free disk space is below --min-free-disk-bytes (ingest refused).", low)
}

// serveMetrics serves /metrics on addr ("" disables it) and returns a stop
// function.
func serveMetrics(addr string, eng *engine.Engine, worker *anchor.Worker, gauges *alertGauges, logger *slog.Logger) (func(), error) {
	if addr == "" {
		return func() {}, nil
	}
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("metrics listener: %w", err)
	}
	if host, _, _ := net.SplitHostPort(addr); host == "" || !net.ParseIP(host).IsLoopback() && host != "localhost" {
		logger.Warn("metrics are served on a non-loopback address without authentication; they reveal agent ids and volumes",
			"addr", lis.Addr().String())
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", metrics.Handler(func(w *metrics.Writer) {
		collect(w, eng, worker)
		gauges.collect(w)
	}))
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second}
	go func() {
		if err := srv.Serve(lis); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("metrics server stopped", "err", err)
		}
	}()
	logger.Info("metrics listening", "addr", "http://"+lis.Addr().String()+"/metrics")
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}, nil
}
