package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"

	"golang.org/x/net/netutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	"github.com/ronitspatil/verilog/daemon/internal/authz"
	"github.com/ronitspatil/verilog/daemon/internal/config"
)

// listen opens the gRPC listener, limited to MaxConnections concurrent
// connections.
func listen(addr string, t config.Transport) (net.Listener, error) {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	if t.MaxConnections > 0 {
		lis = netutil.LimitListener(lis, t.MaxConnections)
	}
	return lis, nil
}

// transportOptions returns the gRPC server options for transport security and
// limits, and the authorization policy that goes with them.
func transportOptions(t config.Transport, logger *slog.Logger) ([]grpc.ServerOption, authz.Policy, error) {
	opts := []grpc.ServerOption{
		grpc.MaxConcurrentStreams(t.MaxConcurrentStreams),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: t.KeepaliveMinTime, PermitWithoutStream: true}),
		grpc.KeepaliveParams(keepalive.ServerParameters{Time: t.KeepaliveTime, Timeout: t.KeepaliveTimeout}),
	}
	if t.InsecurePlaintext {
		logger.Warn("!!! INSECURE PLAINTEXT MODE (--insecure-plaintext): no TLS, no client authentication, " +
			"no authorization. Anyone who can reach this port can read every agent's events with GetProof " +
			"and submit events for any agent. Local development only.")
		return opts, authz.Policy{}, nil
	}
	tlsCfg, err := serverTLS(t)
	if err != nil {
		return nil, authz.Policy{}, err
	}
	return append(opts, grpc.Creds(credentials.NewTLS(tlsCfg))), authz.Policy{Required: true}, nil
}

// serverTLS is the mutual TLS configuration: TLS 1.3 only, and a client
// certificate chaining to TLSClientCA is required.
func serverTLS(t config.Transport) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(t.TLSCert, t.TLSKey)
	if err != nil {
		return nil, fmt.Errorf("loading TLS certificate: %w", err)
	}
	pem, err := os.ReadFile(t.TLSClientCA)
	if err != nil {
		return nil, fmt.Errorf("--tls-client-ca: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("--tls-client-ca: no PEM certificates found")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}, nil
}
