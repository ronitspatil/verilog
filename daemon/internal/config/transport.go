package config

import (
	"errors"
	"flag"
	"fmt"
	"strconv"
	"time"
)

// Transport is the gRPC transport configuration: mutual TLS (or the
// dev-only plaintext opt-in) and the connection and stream limits.
type Transport struct {
	TLSCert           string // server certificate (PEM)
	TLSKey            string // server private key (PEM)
	TLSClientCA       string // CA bundle (PEM) that client certificates must chain to; enables mTLS
	InsecurePlaintext bool   // DEV ONLY: no TLS, no client authentication or authorization

	MaxConnections       int           // concurrent TCP connections (0: unlimited)
	MaxConcurrentStreams uint32        // concurrent RPCs per connection
	StreamIdleTimeout    time.Duration // close an ingest stream with no event for this long (0: never)
	KeepaliveMinTime     time.Duration // reject client pings more frequent than this
	KeepaliveTime        time.Duration // server ping interval on an idle connection
	KeepaliveTimeout     time.Duration // close a connection whose ping is not answered in this time
}

// MTLS reports whether client certificates are required.
func (t *Transport) MTLS() bool { return t.TLSClientCA != "" }

// transportFlags registers the transport flags; the returned func validates
// them after parsing.
func transportFlags(fs *flag.FlagSet, env func(name, def string) string, t *Transport) func() error {
	insecureEnv := env("VERILOG_INSECURE_PLAINTEXT", "false")
	insecureDef, insecureErr := strconv.ParseBool(insecureEnv)
	maxConns := env("VERILOG_MAX_CONNECTIONS", "1024")
	maxStreams := env("VERILOG_MAX_CONCURRENT_STREAMS", "64")
	idle := env("VERILOG_STREAM_IDLE_TIMEOUT", "15m")
	fs.StringVar(&t.TLSCert, "tls-cert", env("VERILOG_TLS_CERT", ""), "PEM server certificate (env VERILOG_TLS_CERT)")
	fs.StringVar(&t.TLSKey, "tls-key", env("VERILOG_TLS_KEY", ""), "PEM server private key (env VERILOG_TLS_KEY)")
	fs.StringVar(&t.TLSClientCA, "tls-client-ca", env("VERILOG_TLS_CLIENT_CA", ""),
		"PEM CA bundle for client certificates; turns on mutual TLS (env VERILOG_TLS_CLIENT_CA)")
	fs.BoolVar(&t.InsecurePlaintext, "insecure-plaintext", insecureDef,
		"DEV ONLY: serve plaintext gRPC with no client authentication or authorization (env VERILOG_INSECURE_PLAINTEXT)")
	fs.StringVar(&maxConns, "max-connections", maxConns, "max concurrent client connections, 0 for no limit (env VERILOG_MAX_CONNECTIONS)")
	fs.StringVar(&maxStreams, "max-concurrent-streams", maxStreams, "max concurrent RPCs per connection (env VERILOG_MAX_CONCURRENT_STREAMS)")
	fs.StringVar(&idle, "stream-idle-timeout", idle, "close an ingest stream that sends no event for this long, 0 to disable (env VERILOG_STREAM_IDLE_TIMEOUT)")
	fs.DurationVar(&t.KeepaliveMinTime, "keepalive-min-time", 10*time.Second, "reject client keepalive pings more frequent than this")
	fs.DurationVar(&t.KeepaliveTime, "keepalive-time", 30*time.Second, "ping a client connection idle for this long")
	fs.DurationVar(&t.KeepaliveTimeout, "keepalive-timeout", 10*time.Second, "close a connection whose ping is unanswered for this long")

	return func() error {
		if insecureErr != nil {
			return fmt.Errorf("invalid VERILOG_INSECURE_PLAINTEXT %q", insecureEnv)
		}
		var err error
		if t.MaxConnections, err = strconv.Atoi(maxConns); err != nil || t.MaxConnections < 0 {
			return fmt.Errorf("invalid max connections %q", maxConns)
		}
		n, err := strconv.ParseUint(maxStreams, 10, 32)
		if err != nil || n == 0 {
			return fmt.Errorf("invalid max concurrent streams %q (>= 1)", maxStreams)
		}
		t.MaxConcurrentStreams = uint32(n)
		if t.StreamIdleTimeout, err = time.ParseDuration(idle); err != nil || t.StreamIdleTimeout < 0 {
			return fmt.Errorf("invalid stream idle timeout %q", idle)
		}
		if t.KeepaliveMinTime <= 0 || t.KeepaliveTime <= 0 || t.KeepaliveTimeout <= 0 {
			return errors.New("--keepalive-min-time, --keepalive-time and --keepalive-timeout must be positive")
		}
		tls := t.TLSCert != "" || t.TLSKey != "" || t.TLSClientCA != ""
		switch {
		case t.InsecurePlaintext && tls:
			return errors.New("--insecure-plaintext cannot be combined with --tls-cert, --tls-key or --tls-client-ca")
		case t.InsecurePlaintext:
			return nil
		case !tls:
			return errors.New("no transport security: set --tls-cert, --tls-key and --tls-client-ca for mutual TLS " +
				"(or --insecure-plaintext for local development only)")
		case t.TLSCert == "" || t.TLSKey == "":
			return errors.New("--tls-cert and --tls-key must be set together")
		case t.TLSClientCA == "":
			// Server-only TLS is not offered: without client certificates there is
			// no caller identity, so GetProof would again serve every agent's events
			// to anyone (finding M5).
			return errors.New("--tls-client-ca is required with --tls-cert: client certificates identify " +
				"and authorize callers (server-only TLS is not supported)")
		}
		return nil
	}
}
