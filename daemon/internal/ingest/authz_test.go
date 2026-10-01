package ingest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	verilogv1 "github.com/ronitspatil/verilog/daemon/gen/verilog/v1"
	"github.com/ronitspatil/verilog/daemon/internal/anchor"
	"github.com/ronitspatil/verilog/daemon/internal/authz"
	"github.com/ronitspatil/verilog/daemon/internal/devpki"
)

// pki is a test CA with certificates for two agents, an auditor and a client
// without any identity.
type pki struct {
	ca, server, agentA, agentB, auditor, anonymous *devpki.Cert
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	must := func(c *devpki.Cert, err error) *devpki.Cert {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	p := &pki{ca: must(devpki.NewCA("test CA"))}
	p.server = must(p.ca.Server("localhost"))
	p.agentA = must(p.ca.Client("agent-a", authz.URI(authz.RoleAgent, "agent-a")))
	p.agentB = must(p.ca.Client("agent-b", authz.URI(authz.RoleAgent, "agent-b")))
	p.auditor = must(p.ca.Client("auditor", authz.URI(authz.RoleAuditor, "audit")))
	p.anonymous = must(p.ca.Client("nobody"))
	return p
}

func tlsCert(t *testing.T, c *devpki.Cert) tls.Certificate {
	t.Helper()
	cert, err := tls.X509KeyPair(c.CertPEM, c.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func (p *pki) serverOption(t *testing.T) grpc.ServerOption {
	pool := x509.NewCertPool()
	pool.AddCert(p.ca.Cert)
	return grpc.Creds(credentials.NewTLS(&tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{tlsCert(t, p.server)},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}))
}

// clientCreds returns mTLS client credentials presenting c (none if nil).
func (p *pki) clientCreds(t *testing.T, c *devpki.Cert) credentials.TransportCredentials {
	pool := x509.NewCertPool()
	pool.AddCert(p.ca.Cert)
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: "localhost"}
	if c != nil {
		cfg.Certificates = []tls.Certificate{tlsCert(t, c)}
	}
	return credentials.NewTLS(cfg)
}

func newMTLSEnv(t *testing.T, idle time.Duration) (*env, *pki) {
	p := newPKI(t)
	e := newEnvWith(t, envOptions{
		server: []grpc.ServerOption{p.serverOption(t)},
		client: p.clientCreds(t, p.agentA),
		opts:   Options{Authz: authz.Policy{Required: true}, IdleTimeout: idle},
	})
	return e, p
}

// ingest sends msgs on a new stream and returns the acks.
func ingest(t *testing.T, c verilogv1.VeriLogClient, msgs ...*verilogv1.LogEvent) ([]*verilogv1.Ack, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := c.IngestStream(ctx)
	if err != nil {
		return nil, err
	}
	for _, m := range msgs {
		if err := stream.Send(m); err != nil {
			break // the error comes from Recv
		}
	}
	stream.CloseSend()
	var acks []*verilogv1.Ack
	for range msgs {
		ack, err := stream.Recv()
		if err != nil {
			return acks, err
		}
		acks = append(acks, ack)
	}
	return acks, nil
}

func TestMTLSAgentIngestsOnlyItsOwnEvents(t *testing.T) {
	e, _ := newMTLSEnv(t, 0)
	acks, err := ingest(t, e.client, logEvent("agent-a", 1), logEvent("agent-b", 2), logEvent("agent-a", 3))
	if err != nil {
		t.Fatal(err)
	}
	if !acks[0].Accepted || !acks[2].Accepted {
		t.Fatalf("own events rejected: %+v", acks)
	}
	if acks[1].Accepted || acks[1].Retryable || !strings.Contains(acks[1].Error, "does not match the client certificate identity") {
		t.Fatalf("foreign event: %+v", acks[1])
	}
	// The foreign event was refused before any key lookup.
	e.keys.mu.Lock()
	calls := e.keys.calls
	e.keys.mu.Unlock()
	if calls != 2 {
		t.Fatalf("key lookups = %d, want 2 (none for the foreign event)", calls)
	}
}

func TestMTLSRefusesCallersWithoutIdentity(t *testing.T) {
	e, p := newMTLSEnv(t, 0)
	// No client certificate: the TLS handshake fails.
	if _, err := ingest(t, e.dial(t, p.clientCreds(t, nil)), logEvent("agent-a", 1)); status.Code(err) != codes.Unavailable {
		t.Fatalf("no client cert: %v, want Unavailable (handshake refused)", err)
	}
	// Plaintext against the TLS server.
	if _, err := ingest(t, e.dial(t, nil), logEvent("agent-a", 1)); err == nil {
		t.Fatal("plaintext client was served")
	}
	// A certificate from the CA without a verilog:// identity.
	_, err := ingest(t, e.dial(t, p.clientCreds(t, p.anonymous)), logEvent("agent-a", 1))
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("cert without identity: %v, want Unauthenticated", err)
	}
	// A certificate from another CA.
	other := newPKI(t)
	if _, err := ingest(t, e.dial(t, p.clientCreds(t, other.agentA)), logEvent("agent-a", 1)); err == nil {
		t.Fatal("certificate from a foreign CA was served")
	}
	e.keys.mu.Lock()
	defer e.keys.mu.Unlock()
	if e.keys.calls != 0 {
		t.Fatalf("key lookups for unauthenticated callers: %d", e.keys.calls)
	}
}

func TestMTLSAuditorCannotIngest(t *testing.T) {
	e, p := newMTLSEnv(t, 0)
	_, err := ingest(t, e.dial(t, p.clientCreds(t, p.auditor)), logEvent("agent-a", 1))
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("auditor ingest: %v, want PermissionDenied", err)
	}
}

func TestMTLSGetProofAuthorization(t *testing.T) {
	e, p := newMTLSEnv(t, 0)
	if _, err := ingest(t, e.client, logEvent("agent-a", 1), logEvent("agent-a", 2)); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	e.eng.SealAll(ctx)
	e.sink.mu.Lock()
	job := e.sink.jobs[0]
	e.sink.mu.Unlock()
	if err := job.Done(ctx, anchor.Result{EpochID: 1, TxHash: "0xfeed", BlockNumber: 9}); err != nil {
		t.Fatal(err)
	}
	req := func(agent string) *verilogv1.GetProofRequest {
		return &verilogv1.GetProofRequest{AgentId: agent, EpochId: 1, Selector: &verilogv1.GetProofRequest_LeafIndex{LeafIndex: 0}}
	}
	if _, err := e.client.GetProof(ctx, req("agent-a")); err != nil {
		t.Fatalf("agent's own proof: %v", err)
	}
	if _, err := e.dial(t, p.clientCreds(t, p.auditor)).GetProof(ctx, req("agent-a")); err != nil {
		t.Fatalf("auditor: %v", err)
	}
	// Another agent is refused before the evidence is even looked up: the
	// same answer whether or not the epoch exists.
	b := e.dial(t, p.clientCreds(t, p.agentB))
	for _, r := range []*verilogv1.GetProofRequest{req("agent-a"), {AgentId: "agent-a", EpochId: 99}} {
		if _, err := b.GetProof(ctx, r); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("other agent's proof: %v, want PermissionDenied", err)
		}
	}
	if _, err := e.dial(t, p.clientCreds(t, p.anonymous)).GetProof(ctx, req("agent-a")); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("cert without identity: %v, want Unauthenticated", err)
	}
}

func TestIdleStreamIsClosed(t *testing.T) {
	e, _ := newMTLSEnv(t, time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := e.client.IngestStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Activity keeps the stream open past the timeout.
	for i := uint64(1); i <= 3; i++ {
		time.Sleep(300 * time.Millisecond)
		if err := stream.Send(logEvent("agent-a", i)); err != nil {
			t.Fatal(err)
		}
		if ack, err := stream.Recv(); err != nil || !ack.Accepted {
			t.Fatalf("ack %d: %+v %v", i, ack, err)
		}
	}
	start := time.Now()
	_, err = stream.Recv()
	if status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("idle stream: %v, want DeadlineExceeded", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("idle stream closed after %s", d)
	}
}
