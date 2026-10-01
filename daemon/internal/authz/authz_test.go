package authz

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func certWith(uris ...string) *x509.Certificate {
	c := &x509.Certificate{}
	for _, s := range uris {
		u, err := url.Parse(s)
		if err != nil {
			panic(err)
		}
		c.URIs = append(c.URIs, u)
	}
	return c
}

func TestFromCert(t *testing.T) {
	for _, tc := range []struct {
		uris []string
		want Identity
	}{
		{[]string{"verilog://agent/e2e-agent"}, Identity{RoleAgent, "e2e-agent"}},
		{[]string{"verilog://auditor/alice"}, Identity{RoleAuditor, "alice"}},
		{[]string{"https://example.com/x", URI(RoleAgent, "team/bot 1")}, Identity{RoleAgent, "team/bot 1"}},
		{[]string{URI(RoleAgent, "ünï")}, Identity{RoleAgent, "ünï"}},
	} {
		got, err := FromCert(certWith(tc.uris...))
		if err != nil || got != tc.want {
			t.Errorf("%v: %+v %v, want %+v", tc.uris, got, err, tc.want)
		}
	}
	for _, uris := range [][]string{
		nil,
		{"https://example.com/agent/x"},
		{"verilog://agent/a", "verilog://agent/b"},
		{"verilog://admin/root"},
		{"verilog://agent/"},
		{"verilog://agent/a/b"},
		{"verilog://agent/a?x=1"},
		{"verilog://agent/a#f"},
		{"verilog://u@agent/a"},
	} {
		if id, err := FromCert(certWith(uris...)); err == nil {
			t.Errorf("%v accepted as %+v", uris, id)
		}
	}
}

func ctxWith(cert *x509.Certificate) context.Context {
	info := credentials.TLSInfo{}
	if cert != nil {
		info.State = tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{cert}}}
	}
	return peer.NewContext(context.Background(), &peer.Peer{AuthInfo: info})
}

func TestPolicy(t *testing.T) {
	p := Policy{Required: true}
	agent := ctxWith(certWith(URI(RoleAgent, "a")))
	auditor := ctxWith(certWith(URI(RoleAuditor, "x")))

	if id, ok, err := p.CanIngest(agent); err != nil || !ok || IngestAgent(id, ok, "a") != "" || IngestAgent(id, ok, "b") == "" {
		t.Fatalf("agent ingest: %+v %v %v", id, ok, err)
	}
	if _, _, err := p.CanIngest(auditor); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("auditor ingest: %v", err)
	}
	for _, ctx := range []context.Context{context.Background(), ctxWith(nil), ctxWith(certWith())} {
		if _, _, err := p.CanIngest(ctx); status.Code(err) != codes.Unauthenticated {
			t.Fatalf("no identity: %v", err)
		}
		if err := p.CanReadProof(ctx, "a"); status.Code(err) != codes.Unauthenticated {
			t.Fatalf("no identity proof: %v", err)
		}
	}
	if p.CanReadProof(agent, "a") != nil || p.CanReadProof(auditor, "a") != nil || p.CanReadProof(auditor, "zzz") != nil {
		t.Fatal("allowed proof reads refused")
	}
	if err := p.CanReadProof(agent, "b"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("agent reads other agent: %v", err)
	}

	// Dev mode (plaintext): everyone may do everything.
	var dev Policy
	if id, ok, err := dev.CanIngest(context.Background()); err != nil || ok || IngestAgent(id, ok, "any") != "" {
		t.Fatal("dev mode ingest refused")
	}
	if dev.CanReadProof(context.Background(), "any") != nil {
		t.Fatal("dev mode proof refused")
	}
}
