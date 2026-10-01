// Package authz derives a caller's identity from its mTLS client certificate
// and decides what that identity may do.
//
// Identity scheme: the client certificate carries exactly one URI SAN with the
// scheme "verilog":
//
//	verilog://agent/<agent_id>     an agent: may ingest events of <agent_id>
//	                               and read proofs of <agent_id>
//	verilog://auditor/<name>       a read-only auditor: may read every proof,
//	                               may not ingest
//
// <agent_id> and <name> are path-escaped (url.PathEscape), so any agent id,
// including one with "/" or spaces, maps to exactly one URI. A certificate
// with no verilog URI SAN, more than one, or an unknown role has no identity
// and is refused.
package authz

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// Scheme is the URI scheme of identity SANs.
const Scheme = "verilog"

// Role is what kind of client an identity is.
type Role string

const (
	RoleAgent   Role = "agent"
	RoleAuditor Role = "auditor"
)

// Identity is an authenticated client.
type Identity struct {
	Role Role
	Name string // agent_id for RoleAgent, the auditor's name for RoleAuditor
}

func (id Identity) String() string { return URI(id.Role, id.Name) }

// URI returns the SAN URI of an identity.
func URI(role Role, name string) string {
	return Scheme + "://" + string(role) + "/" + url.PathEscape(name)
}

// FromCert extracts the identity from a verified client certificate.
func FromCert(cert *x509.Certificate) (Identity, error) {
	var found []*url.URL
	for _, u := range cert.URIs {
		if strings.EqualFold(u.Scheme, Scheme) {
			found = append(found, u)
		}
	}
	switch len(found) {
	case 0:
		return Identity{}, errors.New("client certificate has no verilog:// URI SAN")
	case 1:
	default:
		return Identity{}, errors.New("client certificate has more than one verilog:// URI SAN")
	}
	u := found[0]
	role := Role(u.Host)
	if role != RoleAgent && role != RoleAuditor {
		return Identity{}, fmt.Errorf("client certificate identity %q: unknown role %q", u.String(), u.Host)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return Identity{}, fmt.Errorf("client certificate identity %q is malformed", u.String())
	}
	raw := strings.TrimPrefix(u.EscapedPath(), "/")
	if raw == "" || strings.Contains(raw, "/") {
		return Identity{}, fmt.Errorf("client certificate identity %q must be verilog://%s/<escaped name>", u.String(), role)
	}
	name, err := url.PathUnescape(raw)
	if err != nil || name == "" {
		return Identity{}, fmt.Errorf("client certificate identity %q is malformed", u.String())
	}
	return Identity{Role: role, Name: name}, nil
}

// Policy decides access. With Required false (plaintext dev mode, no client
// certificates), every caller may do everything.
type Policy struct {
	Required bool
}

// Caller returns the identity of the RPC's peer. ok is false when identities
// are not required (dev mode). A missing or invalid identity is an
// Unauthenticated status error.
func (p Policy) Caller(ctx context.Context) (id Identity, ok bool, err error) {
	if !p.Required {
		return Identity{}, false, nil
	}
	pr, found := peer.FromContext(ctx)
	if !found {
		return Identity{}, false, status.Error(codes.Unauthenticated, "no peer information")
	}
	info, isTLS := pr.AuthInfo.(credentials.TLSInfo)
	if !isTLS || len(info.State.VerifiedChains) == 0 || len(info.State.VerifiedChains[0]) == 0 {
		return Identity{}, false, status.Error(codes.Unauthenticated, "a verified client certificate is required")
	}
	id, err = FromCert(info.State.VerifiedChains[0][0])
	if err != nil {
		return Identity{}, false, status.Error(codes.Unauthenticated, err.Error())
	}
	return id, true, nil
}

// CanIngest reports whether the caller may open an ingest stream at all
// (as a status error, or nil).
func (p Policy) CanIngest(ctx context.Context) (Identity, bool, error) {
	id, ok, err := p.Caller(ctx)
	if err != nil || !ok {
		return id, ok, err
	}
	if id.Role != RoleAgent {
		return id, ok, status.Errorf(codes.PermissionDenied, "%s may not ingest events (only agent certificates can)", id)
	}
	return id, ok, nil
}

// IngestAgent returns the rejection reason for an event of agentID submitted
// by caller, or "" when allowed. ok is the result of Caller.
func IngestAgent(caller Identity, ok bool, agentID string) string {
	if !ok {
		return ""
	}
	if caller.Role != RoleAgent || caller.Name != agentID {
		return fmt.Sprintf("agent_id %q does not match the client certificate identity %s", agentID, caller)
	}
	return ""
}

// CanReadProof returns a PermissionDenied status error unless the caller may
// read proofs of agentID: an auditor, or the agent itself.
func (p Policy) CanReadProof(ctx context.Context, agentID string) error {
	id, ok, err := p.Caller(ctx)
	if err != nil || !ok {
		return err
	}
	switch {
	case id.Role == RoleAuditor:
		return nil
	case id.Role == RoleAgent && id.Name == agentID:
		return nil
	}
	return status.Errorf(codes.PermissionDenied, "%s may not read proofs of agent %q", id, agentID)
}
