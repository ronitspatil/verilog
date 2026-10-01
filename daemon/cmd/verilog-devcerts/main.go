// Command verilog-devcerts writes DEVELOPMENT-ONLY mTLS certificates for
// verilogd: a throwaway CA, a server certificate, one client certificate per
// agent (URI SAN verilog://agent/<agent_id>) and per auditor (URI SAN
// verilog://auditor/<name>). Never use them outside local development; issue
// production certificates from your own CA or PKI (docs/operations.md).
//
//	verilog-devcerts --out DIR [--host localhost --host 127.0.0.1] [--agent ID]... [--auditor NAME]...
//
// Each run makes a new CA, whose key is discarded. Files: ca.pem, server.pem/server-key.pem,
// agent-<ID>.pem/agent-<ID>-key.pem, auditor-<NAME>.pem/auditor-<NAME>-key.pem.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ronitspatil/verilog/daemon/internal/authz"
	"github.com/ronitspatil/verilog/daemon/internal/devpki"
)

type list []string

func (l *list) String() string     { return strings.Join(*l, ",") }
func (l *list) Set(v string) error { *l = append(*l, v); return nil }

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "verilog-devcerts:", err)
		os.Exit(2)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("verilog-devcerts", flag.ContinueOnError)
	out := fs.String("out", "dev-certs", "output directory")
	var hosts, agents, auditors list
	fs.Var(&hosts, "host", "server DNS name or IP (repeatable; default localhost and 127.0.0.1)")
	fs.Var(&agents, "agent", "agent id to issue a client certificate for (repeatable)")
	fs.Var(&auditors, "auditor", "auditor name to issue a client certificate for (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	if len(hosts) == 0 {
		hosts = list{"localhost", "127.0.0.1", "::1"}
	}
	if err := os.MkdirAll(*out, 0o700); err != nil {
		return err
	}
	ca, err := devpki.NewCA("VeriLog DEV ONLY CA")
	if err != nil {
		return err
	}
	// The CA key is not written: every run makes a new CA.
	if err := os.WriteFile(filepath.Join(*out, "ca.pem"), ca.CertPEM, 0o644); err != nil {
		return err
	}
	srv, err := ca.Server(hosts...)
	if err != nil {
		return err
	}
	if err := write(*out, "server", srv); err != nil {
		return err
	}
	for _, c := range []struct {
		role  authz.Role
		names list
	}{{authz.RoleAgent, agents}, {authz.RoleAuditor, auditors}} {
		for _, name := range c.names {
			if name == "" || strings.ContainsAny(name, `/\`) || name == "." || name == ".." {
				return fmt.Errorf("%s name %q cannot be used as a file name", c.role, name)
			}
			cert, err := ca.Client(string(c.role)+" "+name+" (DEV ONLY)", authz.URI(c.role, name))
			if err != nil {
				return err
			}
			if err := write(*out, string(c.role)+"-"+name, cert); err != nil {
				return err
			}
		}
	}
	readme := "DEVELOPMENT-ONLY certificates written by verilog-devcerts (make certs).\n" +
		"Each run makes a new CA (its key is not kept); re-run to add identities.\n" +
		"Never use these outside local development. See docs/operations.md.\n"
	if err := os.WriteFile(filepath.Join(*out, "README"), []byte(readme), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote DEV-ONLY certificates to %s\n", *out)
	return nil
}

func write(dir, base string, c *devpki.Cert) error {
	if c == nil {
		return errors.New("no certificate")
	}
	if err := os.WriteFile(filepath.Join(dir, base+".pem"), c.CertPEM, 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, base+"-key.pem"), c.KeyPEM, 0o600)
}
