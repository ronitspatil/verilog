package config

import (
	"io"
	"strings"
	"testing"
	"time"
)

func TestTransport(t *testing.T) {
	base := []string{"--rpc", "http://x", "--contract", "0x5FbDB2315678afecb367f032d93F642f64180aa3"}
	load := func(env map[string]string, extra ...string) (*Config, error) {
		return Load(append(append([]string{}, base...), extra...), envOf(env), io.Discard)
	}
	mtls := []string{"--tls-cert", "s.pem", "--tls-key", "s-key.pem", "--tls-client-ca", "ca.pem"}

	c, err := load(nil, mtls...)
	if err != nil || !c.Transport.MTLS() || c.Transport.InsecurePlaintext {
		t.Fatalf("mtls: %+v %v", c, err)
	}
	tr := c.Transport
	if tr.MaxConnections != 1024 || tr.MaxConcurrentStreams != 64 || tr.StreamIdleTimeout != 15*time.Minute ||
		tr.KeepaliveMinTime != 10*time.Second || tr.KeepaliveTime != 30*time.Second || tr.KeepaliveTimeout != 10*time.Second {
		t.Fatalf("defaults: %+v", tr)
	}
	c, err = load(map[string]string{"VERILOG_INSECURE_PLAINTEXT": "1", "VERILOG_MAX_CONNECTIONS": "0"},
		"--max-concurrent-streams", "8", "--stream-idle-timeout", "0")
	if err != nil || !c.Transport.InsecurePlaintext || c.Transport.MTLS() || c.Transport.MaxConnections != 0 ||
		c.Transport.MaxConcurrentStreams != 8 || c.Transport.StreamIdleTimeout != 0 {
		t.Fatalf("plaintext via env: %+v %v", c, err)
	}

	for _, tc := range []struct {
		env  map[string]string
		args []string
		want string
	}{
		{nil, nil, "no transport security"},
		{nil, []string{"--tls-cert", "s.pem", "--tls-key", "s-key.pem"}, "server-only TLS is not supported"},
		{nil, []string{"--tls-cert", "s.pem", "--tls-client-ca", "ca.pem"}, "must be set together"},
		{nil, append([]string{"--insecure-plaintext"}, mtls...), "cannot be combined"},
		{map[string]string{"VERILOG_INSECURE_PLAINTEXT": "maybe"}, nil, "VERILOG_INSECURE_PLAINTEXT"},
		{nil, append([]string{"--max-concurrent-streams", "0"}, mtls...), "max concurrent streams"},
		{nil, append([]string{"--max-connections", "-1"}, mtls...), "max connections"},
		{nil, append([]string{"--stream-idle-timeout", "soon"}, mtls...), "idle timeout"},
		{nil, append([]string{"--keepalive-time", "0s"}, mtls...), "keepalive"},
	} {
		if _, err := load(tc.env, tc.args...); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v %v: %v, want error containing %q", tc.env, tc.args, err, tc.want)
		}
	}
}
