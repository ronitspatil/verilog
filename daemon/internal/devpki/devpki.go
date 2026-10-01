// Package devpki issues DEVELOPMENT-ONLY certificates for verilogd's mTLS: a
// throwaway CA, a server certificate and client certificates carrying the
// identity URI SANs of package authz. It is used by tests and by
// cmd/verilog-devcerts (make certs). Production deployments issue
// certificates from their own CA or PKI.
package devpki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"time"
)

// Cert is a certificate with its key.
type Cert struct {
	Cert    *x509.Certificate
	Key     *ecdsa.PrivateKey
	CertPEM []byte
	KeyPEM  []byte
}

// Validity of every issued certificate.
const Validity = 90 * 24 * time.Hour

// NewCA returns a self-signed CA.
func NewCA(commonName string) (*Cert, error) {
	tmpl := &x509.Certificate{
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"VeriLog DEV ONLY"}},
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	return issue(tmpl, nil)
}

// Server issues a server certificate for the given DNS names and IPs.
func (ca *Cert) Server(hosts ...string) (*Cert, error) {
	tmpl := &x509.Certificate{
		Subject:     pkix.Name{CommonName: "verilogd (DEV ONLY)"},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	return issue(tmpl, ca)
}

// Client issues a client certificate with the given URI SANs (none for a
// certificate without identity).
func (ca *Cert) Client(commonName string, uris ...string) (*Cert, error) {
	tmpl := &x509.Certificate{
		Subject:     pkix.Name{CommonName: commonName},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	for _, s := range uris {
		u, err := url.Parse(s)
		if err != nil {
			return nil, err
		}
		tmpl.URIs = append(tmpl.URIs, u)
	}
	return issue(tmpl, ca)
}

func issue(tmpl *x509.Certificate, parent *Cert) (*Cert, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	tmpl.SerialNumber = serial
	tmpl.NotBefore = time.Now().Add(-time.Minute)
	tmpl.NotAfter = time.Now().Add(Validity)
	signer, parentCert := key, tmpl
	if parent != nil {
		signer, parentCert = parent.Key, parent.Cert
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, &key.PublicKey, signer)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &Cert{
		Cert:    cert,
		Key:     key,
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}, nil
}
