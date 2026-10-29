package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CA is a long-lived root certificate authority used to mint per-host leaf
// certificates for MITM'd connections. The browser trusts it, so those leaf
// certs validate as if they came from the real origin.
type CA struct {
	dir      string
	key      *ecdsa.PrivateKey
	cert     *x509.Certificate
	tlsCert  tls.Certificate
	mu       sync.Mutex
	leafs    map[string]*tls.Certificate
	leafKeys map[string]*ecdsa.PrivateKey
}

// ensureCA loads the CA from dir, generating a fresh one if none exists.
// The CA certificate and key are persisted as ca.pem and ca.key.
func ensureCA(dir string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create CA dir: %w", err)
	}
	ca := &CA{
		dir:      dir,
		leafs:    map[string]*tls.Certificate{},
		leafKeys: map[string]*ecdsa.PrivateKey{},
	}

	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca.key")

	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if certErr == nil && keyErr == nil {
		if err := ca.load(certPEM, keyPEM); err == nil {
			return ca, nil
		}
		// Corrupt on-disk CA — regenerate.
	}

	if err := ca.generate(); err != nil {
		return nil, err
	}
	if err := os.WriteFile(certPath, ca.certPEM(), 0o600); err != nil {
		return nil, fmt.Errorf("write ca.pem: %w", err)
	}
	if err := os.WriteFile(keyPath, ca.keyPEM(), 0o600); err != nil {
		return nil, fmt.Errorf("write ca.key: %w", err)
	}
	return ca, nil
}

func (c *CA) load(certPEM, keyPEM []byte) error {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("bad CA cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse CA cert: %w", err)
	}
	block, _ = pem.Decode(keyPEM)
	if block == nil {
		return fmt.Errorf("bad CA key PEM")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse CA key: %w", err)
	}
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("load CA keypair: %w", err)
	}
	c.cert = cert
	c.key = key
	c.tlsCert = tlsCert
	return nil
}

func (c *CA) generate() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate CA key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("CA serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "SNI Browser Root CA", Organization: []string{"SNI Browser"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create CA cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("parse generated CA: %w", err)
	}
	c.key = key
	c.cert = cert
	c.tlsCert = tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}
	return nil
}

func (c *CA) certPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw})
}

func (c *CA) keyPEM() []byte {
	der, _ := x509.MarshalECPrivateKey(c.key)
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// leafForHost returns (caching) a leaf certificate valid for host, signed by
// the CA. The certificate is valid for host as both CN and SAN.
func (c *CA) leafForHost(host string) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cert, ok := c.leafs[host]; ok {
		return cert, nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("leaf serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("create leaf cert: %w", err)
	}
	leaf := &tls.Certificate{
		Certificate: [][]byte{der, c.cert.Raw},
		PrivateKey:  key,
	}
	c.leafs[host] = leaf
	c.leafKeys[host] = key
	return leaf, nil
}
