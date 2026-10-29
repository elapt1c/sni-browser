package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

// TestEvasionMatching verifies domain suffix matching.
func TestEvasionMatching(t *testing.T) {
	cases := map[string]string{
		"youtube.com":          "www.google.com",
		"music.youtube.com":    "www.google.com",
		"i.ytimg.com":          "www.google.com",
		"wordpress.com":        "en.wordpress.com",
		"login.wordpress.com":  "en.wordpress.com",
		"reddit.com":           "alb.reddit.com",
		"www.reddit.com":       "alb.reddit.com",
		"crates.io":            "alb.reddit.com",
		"example.com":          "", // no rule
		"notyoutube.com":       "", // suffix must be exact
		"youtube.com.evil.com": "", // not a suffix match
	}
	for host, want := range cases {
		r := matchEvasion(host)
		got := ""
		if r != nil {
			got = r.SNI
		}
		if got != want {
			t.Errorf("matchEvasion(%q) = %q, want %q", host, got, want)
		}
	}
}

// TestProxySNISpoofing starts a TLS server that records the ClientHello SNI,
// dials it with the proxy's spoofed-SNI TLS config, and asserts the server
// observed the spoofed SNI (not the real hostname).
func TestProxySNISpoofing(t *testing.T) {
	var receivedSNI string
	done := make(chan struct{})

	cert := selfSignedCert(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	targetAddr := ln.Addr().String()

	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		tlsConn := tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{cert},
			GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				receivedSNI = hello.ServerName
				return nil, nil
			},
		})
		if err := tlsConn.Handshake(); err != nil {
			return
		}
		io.Copy(io.Discard, tlsConn)
	}()

	// Mirror the proxy's SNI-spoofing dial path for wordpress.com
	// (relaxed=false, so the default cert verification path applies).
	sni, _, _ := spoofForHost("wordpress.com")
	if sni != "en.wordpress.com" {
		t.Fatalf("spoofForHost(wordpress.com) SNI = %q, want en.wordpress.com", sni)
	}

	tcpConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		t.Fatalf("dial target: %v", err)
	}
	tlsCfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // self-signed test cert
		MinVersion:         tls.VersionTLS12,
	}
	tlsClient := tls.Client(tcpConn, tlsCfg)
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	tlsClient.Close()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for server")
	}

	if receivedSNI != "en.wordpress.com" {
		t.Errorf("server received SNI %q, want %q (spoofed)", receivedSNI, "en.wordpress.com")
	}
}

// spoofForHost returns the (sni, ip, relaxed) for a host, matching the
// proxy's evasion logic.
func spoofForHost(host string) (string, string, bool) {
	if r := matchEvasion(host); r != nil {
		return r.SNI, r.IP, r.Relaxed
	}
	return host, "", false
}

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "www.google.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"www.google.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	return cert
}
