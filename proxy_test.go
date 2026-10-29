package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"sync"
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

// TestRewriteClientHelloSNI captures a real TLS ClientHello, rewrites its SNI,
// feeds the result to a TLS server, and asserts the server observed the
// spoofed SNI.
func TestRewriteClientHelloSNI(t *testing.T) {
	cases := []struct{ orig, want string }{
		{"wordpress.com", "en.wordpress.com"}, // longer replacement
		{"youtube.com", "www.google.com"},     // longer replacement
		{"reddit.com", "alb.reddit.com"},      // longer replacement
		{"crates.io", "alb.reddit.com"},       // longer replacement
		{"abcdefghijklmnop.com", "x.io"},      // shorter replacement
	}
	for _, tc := range cases {
		hello := captureClientHello(t, tc.orig)
		out, changed, complete, err := rewriteClientHelloSNI(hello, tc.want)
		if err != nil {
			t.Fatalf("%s→%s: rewrite error: %v", tc.orig, tc.want, err)
		}
		if !complete {
			t.Fatalf("%s→%s: expected complete=true", tc.orig, tc.want)
		}
		if !changed {
			t.Fatalf("%s→%s: expected changed=true", tc.orig, tc.want)
		}
		got := serverSNIFromRaw(t, out)
		if got != tc.want {
			t.Errorf("%s→%s: server parsed SNI %q, want %q", tc.orig, tc.want, got, tc.want)
		}
	}
}

// TestRewriteClientHelloSNINoChange verifies the rewriter is a no-op when the
// SNI already matches the target.
func TestRewriteClientHelloSNINoChange(t *testing.T) {
	hello := captureClientHello(t, "www.google.com")
	out, changed, complete, err := rewriteClientHelloSNI(hello, "www.google.com")
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if !complete {
		t.Fatal("expected complete=true")
	}
	if changed {
		t.Fatal("expected changed=false when SNI already equals target")
	}
	if string(out) != string(hello) {
		t.Fatal("output should be byte-identical when no change")
	}
}

// TestProxyEndToEnd verifies the full CONNECT → relay path: an HTTPS request
// made through the proxy reaches a local TLS server and the response returns
// intact (regression for the double-TLS "unexpected TLS packet" bug).
func TestProxyEndToEnd(t *testing.T) {
	cert := selfSignedCert(t)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("hello via sni-browser proxy"))
		}),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
	}
	srvLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.ServeTLS(srvLn, "", "")
	defer srv.Close()

	proxy := NewProxy("127.0.0.1:0")
	if err := proxy.Start(); err != nil {
		t.Fatal(err)
	}
	defer proxy.Stop()
	proxyAddr := proxy.Listener.Addr().String()

	proxyURL, _ := url.Parse("http://" + proxyAddr)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get("https://" + srvLn.Addr().String() + "/")
	if err != nil {
		t.Fatalf("GET via proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello via sni-browser proxy" {
		t.Errorf("unexpected body: %q", body)
	}
}

// captureClientHello opens a TCP listener, drives a tls.Client handshake, and
// returns the raw ClientHello bytes the client sent.
func captureClientHello(t *testing.T, sni string) []byte {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var mu sync.Mutex
	var captured []byte
	done := make(chan struct{})

	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 0, 65536)
		tmp := make([]byte, 4096)
		for {
			n, err := conn.Read(tmp)
			if n > 0 {
				buf = append(buf, tmp[:n]...)
			}
			// Stop once we have a full TLS record.
			if len(buf) >= 5 && len(buf) >= 5+int(binary.BigEndian.Uint16(buf[3:5])) {
				break
			}
			if err != nil {
				break
			}
		}
		mu.Lock()
		captured = buf
		mu.Unlock()
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := tls.Client(conn, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
	_ = client.Handshake() // sends ClientHello, then errors once the server closes

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout capturing ClientHello")
	}

	mu.Lock()
	defer mu.Unlock()
	return captured
}

// serverSNIFromRaw feeds raw ClientHello bytes to a TLS server and returns the
// SNI the server parsed.
func serverSNIFromRaw(t *testing.T, raw []byte) string {
	t.Helper()
	var sni string
	done := make(chan struct{})
	cert := selfSignedCert(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

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
				sni = hello.ServerName
				return nil, nil
			},
		})
		_ = tlsConn.Handshake() // parses the ClientHello; write side may fail after we close
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Write(raw)
	_ = conn.Close()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for server")
	}
	return sni
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
