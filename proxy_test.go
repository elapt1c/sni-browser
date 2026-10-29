package main

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/url"
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

// TestCAAndLeaf verifies the CA is a CA and that minted leaf certs chain to it
// and are valid for their hostname.
func TestCAAndLeaf(t *testing.T) {
	ca, err := ensureCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !ca.cert.IsCA {
		t.Fatal("generated cert should be a CA")
	}

	leaf, err := ca.leafForHost("youtube.com")
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := leafCert.VerifyHostname("youtube.com"); err != nil {
		t.Fatalf("leaf should be valid for youtube.com: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	if _, err := leafCert.Verify(x509.VerifyOptions{Roots: pool, DNSName: "youtube.com"}); err != nil {
		t.Fatalf("leaf should chain to CA: %v", err)
	}
}

// TestProxyMITM simulates the YouTube case end-to-end: the origin serves a cert
// for a DIFFERENT name than the requested host, the proxy MITMs the browser
// (serving a CA-signed cert for the requested host) and connects upstream with
// a spoofed SNI, relaxing only the upstream cert-name check.
func TestProxyMITM(t *testing.T) {
	ca, err := ensureCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	// Origin server: cert for "edge.googlevideo.com" (mismatched vs the SNI we
	// will present upstream, "www.google.com"), like real Google CDN edges.
	originCert, err := ca.leafForHost("edge.googlevideo.com")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("youtube body"))
		}),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{*originCert}},
	}
	srvLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.ServeTLS(srvLn, "", "")
	defer srv.Close()
	_, originPort, _ := net.SplitHostPort(srvLn.Addr().String())

	// Temporary rule that pins to localhost and relaxes the cert-name check.
	saved := evasionRules
	evasionRules = append(evasionRules, EvasionRule{"mitm.test", "www.google.com", "127.0.0.1", true})
	defer func() { evasionRules = saved }()

	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)

	proxy := NewProxy("127.0.0.1:0", ca)
	proxy.RootCAs = pool // so upstream verification trusts our test CA
	if err := proxy.Start(); err != nil {
		t.Fatal(err)
	}
	defer proxy.Stop()
	proxyAddr := proxy.Listener.Addr().String()

	proxyURL, _ := url.Parse("http://" + proxyAddr)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: pool}, // browser trusts our CA
		},
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get("https://mitm.test:" + originPort + "/")
	if err != nil {
		t.Fatalf("GET via MITM proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "youtube body" {
		t.Errorf("unexpected body: %q", body)
	}
}

// TestProxyTransparent verifies non-evasion hosts are blind-spliced (no MITM).
func TestProxyTransparent(t *testing.T) {
	ca, err := ensureCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	originCert, err := ca.leafForHost("localhost")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("hello via sni-browser proxy"))
		}),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{*originCert}},
	}
	srvLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.ServeTLS(srvLn, "", "")
	defer srv.Close()

	proxy := NewProxy("127.0.0.1:0", ca)
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
