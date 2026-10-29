package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Proxy is an HTTP/HTTPS forward proxy that rewrites SNI on outbound
// TLS connections according to the evasion rules.
type Proxy struct {
	Addr     string
	Listener net.Listener
	server   *http.Server
	mu       sync.Mutex
}

// NewProxy creates a forward proxy on the given listen address.
func NewProxy(addr string) *Proxy {
	return &Proxy{Addr: addr}
}

// Start begins listening. It returns when the listener is ready.
func (p *Proxy) Start() error {
	l, err := net.Listen("tcp", p.Addr)
	if err != nil {
		return fmt.Errorf("proxy listen: %w", err)
	}
	p.Listener = l
	p.server = &http.Server{
		Handler:           http.HandlerFunc(p.handleRequest),
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	log.Printf("[proxy] listening on %s", l.Addr().String())
	go p.server.Serve(l)
	return nil
}

// Stop shuts down the proxy.
func (p *Proxy) Stop() error {
	if p.server != nil {
		return p.server.Close()
	}
	return nil
}

func (p *Proxy) handleRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.handleHTTP(w, r)
}

// handleHTTP forwards plain HTTP requests.
func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	transport := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second}).DialContext,
		ResponseHeaderTimeout: 30 * time.Second,
	}
	resp, err := transport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// handleConnect handles CONNECT tunnels (HTTPS traffic).
// It dials the target, optionally rewriting the SNI, then relays bytes.
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	hostPort := r.Host
	if !strings.Contains(hostPort, ":") {
		hostPort = hostPort + ":443"
	}
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		http.Error(w, "bad host:port", http.StatusBadRequest)
		return
	}

	// Check evasion rules for this host.
	rule := matchEvasion(host)

	// Determine target address.
	targetAddr := hostPort
	if rule != nil && rule.IP != "" {
		targetAddr = net.JoinHostPort(rule.IP, port)
	}

	// Resolve target.
	tcpConn, err := (&net.Dialer{Timeout: 15 * time.Second}).Dial("tcp", targetAddr)
	if err != nil {
		log.Printf("[proxy] CONNECT dial %s: %v", targetAddr, err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	// Build TLS config with optional SNI spoofing.
	sni := host
	if rule != nil {
		sni = rule.SNI
	}

	relaxed := rule != nil && rule.Relaxed
	tlsCfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: relaxed,
		MinVersion:         tls.VersionTLS12,
	}
	if relaxed {
		tlsCfg.VerifyPeerCertificate = buildRelaxedVerifier()
	}

	tlsConn := tls.Client(tcpConn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("[proxy] TLS handshake to %s (SNI=%s): %v", hostPort, sni, err)
		tcpConn.Close()
		http.Error(w, "TLS handshake failed", http.StatusBadGateway)
		return
	}

	// Hijack the client connection.
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		tlsConn.Close()
		return
	}
	clientConn, bufrw, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		tlsConn.Close()
		return
	}

	// Send 200 to client.
	bufrw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	bufrw.Flush()

	if rule != nil {
		log.Printf("[proxy] CONNECT %s → SNI=%s (evasion)", hostPort, sni)
	} else {
		log.Printf("[proxy] CONNECT %s (passthrough)", hostPort)
	}

	// Relay.
	go func() {
		io.Copy(tlsConn, clientConn)
		tlsConn.Close()
	}()
	io.Copy(clientConn, tlsConn)
	clientConn.Close()
}

// buildRelaxedVerifier returns a VerifyPeerCertificate hook that skips the
// hostname check but still validates the certificate chain against the
// system roots. This mirrors mitmproxy's "keep chain validation, drop
// cert-name check" for YouTube/Google CDN edges that serve a fixed cert
// unrelated to the allowed evasion SNI.
func buildRelaxedVerifier() func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("no certificates presented")
		}
		certs := make([]*x509.Certificate, 0, len(rawCerts))
		intermediates := x509.NewCertPool()
		for i, raw := range rawCerts {
			c, err := x509.ParseCertificate(raw)
			if err != nil {
				return fmt.Errorf("parse cert %d: %w", i, err)
			}
			certs = append(certs, c)
			if i > 0 {
				intermediates.AddCert(c)
			}
		}
		// No DNSName → hostname check is skipped; chain still validated.
		_, err := certs[0].Verify(x509.VerifyOptions{
			Roots:         nil, // system roots
			Intermediates: intermediates,
			CurrentTime:   time.Now(),
		})
		return err
	}
}

// ParseProxyURL parses the proxy's listen address to an http.ProxyURL function.
func (p *Proxy) ProxyFunc() func(*http.Request) (*url.URL, error) {
	proxyURL, _ := url.Parse("http://" + p.Addr)
	return http.ProxyURL(proxyURL)
}
