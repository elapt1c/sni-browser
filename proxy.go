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

// Proxy is an HTTP/HTTPS forward proxy. For hosts that match an evasion rule
// it performs a TLS MITM: the browser is served a certificate minted by our
// CA, and the upstream connection is made with a spoofed SNI. All other hosts
// are relayed transparently (no MITM).
type Proxy struct {
	Addr     string
	Listener net.Listener
	server   *http.Server
	ca       *CA
	// RootCAs overrides the trust roots used for upstream (origin) TLS
	// verification. nil means the system roots. Exposed for testing.
	RootCAs *x509.CertPool
	mu      sync.Mutex
}

// NewProxy creates a forward proxy on the given listen address.
func NewProxy(addr string, ca *CA) *Proxy {
	return &Proxy{Addr: addr, ca: ca}
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

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	hostPort := r.Host
	if !strings.Contains(hostPort, ":") {
		hostPort += ":443"
	}
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		http.Error(w, "bad host:port", http.StatusBadRequest)
		return
	}

	rule := matchEvasion(host)
	if rule != nil {
		p.handleMITM(w, host, port, rule)
		return
	}
	p.handleTransparent(w, hostPort)
}

// handleMITM terminates the client TLS with a CA-signed leaf cert for the
// original host, then dials upstream with a spoofed SNI and relays decrypted
// bytes between the two TLS sessions. This is what makes the YouTube/Google
// CDN family work: the browser sees a valid cert for youtube.com, while the
// upstream handshake presents an allowed SNI.
func (p *Proxy) handleMITM(w http.ResponseWriter, host, port string, rule *EvasionRule) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}
	clientRaw, bufrw, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	bufrw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	bufrw.Flush()

	leaf, err := p.ca.leafForHost(host)
	if err != nil {
		log.Printf("[mitm] leaf cert %s: %v", host, err)
		clientRaw.Close()
		return
	}

	clientTLS := tls.Server(clientRaw, &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		NextProtos:   []string{"http/1.1"},
		MinVersion:   tls.VersionTLS12,
	})
	if err := clientTLS.Handshake(); err != nil {
		log.Printf("[mitm] client handshake %s: %v", host, err)
		clientRaw.Close()
		return
	}

	targetAddr := net.JoinHostPort(host, port)
	if rule.IP != "" {
		targetAddr = net.JoinHostPort(rule.IP, port)
	}
	upstreamRaw, err := (&net.Dialer{Timeout: 15 * time.Second}).Dial("tcp", targetAddr)
	if err != nil {
		log.Printf("[mitm] upstream dial %s: %v", targetAddr, err)
		clientTLS.Close()
		return
	}

	relaxed := rule.Relaxed
	upCfg := &tls.Config{
		ServerName:         rule.SNI,
		InsecureSkipVerify: relaxed,
		RootCAs:            p.RootCAs,
		NextProtos:         []string{"http/1.1"},
		MinVersion:         tls.VersionTLS12,
	}
	if relaxed {
		upCfg.VerifyPeerCertificate = buildRelaxedVerifier(p.RootCAs)
	}
	upstreamTLS := tls.Client(upstreamRaw, upCfg)
	if err := upstreamTLS.Handshake(); err != nil {
		log.Printf("[mitm] upstream handshake %s (SNI=%s): %v", host, rule.SNI, err)
		upstreamRaw.Close()
		clientTLS.Close()
		return
	}

	log.Printf("[mitm] CONNECT %s → SNI=%s (MITM)", host, rule.SNI)
	relayTLS(clientTLS, upstreamTLS)
}

// handleTransparent is a blind splice for non-evasion hosts: no MITM, just a
// byte relay between the browser and the origin.
func (p *Proxy) handleTransparent(w http.ResponseWriter, hostPort string) {
	upstream, err := (&net.Dialer{Timeout: 15 * time.Second}).Dial("tcp", hostPort)
	if err != nil {
		log.Printf("[proxy] CONNECT dial %s: %v", hostPort, err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		upstream.Close()
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}
	client, bufrw, err := hijacker.Hijack()
	if err != nil {
		upstream.Close()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	bufrw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	bufrw.Flush()
	log.Printf("[proxy] CONNECT %s (passthrough)", hostPort)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(upstream, client)
		if c, ok := upstream.(*net.TCPConn); ok {
			c.CloseWrite()
		} else {
			upstream.Close()
		}
	}()
	go func() {
		defer wg.Done()
		io.Copy(client, upstream)
		if c, ok := client.(*net.TCPConn); ok {
			c.CloseWrite()
		} else {
			client.Close()
		}
	}()
	wg.Wait()
	client.Close()
	upstream.Close()
}

// relayTLS pipes decrypted bytes between two TLS connections. Closing one side
// once either direction finishes unblocks the other (HTTP/1.1 responses are
// self-delimiting, so no half-close is needed).
func relayTLS(a, b *tls.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(b, a)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(a, b)
		done <- struct{}{}
	}()
	<-done
	a.Close()
	b.Close()
}

// buildRelaxedVerifier returns a VerifyPeerCertificate hook that skips the
// hostname check but still validates the certificate chain against the given
// roots (nil = system roots). This mirrors mitmproxy's "keep chain validation,
// drop cert-name check" for YouTube/Google CDN edges that serve a fixed cert
// unrelated to the allowed evasion SNI.
func buildRelaxedVerifier(roots *x509.CertPool) func([][]byte, [][]*x509.Certificate) error {
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
			Roots:         roots,
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
