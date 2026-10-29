package main

import (
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

// Proxy is an HTTP/HTTPS forward proxy that rewrites the TLS SNI on outbound
// connections according to the evasion rules.
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

// handleConnect handles CONNECT tunnels (HTTPS traffic). It is a transparent
// tunnel: the proxy relays bytes end-to-end and, when a rule matches,
// rewrites the SNI inside the client's first TLS ClientHello before it
// reaches the server. No MITM certificates are involved.
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

	// Resolve the target (optionally pinning the IP for rules that need it).
	targetAddr := hostPort
	if rule != nil && rule.IP != "" {
		targetAddr = net.JoinHostPort(rule.IP, port)
	}

	upstream, err := (&net.Dialer{Timeout: 15 * time.Second}).Dial("tcp", targetAddr)
	if err != nil {
		log.Printf("[proxy] CONNECT dial %s: %v", targetAddr, err)
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

	if rule != nil {
		log.Printf("[proxy] CONNECT %s → SNI=%s (rewrite)", hostPort, rule.SNI)
	} else {
		log.Printf("[proxy] CONNECT %s (passthrough)", hostPort)
	}

	relayBidirectional(client, upstream, rule)
}

// relayBidirectional copies bytes in both directions using half-closes so an
// EOF from one side is propagated to the other without truncating the reply.
func relayBidirectional(client, upstream net.Conn, rule *EvasionRule) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if rule != nil {
			relayClientToUpstreamWithRewrite(client, upstream, rule.SNI)
		} else {
			io.Copy(upstream, client)
		}
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

// relayClientToUpstreamWithRewrite buffers the client's first TLS flight until
// a complete ClientHello is available, rewrites its SNI to newSNI, forwards it,
// then relays the rest verbatim.
func relayClientToUpstreamWithRewrite(client, upstream net.Conn, newSNI string) {
	buf := make([]byte, 0, 16384)
	tmp := make([]byte, 16384)

	for {
		n, err := client.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			out, changed, complete, perr := rewriteClientHelloSNI(buf, newSNI)
			if perr != nil {
				log.Printf("[proxy] SNI rewrite parse error: %v (forwarding unchanged)", perr)
				upstream.Write(buf)
				buf = buf[:0]
				break
			}
			if complete {
				if changed {
					log.Printf("[proxy] SNI rewritten to %s", newSNI)
				}
				upstream.Write(out)
				buf = buf[:0]
				break
			}
			// incomplete — keep buffering and read more.
		}
		if err != nil {
			if len(buf) > 0 {
				upstream.Write(buf)
			}
			return
		}
		if len(buf) > 64*1024 {
			// Sanity cap: forward as-is rather than buffer indefinitely.
			upstream.Write(buf)
			buf = buf[:0]
			break
		}
	}

	io.Copy(upstream, client)
}

// ParseProxyURL parses the proxy's listen address to an http.ProxyURL function.
func (p *Proxy) ProxyFunc() func(*http.Request) (*url.URL, error) {
	proxyURL, _ := url.Parse("http://" + p.Addr)
	return http.ProxyURL(proxyURL)
}
