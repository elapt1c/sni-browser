package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

const banner = `
  ╔══════════════════════════════════════════╗
  ║         SNI BROWSER v1.1.0              ║
  ║  MITM SNI-spoofing evasion browser      ║
  ║  (YouTube / WordPress / Reddit work)    ║
  ╚══════════════════════════════════════════╝
`

func main() {
	log.SetFlags(0)
	fmt.Print(banner)

	// Resolve the per-user config dir for the CA.
	cfgDir, err := os.UserConfigDir()
	if err != nil {
		cfgDir = os.TempDir()
	}
	cfgDir = filepath.Join(cfgDir, "sni-browser")

	// Load (or generate) the root CA the browser will trust for MITM.
	ca, err := ensureCA(cfgDir)
	if err != nil {
		log.Fatalf("failed to load/generate CA: %v", err)
	}

	// Install/trust the CA for the browser engine.
	if err := trustCA(ca); err != nil {
		log.Printf("[main] warning: could not install CA trust: %v", err)
	}

	// Find a free port for the proxy.
	proxyAddr := findFreePort()

	// Start the MITM forward proxy.
	proxy := NewProxy(proxyAddr, ca)
	if err := proxy.Start(); err != nil {
		log.Fatalf("failed to start proxy: %v", err)
	}
	defer proxy.Stop()

	log.Printf("[main] Proxy started on %s", proxyAddr)
	log.Println("[main] Launching browser...")

	// Handle graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("[main] Shutting down...")
		proxy.Stop()
		os.Exit(0)
	}()

	// Run the WebView browser (blocks until window closed).
	runBrowser(proxyAddr)
}

func findFreePort() string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("cannot find free port: %v", err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}
