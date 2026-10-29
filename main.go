package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

const banner = `
  ╔══════════════════════════════════════════╗
  ║         SNI BROWSER v1.0.0              ║
  ║  All HTTPS SNI is spoofed through       ║
  ║  the embedded evasion proxy.            ║
  ║  Keyboard: Ctrl+L=URL  Alt+←=Back       ║
  ║            Alt+→=Fwd  F5=Reload         ║
  ╚══════════════════════════════════════════╝
`

func main() {
	log.SetFlags(0)
	fmt.Print(banner)

	// Find a free port for the proxy.
	proxyAddr := findFreePort()

	// Start the SNI-spoofing forward proxy.
	proxy := NewProxy(proxyAddr)
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
