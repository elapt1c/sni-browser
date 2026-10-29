package main

import (
	_ "embed"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/webview/webview_go"
)

//go:embed inject.js
var injectJS string

func runBrowser(proxyAddr string) {
	// Set proxy env vars so the WebView routes all traffic through our proxy.
	proxyURL := "http://" + proxyAddr
	os.Setenv("HTTP_PROXY", proxyURL)
	os.Setenv("HTTPS_PROXY", proxyURL)
	os.Setenv("http_proxy", proxyURL)
	os.Setenv("https_proxy", proxyURL)
	os.Setenv("no_proxy", "")

	debug := os.Getenv("SNI_BROWSER_DEBUG") == "1"

	w := webview.New(debug)
	defer w.Destroy()

	w.SetTitle("SNI Browser — all HTTPS traffic SNI-spoofed")
	w.SetSize(1280, 800, webview.HintNone)

	// Bind a URL navigator.
	w.Bind("navigateTo", func(raw string) {
		url := strings.TrimSpace(raw)
		if url == "" {
			return
		}
		if !strings.Contains(url, "://") {
			url = "https://" + url
		}
		w.Navigate(url)
	})

	// Bind current-url reporter for the title bar.
	w.Bind("reportURL", func(u string) {
		w.SetTitle(fmt.Sprintf("SNI Browser — %s", u))
	})

	// The webview resets its JS context on every navigation, so we
	// periodically re-inject the keyboard-shortcut/URL-bar script. The
	// script is idempotent (guards on window.__sni_injected), so it is
	// safe to run repeatedly.
	go func() {
		for {
			w.Dispatch(func() {
				w.Eval(injectJS)
			})
			time.Sleep(400 * time.Millisecond)
		}
	}()

	w.Navigate("https://www.google.com")

	log.Println("[browser] WebView started, proxying all traffic through", proxyAddr)
	log.Println("[browser] Ctrl+L = URL bar, Alt+Left/Right = back/forward, F5 = reload")
	w.Run()
}
