package main

import (
	_ "embed"
	"log"
	"os"
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

	w.SetTitle("SNI Browser")
	w.SetSize(1280, 800, webview.HintNone)

	// The webview resets its JS context on every navigation, so we
	// periodically re-inject the browser-chrome script (toolbar + URL bar).
	// The script is idempotent, so repeated injection is safe.
	go func() {
		for {
			w.Dispatch(func() {
				w.Eval(injectJS)
			})
			time.Sleep(400 * time.Millisecond)
		}
	}()

	startURL := os.Getenv("SNI_BROWSER_START_URL")
	if startURL == "" {
		startURL = "https://www.google.com"
	}
	w.Navigate(startURL)

	log.Println("[browser] WebView started, proxying all traffic through", proxyAddr)
	w.Run()
}
