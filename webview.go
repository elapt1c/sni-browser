package main

import (
	_ "embed"
	"log"
	"os"

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

	// Init registers the toolbar script to run at document-start on every
	// top-frame page (WebKitGTK user-content manager / WebView2
	// AddScriptToExecuteOnDocumentCreated), so it survives navigation without
	// any polling. Must be called before the first Navigate.
	w.Init(injectJS)

	startURL := os.Getenv("SNI_BROWSER_START_URL")
	if startURL == "" {
		startURL = "https://www.google.com"
	}
	w.Navigate(startURL)

	log.Println("[browser] WebView started, proxying all traffic through", proxyAddr)
	w.Run()
}
