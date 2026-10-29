//go:build windows

package main

import (
	"os"
	"os/exec"
)

// webview2Available reports whether the Microsoft Edge WebView2 runtime
// (Evergreen) is installed. Without it the webview library returns a null
// handle and the browser crashes silently.
func webview2Available() bool {
	// Evergreen runtime registry keys (stable channel GUID used by WebView2).
	keys := []string{
		`HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}`,
		`HKLM\SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}`,
		`HKCU\SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}`,
	}
	for _, k := range keys {
		if exec.Command("reg", "query", k).Run() == nil {
			return true
		}
	}

	// Fallback: fixed-version / default install locations.
	dirs := []string{
		`C:\Program Files (x86)\Microsoft\EdgeWebView\Application`,
		`C:\Program Files\Microsoft\EdgeWebView\Application`,
	}
	for _, d := range dirs {
		if fi, err := os.Stat(d); err == nil && fi.IsDir() {
			return true
		}
	}
	return false
}
