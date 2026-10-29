//go:build !windows

package main

// webview2Available is only meaningful on Windows; other platforms use their
// own webview engine.
func webview2Available() bool { return true }
