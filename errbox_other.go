//go:build !windows

package main

// showErrorBox is a no-op on non-Windows platforms (errors go to stderr/log).
func showErrorBox(title, msg string) {}
