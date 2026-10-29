package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime/debug"
)

// logPath is the path of the session log file, set by setupLogging.
var logPath string

// setupLogging writes all log output to both stderr and a file in dir, so
// crashes are diagnosable even for a GUI (windowsgui) binary with no console.
func setupLogging(dir string) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	logPath = filepath.Join(dir, "sni-browser.log")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	log.SetOutput(io.MultiWriter(os.Stderr, f))
}

// recoverAndLog recovers from a panic, logs it with a stack trace, and shows a
// visible error box so a GUI binary doesn't fail silently.
func recoverAndLog() {
	if r := recover(); r != nil {
		stack := debug.Stack()
		log.Printf("FATAL PANIC: %v\n%s", r, stack)
		msg := fmt.Sprintf("Fatal error: %v\n\nLog: %s", r, logPath)
		showErrorBox("SNI Browser crashed", msg)
	}
}
