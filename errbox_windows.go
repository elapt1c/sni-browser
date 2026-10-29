//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

// showErrorBox displays a modal error dialog (MB_OK | MB_ICONERROR).
func showErrorBox(title, msg string) {
	user32 := syscall.NewLazyDLL("user32.dll")
	msgBox := user32.NewProc("MessageBoxW")
	t, _ := syscall.UTF16PtrFromString(title)
	m, _ := syscall.UTF16PtrFromString(msg)
	msgBox.Call(0, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)), 0x10)
}
