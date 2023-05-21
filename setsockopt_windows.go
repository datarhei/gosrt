//go:build windows

package srt

import (
	"golang.org/x/sys/windows"
	"syscall"
)

func setSockOpt(fd uintptr, key, value int) error {
	return windows.SetsockoptInt(windows.Handle(fd), key, syscall.SO_REUSEADDR, value)
}
