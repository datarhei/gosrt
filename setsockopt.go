//go:build !windows

package srt

import (
	"syscall"
)

func setSockOpt(fd uintptr, key, value int) error {
	return syscall.SetsockoptInt(int(fd), key, syscall.SO_REUSEADDR, value)
}
