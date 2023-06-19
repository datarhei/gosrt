//go:build windows

package srt

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/windows"
)

func setSockOptREUSE(fd uintptr) error {
	return windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_REUSEADDR, 1)
}

func setSockOptIPTOS(fd uintptr, tos int) error {
	return windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, windows.IP_TOS, tos)
}

func setSockOptIPTTL(fd uintptr, ttl int) error {
	return windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, windows.IP_TTL, ttl)
}

func setSockOptIPTOSFromConn(c *net.UDPConn, tos int) error {
	fmt.Fprintf(os.Stderr, "setSockOptIPTOSFromConn: not implemented on Windows\n")
	return nil
}

func setSockOptIPTTLFromConn(c *net.UDPConn, ttl int) error {
	fmt.Fprintf(os.Stderr, "setSockOptIPTTLFromConn: not implemented on Windows\n")
	return nil
}
