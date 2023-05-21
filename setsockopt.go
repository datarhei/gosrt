//go:build !windows

package srt

import (
	"net"
	"syscall"
)

func setSockOptREUSE(fd uintptr) error {
	return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
}

func setSockOptIPTOS(fd uintptr, tos int) error {
	return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TOS, tos)
}

func setSockOptIPTTL(fd uintptr, ttl int) error {
	return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
}

func setSockOptIPTOSFromConn(c *net.UDPConn, tos int) error {
	file, err := c.File()
	if err != nil {
		return err
	}
	fd := file.Fd()
	return setSockOptIPTOS(fd, tos)
}

func setSockOptIPTTLFromConn(c *net.UDPConn, ttl int) error {
	file, err := c.File()
	if err != nil {
		return err
	}
	fd := file.Fd()
	return setSockOptIPTTL(fd, ttl)
}
