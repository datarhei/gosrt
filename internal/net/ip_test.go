package net

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIPDefault(t *testing.T) {
	ip := IP{}

	ip.setDefault()

	require.Equal(t, "127.0.0.1", ip.String())
}

func TestIPParse(t *testing.T) {
	ip := IP{}

	ip.Parse("192.168.1.3")

	require.Equal(t, "192.168.1.3", ip.String())

	ip.Parse("fhdhdf")

	require.Equal(t, "127.0.0.1", ip.String())
}

func TestIPFrom(t *testing.T) {
	ip := IP{}

	ip.FromNetIP(net.ParseIP("192.168.2.56"))

	require.Equal(t, "192.168.2.56", ip.String())

	ip.FromNetIP(net.ParseIP("127.0.0.1"))

	require.Equal(t, "127.0.0.1", ip.String())

	udpaddr, err := net.ResolveUDPAddr("udp", "localhost:12345")

	require.NoError(t, err)
	ip.FromNetAddr(udpaddr)

	require.Equal(t, "127.0.0.1", ip.String())

	ipaddr, err := net.ResolveIPAddr("ip", "localhost")

	require.NoError(t, err)
	ip.FromNetAddr(ipaddr)

	require.Equal(t, "127.0.0.1", ip.String())
}

func TestIPUnmarshal(t *testing.T) {
	ip := IP{}

	b0 := [5]byte{}

	err := ip.Unmarshal(b0[:])

	require.Error(t, err)

	b1 := [...]byte{1, 0, 168, 192}

	err = ip.Unmarshal(b1[:])

	require.NoError(t, err)
	require.Equal(t, "192.168.0.1", ip.String())

	b2 := [...]byte{1, 0, 168, 192, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	err = ip.Unmarshal(b2[:])

	require.NoError(t, err)
	require.Equal(t, "192.168.0.1", ip.String())

	b3 := [...]byte{1, 0, 0, 0, 0, 0, 0, 0, 0xc5, 0x71, 0x26, 0xdb, 0x94, 0x8c, 0x30, 0xfd}

	err = ip.Unmarshal(b3[:])

	require.NoError(t, err)
	require.Equal(t, "fd30:8c94:db26:71c5::1", ip.String())
}

func TestIPMarshal(t *testing.T) {
	ip := IP{}

	ip.Parse("192.168.0.1")

	b := [16]byte{}

	ip.Marshal(b[:])

	require.Equal(t, [...]byte{1, 0, 168, 192, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, b)

	ip.Parse("fd30:8c94:db26:71c5::1")

	ip.Marshal(b[:])

	require.Equal(t, [...]byte{1, 0, 0, 0, 0, 0, 0, 0, 0xc5, 0x71, 0x26, 0xdb, 0x94, 0x8c, 0x30, 0xfd}, b)
}
