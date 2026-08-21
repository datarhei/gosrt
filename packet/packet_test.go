package packet

import (
	"bytes"
	"encoding/hex"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEmptyPacket(t *testing.T) {
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:6000")

	p := NewPacket(addr)

	var buf bytes.Buffer

	p.Marshal(&buf)

	data := hex.EncodeToString(buf.Bytes())

	require.Equal(t, "00000000c00000010000000000000000", data)
}

func TestArbitraryPacket(t *testing.T) {
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:6000")

	p := NewPacket(addr)
	p.SetData([]byte("hello world!"))

	var buf bytes.Buffer

	p.Marshal(&buf)

	data := hex.EncodeToString(buf.Bytes())

	require.Equal(t, "00000000c0000001000000000000000068656c6c6f20776f726c6421", data)
}

func TestArbitraryControlPacket(t *testing.T) {
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:6000")

	p := NewPacket(addr)
	p.Header().IsControlPacket = true
	p.Header().ControlType = CTRLTYPE_KEEPALIVE
	p.Header().SubType = 112
	p.Header().TypeSpecific = 42

	var buf bytes.Buffer

	p.Marshal(&buf)

	data := hex.EncodeToString(buf.Bytes())

	require.Equal(t, "800100700000002a0000000000000000", data)
}

func FuzzPacket(f *testing.F) {
	f.Add("00000000c00000010000000000000000")
	f.Add("00000000c0000001000000000000000068656c6c6f20776f726c6421")
	f.Add("800100700000002a0000000000000000")

	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:6000")

	f.Fuzz(func(t *testing.T, orig string) {
		data, err := hex.DecodeString(orig)
		if err != nil {
			return
		}
		if len(data) == 0 {
			return
		}
		p, err := NewPacketFromData(addr, data)
		if err != nil {
			return
		}

		var buf bytes.Buffer
		buf.Reset()
		p.Marshal(&buf)

		if !bytes.Equal(data, buf.Bytes()) {
			t.Errorf("Before: %q, after: %q\n%s", orig, hex.EncodeToString(buf.Bytes()), p.Dump())
		}
	})
}

func TestUnmarshalPacket(t *testing.T) {
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:6000")

	data, _ := hex.DecodeString("00000000c0000001000000000000000068656c6c6f20776f726c6421")

	p, err := NewPacketFromData(addr, data)
	require.NoError(t, err)

	require.Equal(t, p.Header().Timestamp, uint32(0))
	require.Equal(t, p.Header().Addr.String(), "127.0.0.1:6000")
	require.False(t, p.Header().IsControlPacket)
	require.Equal(t, p.Header().PacketPositionFlag, SinglePacket)
	require.Equal(t, p.Header().KeyBaseEncryptionFlag, UnencryptedPacket)
	require.Equal(t, p.Header().MessageNumber, uint32(1))

	require.Equal(t, uint64(12), p.Len())
	require.Equal(t, "hello world!", string(p.Data()))
}

func TestPacketString(t *testing.T) {
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:6000")

	p := NewPacket(addr)
	p.SetData([]byte("hello world!"))

	require.Greater(t, len(p.String()), 0)
}

func BenchmarkNewPacket(b *testing.B) {
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:6000")

	for b.Loop() {
		pkt := NewPacket(addr)

		pkt.Decommission()
	}
}

func BenchmarkNewPacketWithData(b *testing.B) {
	data := make([]byte, 1316)
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:6000")

	p := NewPacket(addr)
	p.SetData(data)

	var buf bytes.Buffer

	p.Marshal(&buf)

	data = buf.Bytes()

	for b.Loop() {
		pkt, _ := NewPacketFromData(addr, data)

		if pkt != nil {
			pkt.Decommission()
		}
	}
}

func BenchmarkNoBufferpool(b *testing.B) {
	data := make([]byte, 1316)

	for b.Loop() {
		pdata := make([]byte, len(data)-16)
		copy(pdata, data[16:])
	}
}

func BenchmarkBufferpool(b *testing.B) {
	pool := sync.Pool{
		New: func() any {
			return new(bytes.Buffer)
		},
	}

	data := make([]byte, 1316)

	for b.Loop() {
		p := pool.Get().(*bytes.Buffer)

		p.Reset()
		p.Write(data[16:])

		pool.Put(p)
	}
}
