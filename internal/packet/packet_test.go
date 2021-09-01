package packet

import (
	"bytes"
	"net"
	"sync"
	"testing"
)

func BenchmarkNewPacket(b *testing.B) {
	data := make([]byte, 1316)
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:6000")

	p := NewPacket(addr, nil)
	p.SetData(data)

	var buf bytes.Buffer

	p.Marshal(&buf)

	data = buf.Bytes()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		pkt := NewPacket(addr, data)

		pkt.Decommission()
	}
}

func BenchmarkNoBufferpool(b *testing.B) {
	data := make([]byte, 1316)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		pdata := make([]byte, len(data)-16)
		copy(pdata, data[16:])
	}
}

func BenchmarkBufferpool(b *testing.B) {
	pool := sync.Pool{
		New: func() interface{} {
			return new(bytes.Buffer)
		},
	}

	data := make([]byte, 1316)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		p := pool.Get().(*bytes.Buffer)

		p.Reset()
		p.Write(data[16:])

		pool.Put(p)
	}
}
