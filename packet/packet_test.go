package packet

import (
	"bytes"
	"encoding/hex"
	"net"
	"sync"
	"testing"

	"github.com/datarhei/gosrt/circular"
	srtnet "github.com/datarhei/gosrt/net"

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

func TestHandshakeV4(t *testing.T) {
	ip := srtnet.IP{}
	ip.Parse("127.0.0.1")

	cif := &CIFHandshake{
		IsRequest:                   false,
		Version:                     4,
		EncryptionField:             0,
		ExtensionField:              2,
		InitialPacketSequenceNumber: circular.New(42, MAX_SEQUENCENUMBER),
		MaxTransmissionUnitSize:     1500,
		MaxFlowWindowSize:           100,
		HandshakeType:               HSTYPE_CONCLUSION,
		SRTSocketId:                 0x274921,
		SynCookie:                   0x123456,
		PeerIP:                      ip,
		HasHS:                       false,
		HasKM:                       false,
		HasSID:                      false,
		HasCongestionCtl:            false,
	}

	var buf bytes.Buffer

	cif.Marshal(&buf)

	data := hex.EncodeToString(buf.Bytes())

	require.Equal(t, "00000004000000020000002a000005dc00000064ffffffff00274921001234560100007f000000000000000000000000", data)

	cif2 := &CIFHandshake{}

	err := cif2.Unmarshal(buf.Bytes())

	require.NoError(t, err)
	require.Equal(t, cif, cif2)
}

func TestHandshakeV5(t *testing.T) {
	ip := srtnet.IP{}
	ip.Parse("127.0.0.1")

	cif := &CIFHandshake{
		IsRequest:                   false,
		Version:                     5,
		EncryptionField:             0,
		ExtensionField:              0,
		InitialPacketSequenceNumber: circular.New(42, MAX_SEQUENCENUMBER),
		MaxTransmissionUnitSize:     1500,
		MaxFlowWindowSize:           100,
		HandshakeType:               HSTYPE_CONCLUSION,
		SRTSocketId:                 0x274921,
		SynCookie:                   0x123456,
		PeerIP:                      ip,
		HasHS:                       true,
		HasKM:                       true,
		HasSID:                      true,
		HasCongestionCtl:            true,
		SRTHS: &CIFHandshakeExtension{
			SRTVersion: 0x010402,
			SRTFlags: CIFHandshakeExtensionFlags{
				TSBPDSND:      true,
				TSBPDRCV:      true,
				CRYPT:         true,
				TLPKTDROP:     true,
				PERIODICNAK:   true,
				REXMITFLG:     true,
				STREAM:        false,
				PACKET_FILTER: false,
			},
			RecvTSBPDDelay: 100,
			SendTSBPDDelay: 100,
		},
		SRTKM: &CIFKeyMaterialExtension{
			S:                     0,
			Version:               1,
			PacketType:            2,
			Sign:                  0x2029,
			Resv1:                 0,
			KeyBasedEncryption:    EvenKeyEncrypted,
			KeyEncryptionKeyIndex: 0,
			Cipher:                2,
			Authentication:        0,
			StreamEncapsulation:   2,
			Resv2:                 0,
			Resv3:                 0,
			SLen:                  16,
			KLen:                  16,
			Salt:                  []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
			Wrap:                  []byte{0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20},
		},
		StreamId:      "/live/stream.foobar",
		CongestionCtl: "foob",
	}

	var buf bytes.Buffer

	cif.Marshal(&buf)

	data := hex.EncodeToString(buf.Bytes())

	require.Equal(t, "00000005000200070000002a000005dc00000064ffffffff00274921001234560100007f00000000000000000000000000020003000104020000003f006400640004000e122029010000000002000200000004040102030405060708090a0b0c0d0e0f10f0f1f2f3f4f5f6f71112131415161718191a1b1c1d1e1f200005000576696c2f74732f656d6165726f6f662e0072616200060001626f6f66", data)

	cif2 := &CIFHandshake{}

	err := cif2.Unmarshal(buf.Bytes())

	require.NoError(t, err)
	require.Equal(t, cif, cif2)
}

func TestHandshakeString(t *testing.T) {
	ip := srtnet.IP{}
	ip.Parse("127.0.0.1")

	cif := &CIFHandshake{
		IsRequest:                   false,
		Version:                     5,
		EncryptionField:             0,
		ExtensionField:              0,
		InitialPacketSequenceNumber: circular.New(42, MAX_SEQUENCENUMBER),
		MaxTransmissionUnitSize:     1500,
		MaxFlowWindowSize:           100,
		HandshakeType:               HSTYPE_CONCLUSION,
		SRTSocketId:                 0x274921,
		SynCookie:                   0x123456,
		PeerIP:                      ip,
		HasHS:                       true,
		HasKM:                       false,
		HasSID:                      true,
		HasCongestionCtl:            false,
		SRTHS: &CIFHandshakeExtension{
			SRTVersion: 0x010402,
			SRTFlags: CIFHandshakeExtensionFlags{
				TSBPDSND:      true,
				TSBPDRCV:      true,
				CRYPT:         true,
				TLPKTDROP:     true,
				PERIODICNAK:   true,
				REXMITFLG:     true,
				STREAM:        false,
				PACKET_FILTER: false,
			},
			RecvTSBPDDelay: 100,
			SendTSBPDDelay: 100,
		},
		SRTKM:    nil,
		StreamId: "/live/stream.foobar",
	}

	require.Greater(t, len(cif.String()), 0)
}

func TestKM(t *testing.T) {
	cif := &CIFKeyMaterialExtension{
		S:                     0,
		Version:               1,
		PacketType:            2,
		Sign:                  0x2029,
		Resv1:                 0,
		KeyBasedEncryption:    EvenKeyEncrypted,
		KeyEncryptionKeyIndex: 0,
		Cipher:                2,
		Authentication:        0,
		StreamEncapsulation:   2,
		Resv2:                 0,
		Resv3:                 0,
		SLen:                  16,
		KLen:                  16,
		Salt:                  []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
		Wrap:                  []byte{0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20},
	}

	var buf bytes.Buffer

	cif.Marshal(&buf)

	data := hex.EncodeToString(buf.Bytes())

	require.Equal(t, "122029010000000002000200000004040102030405060708090a0b0c0d0e0f10f0f1f2f3f4f5f6f71112131415161718191a1b1c1d1e1f20", data)

	cif2 := &CIFKeyMaterialExtension{}

	err := cif2.Unmarshal(buf.Bytes())

	require.NoError(t, err)
	require.Equal(t, cif, cif2)
}

func TestKMString(t *testing.T) {
	cif := &CIFKeyMaterialExtension{
		S:                     0,
		Version:               1,
		PacketType:            2,
		Sign:                  0x2029,
		Resv1:                 0,
		KeyBasedEncryption:    EvenKeyEncrypted,
		KeyEncryptionKeyIndex: 0,
		Cipher:                2,
		Authentication:        0,
		StreamEncapsulation:   2,
		Resv2:                 0,
		Resv3:                 0,
		SLen:                  16,
		KLen:                  16,
		Salt:                  []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
		Wrap:                  []byte{0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20},
	}

	require.Greater(t, len(cif.String()), 0)
}

func TestFullACK(t *testing.T) {
	cif := &CIFACK{
		IsLite:                      false,
		IsSmall:                     false,
		LastACKPacketSequenceNumber: circular.New(42, MAX_SEQUENCENUMBER),
		RTT:                         38473,
		RTTVar:                      9084,
		AvailableBufferSize:         48533,
		PacketsReceivingRate:        20,
		EstimatedLinkCapacity:       0,
		ReceivingRate:               73637,
	}

	var buf bytes.Buffer

	cif.Marshal(&buf)

	data := hex.EncodeToString(buf.Bytes())

	require.Equal(t, "0000002a000096490000237c0000bd95000000140000000000011fa5", data)

	cif2 := &CIFACK{}

	err := cif2.Unmarshal(buf.Bytes())

	require.NoError(t, err)
	require.Equal(t, cif, cif2)
}

func TestFullACKString(t *testing.T) {
	cif := &CIFACK{
		IsLite:                      false,
		IsSmall:                     false,
		LastACKPacketSequenceNumber: circular.New(42, MAX_SEQUENCENUMBER),
		RTT:                         38473,
		RTTVar:                      9084,
		AvailableBufferSize:         48533,
		PacketsReceivingRate:        20,
		EstimatedLinkCapacity:       0,
		ReceivingRate:               73637,
	}

	require.Greater(t, len(cif.String()), 0)
}

func TestSmallACK(t *testing.T) {
	cif := &CIFACK{
		IsLite:                      false,
		IsSmall:                     true,
		LastACKPacketSequenceNumber: circular.New(42, MAX_SEQUENCENUMBER),
		RTT:                         38473,
		RTTVar:                      9084,
		AvailableBufferSize:         48533,
		PacketsReceivingRate:        0,
		EstimatedLinkCapacity:       0,
		ReceivingRate:               0,
	}

	var buf bytes.Buffer

	cif.Marshal(&buf)

	data := hex.EncodeToString(buf.Bytes())

	require.Equal(t, "0000002a000096490000237c0000bd95", data)

	cif2 := &CIFACK{}

	err := cif2.Unmarshal(buf.Bytes())

	require.NoError(t, err)
	require.Equal(t, cif, cif2)
}

func TestSmallACKString(t *testing.T) {
	cif := &CIFACK{
		IsLite:                      false,
		IsSmall:                     true,
		LastACKPacketSequenceNumber: circular.New(42, MAX_SEQUENCENUMBER),
		RTT:                         38473,
		RTTVar:                      9084,
		AvailableBufferSize:         48533,
		PacketsReceivingRate:        0,
		EstimatedLinkCapacity:       0,
		ReceivingRate:               0,
	}

	require.Greater(t, len(cif.String()), 0)
}

func TestLiteACK(t *testing.T) {
	cif := &CIFACK{
		IsLite:                      true,
		IsSmall:                     false,
		LastACKPacketSequenceNumber: circular.New(42, MAX_SEQUENCENUMBER),
		RTT:                         0,
		RTTVar:                      0,
		AvailableBufferSize:         0,
		PacketsReceivingRate:        0,
		EstimatedLinkCapacity:       0,
		ReceivingRate:               0,
	}

	var buf bytes.Buffer

	cif.Marshal(&buf)

	data := hex.EncodeToString(buf.Bytes())

	require.Equal(t, "0000002a", data)

	cif2 := &CIFACK{}

	err := cif2.Unmarshal(buf.Bytes())

	require.NoError(t, err)
	require.Equal(t, cif, cif2)
}

func TestLiteACKString(t *testing.T) {
	cif := &CIFACK{
		IsLite:                      true,
		IsSmall:                     false,
		LastACKPacketSequenceNumber: circular.New(42, MAX_SEQUENCENUMBER),
		RTT:                         0,
		RTTVar:                      0,
		AvailableBufferSize:         0,
		PacketsReceivingRate:        0,
		EstimatedLinkCapacity:       0,
		ReceivingRate:               0,
	}

	require.Greater(t, len(cif.String()), 0)
}

func TestNAK(t *testing.T) {
	cif := &CIFNAK{
		LostPacketSequenceNumber: []circular.Number{
			circular.New(42, MAX_SEQUENCENUMBER),
			circular.New(42, MAX_SEQUENCENUMBER),
			circular.New(45, MAX_SEQUENCENUMBER),
			circular.New(49, MAX_SEQUENCENUMBER),
		},
	}

	var buf bytes.Buffer

	cif.Marshal(&buf)

	data := hex.EncodeToString(buf.Bytes())

	require.Equal(t, "0000002a8000002d00000031", data)

	cif2 := &CIFNAK{}

	err := cif2.Unmarshal(buf.Bytes())

	require.NoError(t, err)
	require.Equal(t, cif, cif2)
}

func TestNAKString(t *testing.T) {
	cif := &CIFNAK{
		LostPacketSequenceNumber: []circular.Number{
			circular.New(42, MAX_SEQUENCENUMBER),
			circular.New(42, MAX_SEQUENCENUMBER),
			circular.New(45, MAX_SEQUENCENUMBER),
			circular.New(49, MAX_SEQUENCENUMBER),
		},
	}

	require.Greater(t, len(cif.String()), 0)
}

func TestShutdown(t *testing.T) {
	cif := &CIFShutdown{}

	var buf bytes.Buffer

	cif.Marshal(&buf)

	data := hex.EncodeToString(buf.Bytes())

	require.Equal(t, "00000000", data)

	cif2 := &CIFShutdown{}

	err := cif2.Unmarshal(buf.Bytes())

	require.NoError(t, err)
	require.Equal(t, cif, cif2)
}

func TestShutdownString(t *testing.T) {
	cif := &CIFShutdown{}

	require.Greater(t, len(cif.String()), 0)
}

func BenchmarkNewPacket(b *testing.B) {
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:6000")

	for i := 0; i < b.N; i++ {
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

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		pkt, _ := NewPacketFromData(addr, data)

		if pkt != nil {
			pkt.Decommission()
		}
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
