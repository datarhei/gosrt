package srt

import (
	"testing"
	"time"

	"github.com/datarhei/gosrt/circular"
	"github.com/datarhei/gosrt/congestion"
	"github.com/datarhei/gosrt/congestion/live"
	"github.com/datarhei/gosrt/crypto"
	"github.com/datarhei/gosrt/packet"
	"github.com/stretchr/testify/require"
)

type undecryptTest struct {
	t         *testing.T
	c         *srtConn
	cr        crypto.Crypto
	recv      congestion.Receiver
	ack       uint32
	naks      [][]uint32
	delivered [][]byte
}

func newUndecryptTest(t *testing.T) *undecryptTest {
	u := &undecryptTest{t: t}

	u.recv = live.NewReceiver(live.ReceiveConfig{
		InitialSequenceNumber: circular.New(100, packet.MAX_SEQUENCENUMBER),
		PeriodicACKInterval:   10,
		PeriodicNAKInterval:   20,
		OnSendACK:             func(seq circular.Number, _ bool) { u.ack = seq.Val() },
		OnSendNAK: func(seqs []circular.Number) {
			l := []uint32{}
			for _, seq := range seqs {
				l = append(l, seq.Val())
			}
			u.naks = append(u.naks, l)
		},
		OnDeliver: func(p packet.Packet) {
			u.delivered = append(u.delivered, p.Data())
		},
	})

	var err error
	u.cr, err = crypto.New(16)
	require.NoError(t, err)
	require.NoError(t, u.cr.GenerateSEK(packet.EvenKeyEncrypted))

	u.c = &srtConn{
		recv:            u.recv,
		snd:             live.NewSender(live.SendConfig{InitialSequenceNumber: circular.New(0, packet.MAX_SEQUENCENUMBER)}),
		crypto:          u.cr,
		config:          DefaultConfig(),
		start:           time.Now(),
		tsbpdDelay:      1_000_000_000, // no delivery until tick() with undecryptTestLate
		peerIdleTimeout: time.NewTimer(time.Hour),
		logger:          NewLogger(nil),
	}
	t.Cleanup(func() { u.c.peerIdleTimeout.Stop() })

	return u
}

const undecryptTestLate = uint64(100_000_000_000)

func (u *undecryptTest) push(seq uint32, key packet.PacketEncryption, data string) {
	p := packet.NewPacket(nil)
	p.Header().PacketSequenceNumber = circular.New(seq, packet.MAX_SEQUENCENUMBER)
	p.Header().MessageNumber = seq
	p.Header().KeyBaseEncryptionFlag = key

	payload := []byte(data)
	if key == packet.EvenKeyEncrypted {
		require.NoError(u.t, u.cr.EncryptOrDecryptPayload(payload, key, seq))
	}
	p.SetData(payload)

	u.c.handlePacket(p)
}

func (u *undecryptTest) stats() StatisticsAccumulated {
	s := &Statistics{}
	u.c.Stats(s)
	return s.Accumulated
}

const invalidKey = packet.PacketEncryption(3) // can't be decrypted

func TestUndecryptedPacketIsDropped(t *testing.T) {
	u := newUndecryptTest(t)

	u.push(100, packet.EvenKeyEncrypted, "a")
	u.push(101, packet.UnencryptedPacket, "injected")
	u.push(102, invalidKey, "garbage")
	u.push(103, packet.EvenKeyEncrypted, "b")

	// As libsrt, they are counted as dropped right away
	s := u.stats()
	require.Equal(t, uint64(4), s.PktRecv)
	require.Equal(t, uint64(2), s.PktRecvUnique)
	require.Equal(t, uint64(2), s.PktRecvDrop)
	require.Equal(t, uint64(2), s.PktRecvUndecrypt)

	// They are neither reported as missing nor do they hold the ACK
	u.recv.Tick(1000)
	require.Equal(t, uint32(104), u.ack)
	require.Empty(t, u.naks)
	require.Empty(t, u.delivered)

	// Only the decrypted packets are delivered
	u.recv.Tick(undecryptTestLate)
	require.Equal(t, [][]byte{[]byte("a"), []byte("b")}, u.delivered)

	s = u.stats()
	require.Equal(t, uint64(2), s.PktRecvDrop)
	require.Equal(t, uint64(0), s.PktRecvLoss)
	require.Equal(t, uint64(0), s.PktRecvLost)
	require.Equal(t, uint64(0), u.recv.Stats().PktBuf)
}

func TestUndecryptedPacketAfterGap(t *testing.T) {
	u := newUndecryptTest(t)

	u.push(100, packet.EvenKeyEncrypted, "a")
	u.push(102, packet.UnencryptedPacket, "injected")

	// The gap in front of the packet is reported right away, only the missing packet counts as loss
	require.Equal(t, [][]uint32{{101, 101}}, u.naks)
	require.Equal(t, uint64(1), u.stats().PktRecvLoss)

	u.push(103, packet.EvenKeyEncrypted, "b")
	require.Equal(t, [][]uint32{{101, 101}}, u.naks)
	require.Equal(t, uint64(1), u.stats().PktRecvLoss)
	require.Equal(t, uint64(1), u.stats().PktRecvDrop)
}

func TestUndecryptedPacketsOnly(t *testing.T) {
	u := newUndecryptTest(t)

	u.push(100, packet.EvenKeyEncrypted, "a")
	for seq := uint32(101); seq <= 200; seq++ {
		u.push(seq, packet.UnencryptedPacket, "injected")
	}

	// The connection doesn't stall without any decryptable packet
	u.recv.Tick(2_000_000)
	require.Equal(t, uint32(201), u.ack)
	require.Empty(t, u.naks)
	require.Equal(t, uint64(100), u.stats().PktRecvDrop)

	// They are part of the receive rate
	pps, _, _ := u.recv.PacketRate()
	require.Greater(t, pps, float64(0))

	u.push(201, packet.EvenKeyEncrypted, "b")
	require.Equal(t, uint64(0), u.stats().PktRecvLoss)
}
