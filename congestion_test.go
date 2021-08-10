package srt

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func mockLiveSend(onDeliver func(p packet)) *liveSend {
	send := newLiveSend(liveSendConfig{
		initialSequenceNumber: newCircular(0, MAX_SEQUENCENUMBER),
		dropInterval:          10,
		onDeliver:             onDeliver,
	})

	return send
}

func TestSendSequence(t *testing.T) {
	numbers := []uint32{}
	send := mockLiveSend(func(p packet) {
		numbers = append(numbers, p.Header().packetSequenceNumber.Val())
	})

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for i := 0; i < 10; i++ {
		p := newPacket(addr, nil)
		p.Header().pktTsbpdTime = uint64(i + 1)

		send.Push(p)
	}

	send.Tick(5)

	require.Exactly(t, []uint32{0, 1, 2, 3, 4}, numbers)

	send.Tick(10)

	require.Exactly(t, []uint32{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, numbers)
}

func TestSendLossListACK(t *testing.T) {
	send := mockLiveSend(nil)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for i := 0; i < 10; i++ {
		p := newPacket(addr, nil)
		p.Header().pktTsbpdTime = uint64(i + 1)

		send.Push(p)
	}

	send.Tick(10)

	require.Equal(t, 10, send.lossList.Len())

	for i := 0; i < 10; i++ {
		send.ACK(newCircular(uint32(i+1), MAX_SEQUENCENUMBER))
		require.Equal(t, 10-(i+1), send.lossList.Len())
	}
}

func TestSendRetransmit(t *testing.T) {
	numbers := []uint32{}
	nRetransmit := 0
	send := mockLiveSend(func(p packet) {
		numbers = append(numbers, p.Header().packetSequenceNumber.Val())
		if p.Header().retransmittedPacketFlag {
			nRetransmit++
		}
	})

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for i := 0; i < 10; i++ {
		p := newPacket(addr, nil)
		p.Header().pktTsbpdTime = uint64(i + 1)

		send.Push(p)
	}

	send.Tick(10)

	require.Equal(t, 0, nRetransmit)

	send.NAK([]circular{
		newCircular(2, MAX_SEQUENCENUMBER),
		newCircular(2, MAX_SEQUENCENUMBER),
	})

	require.Equal(t, 1, nRetransmit)

	send.NAK([]circular{
		newCircular(5, MAX_SEQUENCENUMBER),
		newCircular(7, MAX_SEQUENCENUMBER),
	})

	require.Equal(t, 4, nRetransmit)
}

func TestSendDrop(t *testing.T) {
	send := mockLiveSend(nil)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for i := 0; i < 10; i++ {
		p := newPacket(addr, nil)
		p.Header().pktTsbpdTime = uint64(i + 1)

		send.Push(p)
	}

	send.Tick(10)

	require.Equal(t, 10, send.lossList.Len())

	send.Tick(20)

	require.Equal(t, 0, send.lossList.Len())
}

func TestSendFlush(t *testing.T) {
	send := mockLiveSend(nil)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for i := 0; i < 10; i++ {
		p := newPacket(addr, nil)
		p.Header().pktTsbpdTime = uint64(i + 1)

		send.Push(p)
	}

	require.Exactly(t, 10, send.packetList.Len())
	require.Exactly(t, 0, send.lossList.Len())

	send.Tick(5)

	require.Exactly(t, 5, send.packetList.Len())
	require.Exactly(t, 5, send.lossList.Len())

	send.Flush()

	require.Exactly(t, 0, send.packetList.Len())
	require.Exactly(t, 0, send.lossList.Len())
}

func mockLiveRecv(onSendACK func(seq circular, light bool), onSendNAK func(from circular, to circular), onDeliver func(p packet)) *liveRecv {
	recv := newLiveRecv(liveRecvConfig{
		initialSequenceNumber: newCircular(0, MAX_SEQUENCENUMBER),
		periodicACKInterval:   10,
		periodicNAKInterval:   20,
		onSendACK:             onSendACK,
		onSendNAK:             onSendNAK,
		onDeliver:             onDeliver,
	})

	return recv
}

func TestRecvSequence(t *testing.T) {
	nACK := 0
	nNAK := 0
	numbers := []uint32{}
	recv := mockLiveRecv(
		func(seq circular, light bool) {
			nACK++
		},
		func(from circular, to circular) {
			nNAK++
		},
		func(p packet) {
			numbers = append(numbers, p.Header().packetSequenceNumber.Val())
		},
	)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for i := 0; i < 10; i++ {
		p := newPacket(addr, nil)
		p.Header().packetSequenceNumber = newCircular(uint32(i), MAX_SEQUENCENUMBER)
		p.Header().pktTsbpdTime = uint64(i + 1)

		recv.Push(p)
	}

	require.Equal(t, 0, nACK)
	require.Equal(t, 0, nNAK)
	require.Equal(t, uint32(9), recv.maxSeenSequenceNumber.Val())
	require.Equal(t, uint32(0), recv.lastACKSequenceNumber.Inc().Val())

	recv.Tick(1)

	require.Equal(t, 0, nACK)
	require.Equal(t, 0, nNAK)
	require.Equal(t, uint32(9), recv.maxSeenSequenceNumber.Val())
	require.Equal(t, uint32(0), recv.lastACKSequenceNumber.Inc().Val())

	recv.Tick(10) // ACK period

	require.Equal(t, 1, nACK)
	require.Equal(t, 0, nNAK)
	require.Equal(t, uint32(9), recv.maxSeenSequenceNumber.Val())
	require.Equal(t, uint32(9), recv.lastACKSequenceNumber.Val())

	require.Exactly(t, []uint32{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, numbers)
}

func TestRecvTSBPD(t *testing.T) {
	numbers := []uint32{}
	recv := mockLiveRecv(
		nil,
		nil,
		func(p packet) {
			numbers = append(numbers, p.Header().packetSequenceNumber.Val())
		},
	)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for i := 0; i < 20; i++ {
		p := newPacket(addr, nil)
		p.Header().packetSequenceNumber = newCircular(uint32(i), MAX_SEQUENCENUMBER)
		p.Header().pktTsbpdTime = uint64(i + 1)

		recv.Push(p)
	}

	require.Equal(t, uint32(19), recv.maxSeenSequenceNumber.Val())
	require.Equal(t, uint32(0), recv.lastACKSequenceNumber.Inc().Val())

	recv.Tick(10) // ACK period

	require.Equal(t, uint32(19), recv.maxSeenSequenceNumber.Val())
	require.Equal(t, uint32(19), recv.lastACKSequenceNumber.Val())

	require.Exactly(t, []uint32{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, numbers)
}

func TestRecvNAK(t *testing.T) {
	seqACK := uint32(0)
	seqNAKFrom := uint32(0)
	seqNAKTo := uint32(0)
	numbers := []uint32{}
	recv := mockLiveRecv(
		func(seq circular, light bool) {
			seqACK = seq.Val()
		},
		func(from circular, to circular) {
			seqNAKFrom = from.Val()
			seqNAKTo = to.Val()
		},
		func(p packet) {
			numbers = append(numbers, p.Header().packetSequenceNumber.Val())
		},
	)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for i := 0; i < 5; i++ {
		p := newPacket(addr, nil)
		p.Header().packetSequenceNumber = newCircular(uint32(i), MAX_SEQUENCENUMBER)
		p.Header().pktTsbpdTime = uint64(i + 1)

		recv.Push(p)
	}

	require.Equal(t, uint32(0), seqACK)
	require.Equal(t, uint32(0), seqNAKFrom)
	require.Equal(t, uint32(0), seqNAKTo)
	require.Equal(t, uint32(4), recv.maxSeenSequenceNumber.Val())

	for i := 7; i < 10; i++ {
		p := newPacket(addr, nil)
		p.Header().packetSequenceNumber = newCircular(uint32(i), MAX_SEQUENCENUMBER)
		p.Header().pktTsbpdTime = uint64(i + 1)

		recv.Push(p)
	}

	require.Equal(t, uint32(0), seqACK)
	require.Equal(t, uint32(5), seqNAKFrom)
	require.Equal(t, uint32(6), seqNAKTo)
	require.Equal(t, uint32(9), recv.maxSeenSequenceNumber.Val())

	recv.Tick(10) // ACK period

	require.Equal(t, uint32(5), seqACK)
	require.Equal(t, uint32(5), seqNAKFrom)
	require.Equal(t, uint32(6), seqNAKTo)
	require.Equal(t, uint32(9), recv.maxSeenSequenceNumber.Val())
}

func TestRecvPeriodicNAK(t *testing.T) {
	seqACK := uint32(0)
	seqNAKFrom := uint32(0)
	seqNAKTo := uint32(0)
	numbers := []uint32{}
	recv := mockLiveRecv(
		func(seq circular, light bool) {
			seqACK = seq.Val()
		},
		func(from circular, to circular) {
			seqNAKFrom = from.Val()
			seqNAKTo = to.Val()
		},
		func(p packet) {
			numbers = append(numbers, p.Header().packetSequenceNumber.Val())
		},
	)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for i := 0; i < 5; i++ {
		p := newPacket(addr, nil)
		p.Header().packetSequenceNumber = newCircular(uint32(i), MAX_SEQUENCENUMBER)
		p.Header().pktTsbpdTime = uint64(50 + i + 1)

		recv.Push(p)
	}

	require.Equal(t, uint32(0), seqACK)
	require.Equal(t, uint32(0), seqNAKFrom)
	require.Equal(t, uint32(0), seqNAKTo)
	require.Equal(t, uint32(4), recv.maxSeenSequenceNumber.Val())

	for i := 7; i < 10; i++ {
		p := newPacket(addr, nil)
		p.Header().packetSequenceNumber = newCircular(uint32(i), MAX_SEQUENCENUMBER)
		p.Header().pktTsbpdTime = uint64(50 + i + 1)

		recv.Push(p)
	}

	require.Equal(t, uint32(0), seqACK)
	require.Equal(t, uint32(5), seqNAKFrom)
	require.Equal(t, uint32(6), seqNAKTo)
	require.Equal(t, uint32(9), recv.maxSeenSequenceNumber.Val())

	recv.Tick(10) // ACK period

	require.Equal(t, uint32(5), seqACK)
	require.Equal(t, uint32(5), seqNAKFrom)
	require.Equal(t, uint32(6), seqNAKTo)
	require.Equal(t, uint32(9), recv.maxSeenSequenceNumber.Val())

	seqNAKFrom = 0
	seqNAKTo = 0

	recv.Tick(20) // ACK period, NAK period

	require.Equal(t, uint32(5), seqACK)
	require.Equal(t, uint32(5), seqNAKFrom)
	require.Equal(t, uint32(6), seqNAKTo)
	require.Equal(t, uint32(9), recv.maxSeenSequenceNumber.Val())
}

func TestRecvACK(t *testing.T) {
	seqACK := uint32(0)
	seqNAKFrom := uint32(0)
	seqNAKTo := uint32(0)
	numbers := []uint32{}
	recv := mockLiveRecv(
		func(seq circular, light bool) {
			seqACK = seq.Val()
		},
		func(from circular, to circular) {
			seqNAKFrom = from.Val()
			seqNAKTo = to.Val()
		},
		func(p packet) {
			numbers = append(numbers, p.Header().packetSequenceNumber.Val())
		},
	)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for i := 0; i < 5; i++ {
		p := newPacket(addr, nil)
		p.Header().packetSequenceNumber = newCircular(uint32(i), MAX_SEQUENCENUMBER)
		p.Header().pktTsbpdTime = uint64(10 + i + 1)

		recv.Push(p)
	}

	require.Equal(t, uint32(0), seqACK)
	require.Equal(t, uint32(0), seqNAKFrom)
	require.Equal(t, uint32(0), seqNAKTo)
	require.Equal(t, uint32(4), recv.maxSeenSequenceNumber.Val())
	require.Equal(t, uint32(0), recv.lastACKSequenceNumber.Inc().Val())
	require.Exactly(t, []uint32{}, numbers)

	for i := 7; i < 10; i++ {
		p := newPacket(addr, nil)
		p.Header().packetSequenceNumber = newCircular(uint32(i), MAX_SEQUENCENUMBER)
		p.Header().pktTsbpdTime = uint64(30 + i + 1)

		recv.Push(p)
	}

	require.Equal(t, uint32(0), seqACK)
	require.Equal(t, uint32(5), seqNAKFrom)
	require.Equal(t, uint32(6), seqNAKTo)
	require.Equal(t, uint32(9), recv.maxSeenSequenceNumber.Val())
	require.Equal(t, uint32(0), recv.lastACKSequenceNumber.Inc().Val())
	require.Exactly(t, []uint32{}, numbers)

	recv.Tick(10)

	require.Equal(t, uint32(5), seqACK)
	require.Equal(t, uint32(5), seqNAKFrom)
	require.Equal(t, uint32(6), seqNAKTo)
	require.Equal(t, uint32(9), recv.maxSeenSequenceNumber.Val())
	require.Equal(t, uint32(5), recv.lastACKSequenceNumber.Inc().Val())
	require.Exactly(t, []uint32{}, numbers)

	recv.Tick(20)

	require.Equal(t, uint32(5), seqACK)
	require.Equal(t, uint32(5), seqNAKFrom)
	require.Equal(t, uint32(6), seqNAKTo)
	require.Equal(t, uint32(9), recv.maxSeenSequenceNumber.Val())
	require.Equal(t, uint32(5), recv.lastACKSequenceNumber.Inc().Val())
	require.Exactly(t, []uint32{0, 1, 2, 3, 4}, numbers)

	recv.Tick(30)

	for i := 5; i < 7; i++ {
		p := newPacket(addr, nil)
		p.Header().packetSequenceNumber = newCircular(uint32(i), MAX_SEQUENCENUMBER)
		p.Header().pktTsbpdTime = uint64(30 + i + 1)

		recv.Push(p)
	}

	require.Equal(t, uint32(5), seqACK)
	require.Equal(t, uint32(5), seqNAKFrom)
	require.Equal(t, uint32(6), seqNAKTo)
	require.Equal(t, uint32(9), recv.maxSeenSequenceNumber.Val())
	require.Equal(t, uint32(5), recv.lastACKSequenceNumber.Inc().Val())
	require.Exactly(t, []uint32{0, 1, 2, 3, 4}, numbers)

	recv.Tick(40)

	require.Equal(t, uint32(10), seqACK)
	require.Equal(t, uint32(5), seqNAKFrom)
	require.Equal(t, uint32(6), seqNAKTo)
	require.Equal(t, uint32(9), recv.maxSeenSequenceNumber.Val())
	require.Equal(t, uint32(10), recv.lastACKSequenceNumber.Inc().Val())
	require.Exactly(t, []uint32{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, numbers)
}

func TestRecvDropTooLate(t *testing.T) {
	recv := mockLiveRecv(
		nil,
		nil,
		nil,
	)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for i := 0; i < 10; i++ {
		p := newPacket(addr, nil)
		p.Header().packetSequenceNumber = newCircular(uint32(i), MAX_SEQUENCENUMBER)
		p.Header().pktTsbpdTime = uint64(i + 1)

		recv.Push(p)
	}

	recv.Tick(10) // ACK period

	stats := recv.Stats()

	require.Equal(t, uint32(9), recv.lastACKSequenceNumber.Val())
	require.Equal(t, uint32(9), recv.lastDeliveredSequenceNumber.Val())
	require.Equal(t, uint32(9), recv.maxSeenSequenceNumber.Val())
	require.Equal(t, uint64(0), stats.pktRcvDrop)

	p := newPacket(addr, nil)
	p.Header().packetSequenceNumber = newCircular(uint32(3), MAX_SEQUENCENUMBER)
	p.Header().pktTsbpdTime = uint64(4)

	recv.Push(p)

	stats = recv.Stats()

	require.Equal(t, uint64(1), stats.pktRcvDrop)
}

func TestRecvDropAlreadyACK(t *testing.T) {
	recv := mockLiveRecv(
		nil,
		nil,
		nil,
	)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for i := 0; i < 5; i++ {
		p := newPacket(addr, nil)
		p.Header().packetSequenceNumber = newCircular(uint32(i), MAX_SEQUENCENUMBER)
		p.Header().pktTsbpdTime = uint64(i + 1)

		recv.Push(p)
	}

	for i := 5; i < 10; i++ {
		p := newPacket(addr, nil)
		p.Header().packetSequenceNumber = newCircular(uint32(i), MAX_SEQUENCENUMBER)
		p.Header().pktTsbpdTime = uint64(10 + i + 1)

		recv.Push(p)
	}

	recv.Tick(10) // ACK period

	stats := recv.Stats()

	require.Equal(t, uint32(9), recv.lastACKSequenceNumber.Val())
	require.Equal(t, uint32(4), recv.lastDeliveredSequenceNumber.Val())
	require.Equal(t, uint32(9), recv.maxSeenSequenceNumber.Val())
	require.Equal(t, uint64(0), stats.pktRcvDrop)

	p := newPacket(addr, nil)
	p.Header().packetSequenceNumber = newCircular(uint32(6), MAX_SEQUENCENUMBER)
	p.Header().pktTsbpdTime = uint64(7)

	recv.Push(p)

	stats = recv.Stats()

	require.Equal(t, uint64(1), stats.pktRcvDrop)
}

func TestRecvDropAlreadyRecvNoACK(t *testing.T) {
	recv := mockLiveRecv(
		nil,
		nil,
		nil,
	)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for i := 0; i < 5; i++ {
		p := newPacket(addr, nil)
		p.Header().packetSequenceNumber = newCircular(uint32(i), MAX_SEQUENCENUMBER)
		p.Header().pktTsbpdTime = uint64(i + 1)

		recv.Push(p)
	}

	for i := 5; i < 10; i++ {
		p := newPacket(addr, nil)
		p.Header().packetSequenceNumber = newCircular(uint32(i), MAX_SEQUENCENUMBER)
		p.Header().pktTsbpdTime = uint64(10 + i + 1)

		recv.Push(p)
	}

	recv.Tick(10) // ACK period

	for i := 0; i < 10; i++ {
		p := newPacket(addr, nil)
		p.Header().packetSequenceNumber = newCircular(uint32(10+i), MAX_SEQUENCENUMBER)
		p.Header().pktTsbpdTime = uint64(20 + i + 1)

		recv.Push(p)
	}

	stats := recv.Stats()

	require.Equal(t, uint32(9), recv.lastACKSequenceNumber.Val())
	require.Equal(t, uint32(4), recv.lastDeliveredSequenceNumber.Val())
	require.Equal(t, uint32(19), recv.maxSeenSequenceNumber.Val())
	require.Equal(t, uint64(0), stats.pktRcvDrop)

	p := newPacket(addr, nil)
	p.Header().packetSequenceNumber = newCircular(uint32(15), MAX_SEQUENCENUMBER)
	p.Header().pktTsbpdTime = uint64(20 + 6)

	recv.Push(p)

	stats = recv.Stats()

	require.Equal(t, uint64(1), stats.pktRcvDrop)
}
func TestRecvFlush(t *testing.T) {
	recv := mockLiveRecv(
		nil,
		nil,
		nil,
	)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for i := 0; i < 10; i++ {
		p := newPacket(addr, nil)
		p.Header().packetSequenceNumber = newCircular(uint32(i), MAX_SEQUENCENUMBER)
		p.Header().pktTsbpdTime = uint64(i + 1)

		recv.Push(p)
	}

	require.Equal(t, 10, recv.packetList.Len())

	recv.Flush()

	require.Equal(t, 00, recv.packetList.Len())
}

func TestRecvPeriodicACKLite(t *testing.T) {
	liteACK := false
	recv := mockLiveRecv(
		func(seq circular, light bool) {
			liteACK = light
		},
		nil,
		nil,
	)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for i := 0; i < 100; i++ {
		p := newPacket(addr, nil)
		p.Header().packetSequenceNumber = newCircular(uint32(i), MAX_SEQUENCENUMBER)
		p.Header().pktTsbpdTime = uint64(10 + i + 1)

		recv.Push(p)
	}

	require.Equal(t, false, liteACK)

	recv.Tick(1)

	require.Equal(t, true, liteACK)
}
