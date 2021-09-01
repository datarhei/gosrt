package congestion

import (
	"net"
	"testing"

	"github.com/datarhei/gosrt/internal/circular"
	"github.com/datarhei/gosrt/internal/packet"

	"github.com/stretchr/testify/require"
)

func mockLiveSend(onDeliver func(p packet.Packet)) *liveSend {
	send := NewLiveSend(SendConfig{
		InitialSequenceNumber: circular.New(0, packet.MAX_SEQUENCENUMBER),
		DropInterval:          10,
		OnDeliver:             onDeliver,
	})

	return send.(*liveSend)
}

func TestSendSequence(t *testing.T) {
	numbers := []uint32{}
	send := mockLiveSend(func(p packet.Packet) {
		numbers = append(numbers, p.Header().PacketSequenceNumber.Val())
	})

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for i := 0; i < 10; i++ {
		p := packet.NewPacket(addr, nil)
		p.Header().PktTsbpdTime = uint64(i + 1)

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
		p := packet.NewPacket(addr, nil)
		p.Header().PktTsbpdTime = uint64(i + 1)

		send.Push(p)
	}

	send.Tick(10)

	require.Equal(t, 10, send.lossList.Len())

	for i := 0; i < 10; i++ {
		send.ACK(circular.New(uint32(i+1), packet.MAX_SEQUENCENUMBER))
		require.Equal(t, 10-(i+1), send.lossList.Len())
	}
}

func TestSendRetransmit(t *testing.T) {
	numbers := []uint32{}
	nRetransmit := 0
	send := mockLiveSend(func(p packet.Packet) {
		numbers = append(numbers, p.Header().PacketSequenceNumber.Val())
		if p.Header().RetransmittedPacketFlag {
			nRetransmit++
		}
	})

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for i := 0; i < 10; i++ {
		p := packet.NewPacket(addr, nil)
		p.Header().PktTsbpdTime = uint64(i + 1)

		send.Push(p)
	}

	send.Tick(10)

	require.Equal(t, 0, nRetransmit)

	send.NAK([]circular.Number{
		circular.New(2, packet.MAX_SEQUENCENUMBER),
		circular.New(2, packet.MAX_SEQUENCENUMBER),
	})

	require.Equal(t, 1, nRetransmit)

	send.NAK([]circular.Number{
		circular.New(5, packet.MAX_SEQUENCENUMBER),
		circular.New(7, packet.MAX_SEQUENCENUMBER),
	})

	require.Equal(t, 4, nRetransmit)
}

func TestSendDrop(t *testing.T) {
	send := mockLiveSend(nil)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for i := 0; i < 10; i++ {
		p := packet.NewPacket(addr, nil)
		p.Header().PktTsbpdTime = uint64(i + 1)

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
		p := packet.NewPacket(addr, nil)
		p.Header().PktTsbpdTime = uint64(i + 1)

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

func mockLiveRecv(onSendACK func(seq circular.Number, light bool), onSendNAK func(from, to circular.Number), onDeliver func(p packet.Packet)) *liveReceive {
	recv := NewLiveReceive(ReceiveConfig{
		InitialSequenceNumber: circular.New(0, packet.MAX_SEQUENCENUMBER),
		PeriodicACKInterval:   10,
		PeriodicNAKInterval:   20,
		OnSendACK:             onSendACK,
		OnSendNAK:             onSendNAK,
		OnDeliver:             onDeliver,
	})

	return recv.(*liveReceive)
}

func TestRecvSequence(t *testing.T) {
	nACK := 0
	nNAK := 0
	numbers := []uint32{}
	recv := mockLiveRecv(
		func(seq circular.Number, light bool) {
			nACK++
		},
		func(from, to circular.Number) {
			nNAK++
		},
		func(p packet.Packet) {
			numbers = append(numbers, p.Header().PacketSequenceNumber.Val())
		},
	)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for i := 0; i < 10; i++ {
		p := packet.NewPacket(addr, nil)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(i + 1)

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
		func(p packet.Packet) {
			numbers = append(numbers, p.Header().PacketSequenceNumber.Val())
		},
	)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for i := 0; i < 20; i++ {
		p := packet.NewPacket(addr, nil)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(i + 1)

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
		func(seq circular.Number, light bool) {
			seqACK = seq.Val()
		},
		func(from, to circular.Number) {
			seqNAKFrom = from.Val()
			seqNAKTo = to.Val()
		},
		func(p packet.Packet) {
			numbers = append(numbers, p.Header().PacketSequenceNumber.Val())
		},
	)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for i := 0; i < 5; i++ {
		p := packet.NewPacket(addr, nil)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(i + 1)

		recv.Push(p)
	}

	require.Equal(t, uint32(0), seqACK)
	require.Equal(t, uint32(0), seqNAKFrom)
	require.Equal(t, uint32(0), seqNAKTo)
	require.Equal(t, uint32(4), recv.maxSeenSequenceNumber.Val())

	for i := 7; i < 10; i++ {
		p := packet.NewPacket(addr, nil)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(i + 1)

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
		func(seq circular.Number, light bool) {
			seqACK = seq.Val()
		},
		func(from, to circular.Number) {
			seqNAKFrom = from.Val()
			seqNAKTo = to.Val()
		},
		func(p packet.Packet) {
			numbers = append(numbers, p.Header().PacketSequenceNumber.Val())
		},
	)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for i := 0; i < 5; i++ {
		p := packet.NewPacket(addr, nil)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(50 + i + 1)

		recv.Push(p)
	}

	require.Equal(t, uint32(0), seqACK)
	require.Equal(t, uint32(0), seqNAKFrom)
	require.Equal(t, uint32(0), seqNAKTo)
	require.Equal(t, uint32(4), recv.maxSeenSequenceNumber.Val())

	for i := 7; i < 10; i++ {
		p := packet.NewPacket(addr, nil)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(50 + i + 1)

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
		func(seq circular.Number, light bool) {
			seqACK = seq.Val()
		},
		func(from, to circular.Number) {
			seqNAKFrom = from.Val()
			seqNAKTo = to.Val()
		},
		func(p packet.Packet) {
			numbers = append(numbers, p.Header().PacketSequenceNumber.Val())
		},
	)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for i := 0; i < 5; i++ {
		p := packet.NewPacket(addr, nil)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(10 + i + 1)

		recv.Push(p)
	}

	require.Equal(t, uint32(0), seqACK)
	require.Equal(t, uint32(0), seqNAKFrom)
	require.Equal(t, uint32(0), seqNAKTo)
	require.Equal(t, uint32(4), recv.maxSeenSequenceNumber.Val())
	require.Equal(t, uint32(0), recv.lastACKSequenceNumber.Inc().Val())
	require.Exactly(t, []uint32{}, numbers)

	for i := 7; i < 10; i++ {
		p := packet.NewPacket(addr, nil)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(30 + i + 1)

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
		p := packet.NewPacket(addr, nil)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(30 + i + 1)

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
		p := packet.NewPacket(addr, nil)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(i + 1)

		recv.Push(p)
	}

	recv.Tick(10) // ACK period

	stats := recv.Stats()

	require.Equal(t, uint32(9), recv.lastACKSequenceNumber.Val())
	require.Equal(t, uint32(9), recv.lastDeliveredSequenceNumber.Val())
	require.Equal(t, uint32(9), recv.maxSeenSequenceNumber.Val())
	require.Equal(t, uint64(0), stats.PktRcvDrop)

	p := packet.NewPacket(addr, nil)
	p.Header().PacketSequenceNumber = circular.New(uint32(3), packet.MAX_SEQUENCENUMBER)
	p.Header().PktTsbpdTime = uint64(4)

	recv.Push(p)

	stats = recv.Stats()

	require.Equal(t, uint64(1), stats.PktRcvDrop)
}

func TestRecvDropAlreadyACK(t *testing.T) {
	recv := mockLiveRecv(
		nil,
		nil,
		nil,
	)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for i := 0; i < 5; i++ {
		p := packet.NewPacket(addr, nil)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(i + 1)

		recv.Push(p)
	}

	for i := 5; i < 10; i++ {
		p := packet.NewPacket(addr, nil)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(10 + i + 1)

		recv.Push(p)
	}

	recv.Tick(10) // ACK period

	stats := recv.Stats()

	require.Equal(t, uint32(9), recv.lastACKSequenceNumber.Val())
	require.Equal(t, uint32(4), recv.lastDeliveredSequenceNumber.Val())
	require.Equal(t, uint32(9), recv.maxSeenSequenceNumber.Val())
	require.Equal(t, uint64(0), stats.PktRcvDrop)

	p := packet.NewPacket(addr, nil)
	p.Header().PacketSequenceNumber = circular.New(uint32(6), packet.MAX_SEQUENCENUMBER)
	p.Header().PktTsbpdTime = uint64(7)

	recv.Push(p)

	stats = recv.Stats()

	require.Equal(t, uint64(1), stats.PktRcvDrop)
}

func TestRecvDropAlreadyRecvNoACK(t *testing.T) {
	recv := mockLiveRecv(
		nil,
		nil,
		nil,
	)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for i := 0; i < 5; i++ {
		p := packet.NewPacket(addr, nil)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(i + 1)

		recv.Push(p)
	}

	for i := 5; i < 10; i++ {
		p := packet.NewPacket(addr, nil)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(10 + i + 1)

		recv.Push(p)
	}

	recv.Tick(10) // ACK period

	for i := 0; i < 10; i++ {
		p := packet.NewPacket(addr, nil)
		p.Header().PacketSequenceNumber = circular.New(uint32(10+i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(20 + i + 1)

		recv.Push(p)
	}

	stats := recv.Stats()

	require.Equal(t, uint32(9), recv.lastACKSequenceNumber.Val())
	require.Equal(t, uint32(4), recv.lastDeliveredSequenceNumber.Val())
	require.Equal(t, uint32(19), recv.maxSeenSequenceNumber.Val())
	require.Equal(t, uint64(0), stats.PktRcvDrop)

	p := packet.NewPacket(addr, nil)
	p.Header().PacketSequenceNumber = circular.New(uint32(15), packet.MAX_SEQUENCENUMBER)
	p.Header().PktTsbpdTime = uint64(20 + 6)

	recv.Push(p)

	stats = recv.Stats()

	require.Equal(t, uint64(1), stats.PktRcvDrop)
}
func TestRecvFlush(t *testing.T) {
	recv := mockLiveRecv(
		nil,
		nil,
		nil,
	)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for i := 0; i < 10; i++ {
		p := packet.NewPacket(addr, nil)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(i + 1)

		recv.Push(p)
	}

	require.Equal(t, 10, recv.packetList.Len())

	recv.Flush()

	require.Equal(t, 00, recv.packetList.Len())
}

func TestRecvPeriodicACKLite(t *testing.T) {
	liteACK := false
	recv := mockLiveRecv(
		func(seq circular.Number, light bool) {
			liteACK = light
		},
		nil,
		nil,
	)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for i := 0; i < 100; i++ {
		p := packet.NewPacket(addr, nil)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(10 + i + 1)

		recv.Push(p)
	}

	require.Equal(t, false, liteACK)

	recv.Tick(1)

	require.Equal(t, true, liteACK)
}
