package live

import (
	"net"
	"testing"

	"github.com/datarhei/gosrt/circular"
	"github.com/datarhei/gosrt/packet"
	"github.com/stretchr/testify/require"
)

func mockLiveRecv(onSendACK func(seq circular.Number, light bool), onSendNAK func(list []circular.Number), onDeliver func(p packet.Packet)) *receiver {
	recv := NewReceiver(ReceiveConfig{
		InitialSequenceNumber: circular.New(0, packet.MAX_SEQUENCENUMBER),
		PeriodicACKInterval:   10,
		PeriodicNAKInterval:   20,
		OnSendACK:             onSendACK,
		OnSendNAK:             onSendNAK,
		OnDeliver:             onDeliver,
	})

	return recv.(*receiver)
}

func TestRecvSequence(t *testing.T) {
	nACK := 0
	nNAK := 0
	numbers := []uint32{}
	recv := mockLiveRecv(
		func(seq circular.Number, light bool) {
			nACK++
		},
		func(list []circular.Number) {
			nNAK++
		},
		func(p packet.Packet) {
			numbers = append(numbers, p.Header().PacketSequenceNumber.Val())
		},
	)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for i := range 10 {
		p := packet.NewPacket(addr)
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

	for i := range 20 {
		p := packet.NewPacket(addr)
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
	seqNAK := []uint32{}
	numbers := []uint32{}
	recv := mockLiveRecv(
		func(seq circular.Number, light bool) {
			seqACK = seq.Val()
		},
		func(list []circular.Number) {
			seqNAK = []uint32{}
			for _, sn := range list {
				seqNAK = append(seqNAK, sn.Val())
			}
		},
		func(p packet.Packet) {
			numbers = append(numbers, p.Header().PacketSequenceNumber.Val())
		},
	)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for i := range 5 {
		p := packet.NewPacket(addr)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(i + 1)

		recv.Push(p)
	}

	require.Equal(t, uint32(0), seqACK)
	require.Equal(t, []uint32{}, seqNAK)
	require.Equal(t, uint32(4), recv.maxSeenSequenceNumber.Val())

	for i := 7; i < 10; i++ {
		p := packet.NewPacket(addr)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(i + 1)

		recv.Push(p)
	}

	require.Equal(t, uint32(0), seqACK)
	require.Equal(t, []uint32{5, 6}, seqNAK)
	require.Equal(t, uint32(9), recv.maxSeenSequenceNumber.Val())

	recv.Tick(10) // ACK period

	require.Equal(t, uint32(10), seqACK)
	require.Equal(t, []uint32{5, 6}, seqNAK)
	require.Equal(t, uint32(9), recv.maxSeenSequenceNumber.Val())
}

func TestRecvPeriodicNAK(t *testing.T) {
	seqACK := uint32(0)
	seqNAK := []uint32{}
	numbers := []uint32{}
	recv := mockLiveRecv(
		func(seq circular.Number, light bool) {
			seqACK = seq.Val()
		},
		func(list []circular.Number) {
			seqNAK = []uint32{}
			for _, sn := range list {
				seqNAK = append(seqNAK, sn.Val())
			}
		},
		func(p packet.Packet) {
			numbers = append(numbers, p.Header().PacketSequenceNumber.Val())
		},
	)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for i := range 5 {
		p := packet.NewPacket(addr)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(50 + i + 1)

		recv.Push(p)
	}

	require.Equal(t, uint32(0), seqACK)
	require.Equal(t, []uint32{}, seqNAK)
	require.Equal(t, uint32(4), recv.maxSeenSequenceNumber.Val())

	for i := 7; i < 10; i++ {
		p := packet.NewPacket(addr)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(50 + i + 1)

		recv.Push(p)
	}

	require.Equal(t, uint32(0), seqACK)
	require.Equal(t, []uint32{5, 6}, seqNAK)
	require.Equal(t, uint32(9), recv.maxSeenSequenceNumber.Val())

	recv.Tick(10) // ACK period

	require.Equal(t, uint32(5), seqACK)
	require.Equal(t, []uint32{5, 6}, seqNAK)
	require.Equal(t, uint32(9), recv.maxSeenSequenceNumber.Val())

	recv.Tick(20) // ACK period, NAK period

	require.Equal(t, uint32(5), seqACK)
	require.Equal(t, []uint32{5, 6}, seqNAK)
	require.Equal(t, uint32(9), recv.maxSeenSequenceNumber.Val())
}

func TestRecvACK(t *testing.T) {
	seqACK := uint32(0)
	seqNAK := []uint32{}
	numbers := []uint32{}
	recv := mockLiveRecv(
		func(seq circular.Number, light bool) {
			seqACK = seq.Val()
		},
		func(list []circular.Number) {
			seqNAK = []uint32{}
			for _, sn := range list {
				seqNAK = append(seqNAK, sn.Val())
			}
		},
		func(p packet.Packet) {
			numbers = append(numbers, p.Header().PacketSequenceNumber.Val())
		},
	)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for i := range 5 {
		p := packet.NewPacket(addr)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(10 + i + 1)

		recv.Push(p)
	}

	require.Equal(t, uint32(0), seqACK)
	require.Equal(t, []uint32{}, seqNAK)
	require.Equal(t, uint32(4), recv.maxSeenSequenceNumber.Val())
	require.Equal(t, uint32(0), recv.lastACKSequenceNumber.Inc().Val())
	require.Equal(t, uint32(0), recv.lastDeliveredSequenceNumber.Inc().Val())
	require.Exactly(t, []uint32{}, numbers)

	for i := 7; i < 10; i++ {
		p := packet.NewPacket(addr)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(30 + i + 1)

		recv.Push(p)
	}

	require.Equal(t, uint32(0), seqACK)
	require.Equal(t, []uint32{5, 6}, seqNAK)
	require.Equal(t, uint32(9), recv.maxSeenSequenceNumber.Val())
	require.Equal(t, uint32(0), recv.lastACKSequenceNumber.Inc().Val())
	require.Equal(t, uint32(0), recv.lastDeliveredSequenceNumber.Inc().Val())
	require.Exactly(t, []uint32{}, numbers)

	for i := 15; i < 20; i++ {
		p := packet.NewPacket(addr)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(30 + i + 1)

		recv.Push(p)
	}

	require.Equal(t, uint32(0), seqACK)
	require.Equal(t, []uint32{10, 14}, seqNAK)
	require.Equal(t, uint32(19), recv.maxSeenSequenceNumber.Val())
	require.Equal(t, uint32(0), recv.lastACKSequenceNumber.Inc().Val())
	require.Equal(t, uint32(0), recv.lastDeliveredSequenceNumber.Inc().Val())
	require.Exactly(t, []uint32{}, numbers)

	recv.Tick(10)

	require.Equal(t, uint32(5), seqACK)
	require.Equal(t, []uint32{10, 14}, seqNAK)
	require.Equal(t, uint32(19), recv.maxSeenSequenceNumber.Val())
	require.Equal(t, uint32(5), recv.lastACKSequenceNumber.Inc().Val())
	require.Equal(t, uint32(0), recv.lastDeliveredSequenceNumber.Inc().Val())
	require.Exactly(t, []uint32{}, numbers)

	recv.Tick(20)

	require.Equal(t, uint32(5), seqACK)
	require.Equal(t, []uint32{5, 6, 10, 14}, seqNAK)
	require.Equal(t, uint32(19), recv.maxSeenSequenceNumber.Val())
	require.Equal(t, uint32(5), recv.lastACKSequenceNumber.Inc().Val())
	require.Equal(t, uint32(5), recv.lastDeliveredSequenceNumber.Inc().Val())
	require.Exactly(t, []uint32{0, 1, 2, 3, 4}, numbers)

	recv.Tick(30)

	require.Equal(t, uint32(5), seqACK)
	require.Equal(t, []uint32{5, 6, 10, 14}, seqNAK)
	require.Equal(t, uint32(19), recv.maxSeenSequenceNumber.Val())
	require.Equal(t, uint32(5), recv.lastACKSequenceNumber.Inc().Val())
	require.Equal(t, uint32(5), recv.lastDeliveredSequenceNumber.Inc().Val())
	require.Exactly(t, []uint32{0, 1, 2, 3, 4}, numbers)

	for i := 5; i < 7; i++ {
		p := packet.NewPacket(addr)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(30 + i + 1)

		recv.Push(p)
	}

	recv.Tick(40)

	require.Equal(t, uint32(10), seqACK)
	require.Equal(t, []uint32{10, 14}, seqNAK)
	require.Equal(t, uint32(19), recv.maxSeenSequenceNumber.Val())
	require.Equal(t, uint32(10), recv.lastACKSequenceNumber.Inc().Val())
	require.Equal(t, uint32(10), recv.lastDeliveredSequenceNumber.Inc().Val())
	require.Exactly(t, []uint32{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, numbers)
}

func TestRecvDropTooLate(t *testing.T) {
	recv := mockLiveRecv(
		nil,
		nil,
		nil,
	)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for i := range 10 {
		p := packet.NewPacket(addr)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(i + 1)

		recv.Push(p)
	}

	recv.Tick(10) // ACK period

	stats := recv.Stats()

	require.Equal(t, uint32(9), recv.lastACKSequenceNumber.Val())
	require.Equal(t, uint32(9), recv.lastDeliveredSequenceNumber.Val())
	require.Equal(t, uint32(9), recv.maxSeenSequenceNumber.Val())
	require.Equal(t, uint64(0), stats.PktDrop)

	p := packet.NewPacket(addr)
	p.Header().PacketSequenceNumber = circular.New(uint32(3), packet.MAX_SEQUENCENUMBER)
	p.Header().PktTsbpdTime = uint64(4)

	recv.Push(p)

	stats = recv.Stats()

	require.Equal(t, uint64(1), stats.PktDrop)
}

func TestRecvDropAlreadyACK(t *testing.T) {
	recv := mockLiveRecv(
		nil,
		nil,
		nil,
	)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for i := range 5 {
		p := packet.NewPacket(addr)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(i + 1)

		recv.Push(p)
	}

	for i := 5; i < 10; i++ {
		p := packet.NewPacket(addr)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(10 + i + 1)

		recv.Push(p)
	}

	recv.Tick(10) // ACK period

	stats := recv.Stats()

	require.Equal(t, uint32(9), recv.lastACKSequenceNumber.Val())
	require.Equal(t, uint32(4), recv.lastDeliveredSequenceNumber.Val())
	require.Equal(t, uint32(9), recv.maxSeenSequenceNumber.Val())
	require.Equal(t, uint64(0), stats.PktDrop)

	p := packet.NewPacket(addr)
	p.Header().PacketSequenceNumber = circular.New(uint32(6), packet.MAX_SEQUENCENUMBER)
	p.Header().PktTsbpdTime = uint64(7)

	recv.Push(p)

	stats = recv.Stats()

	require.Equal(t, uint64(1), stats.PktDrop)
}

func TestRecvDropAlreadyRecvNoACK(t *testing.T) {
	recv := mockLiveRecv(
		nil,
		nil,
		nil,
	)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for i := range 5 {
		p := packet.NewPacket(addr)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(i + 1)

		recv.Push(p)
	}

	for i := 5; i < 10; i++ {
		p := packet.NewPacket(addr)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(10 + i + 1)

		recv.Push(p)
	}

	recv.Tick(10) // ACK period

	for i := range 10 {
		p := packet.NewPacket(addr)
		p.Header().PacketSequenceNumber = circular.New(uint32(10+i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(20 + i + 1)

		recv.Push(p)
	}

	stats := recv.Stats()

	require.Equal(t, uint32(9), recv.lastACKSequenceNumber.Val())
	require.Equal(t, uint32(4), recv.lastDeliveredSequenceNumber.Val())
	require.Equal(t, uint32(19), recv.maxSeenSequenceNumber.Val())
	require.Equal(t, uint64(0), stats.PktDrop)

	p := packet.NewPacket(addr)
	p.Header().PacketSequenceNumber = circular.New(uint32(15), packet.MAX_SEQUENCENUMBER)
	p.Header().PktTsbpdTime = uint64(20 + 6)

	recv.Push(p)

	stats = recv.Stats()

	require.Equal(t, uint64(1), stats.PktDrop)
}

func TestRecvFlush(t *testing.T) {
	recv := mockLiveRecv(
		nil,
		nil,
		nil,
	)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for i := range 10 {
		p := packet.NewPacket(addr)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(i + 1)

		recv.Push(p)
	}

	require.Equal(t, 10, recv.packetList.Len())

	recv.Flush()

	require.Equal(t, 0, recv.packetList.Len())
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

	for i := range 100 {
		p := packet.NewPacket(addr)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(10 + i + 1)

		recv.Push(p)
	}

	require.Equal(t, false, liteACK)

	recv.Tick(1)

	require.Equal(t, true, liteACK)
}

func TestSkipTooLate(t *testing.T) {
	seqACK := uint32(0)
	numbers := []uint32{}
	recv := mockLiveRecv(
		func(seq circular.Number, light bool) {
			seqACK = seq.Val()
		},
		nil,
		func(p packet.Packet) {
			numbers = append(numbers, p.Header().PacketSequenceNumber.Val())
		},
	)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for i := range 5 {
		p := packet.NewPacket(addr)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(i + 1)

		recv.Push(p)
	}

	recv.Tick(10)

	require.Equal(t, uint32(5), seqACK)
	require.Equal(t, []uint32{0, 1, 2, 3, 4}, numbers)

	for i := 5; i < 10; i++ {
		p := packet.NewPacket(addr)
		p.Header().PacketSequenceNumber = circular.New(uint32(3+i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(13 + i + 1)

		recv.Push(p)
	}

	recv.Tick(20)

	require.Equal(t, uint32(13), seqACK)
	require.Equal(t, []uint32{0, 1, 2, 3, 4, 8, 9}, numbers)
}

func TestIssue67(t *testing.T) {
	ackNumbers := []uint32{}
	nakNumbers := [][2]uint32{}
	numbers := []uint32{}
	recv := mockLiveRecv(
		func(seq circular.Number, light bool) {
			ackNumbers = append(ackNumbers, seq.Val())
		},
		func(list []circular.Number) {
			nakNumbers = append(nakNumbers, [2]uint32{list[0].Val(), list[1].Val()})
		},
		func(p packet.Packet) {
			numbers = append(numbers, p.Header().PacketSequenceNumber.Val())
		},
	)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	p := packet.NewPacket(addr)
	p.Header().PacketSequenceNumber = circular.New(0, packet.MAX_SEQUENCENUMBER)
	p.Header().PktTsbpdTime = 1

	recv.Push(p)

	recv.Tick(10)
	recv.Tick(20)
	recv.Tick(30)
	recv.Tick(40)
	recv.Tick(50)
	recv.Tick(60)
	recv.Tick(70)
	recv.Tick(80)
	recv.Tick(90)

	require.Equal(t, []uint32{1, 1, 1, 1, 1, 1, 1, 1, 1}, ackNumbers)

	p = packet.NewPacket(addr)
	p.Header().PacketSequenceNumber = circular.New(12, packet.MAX_SEQUENCENUMBER)
	p.Header().PktTsbpdTime = 121

	recv.Push(p)

	require.Equal(t, [][2]uint32{
		{1, 11},
	}, nakNumbers)

	p = packet.NewPacket(addr)
	p.Header().PacketSequenceNumber = circular.New(1, packet.MAX_SEQUENCENUMBER)
	p.Header().PktTsbpdTime = 11

	recv.Push(p)

	p = packet.NewPacket(addr)
	p.Header().PacketSequenceNumber = circular.New(11, packet.MAX_SEQUENCENUMBER)
	p.Header().PktTsbpdTime = 111

	recv.Push(p)

	recv.Tick(100)

	require.Equal(t, []uint32{1, 1, 1, 1, 1, 1, 1, 1, 1, 2}, ackNumbers)

	recv.Tick(110)

	require.Equal(t, []uint32{1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2}, ackNumbers)

	recv.Tick(120)

	require.Equal(t, []uint32{1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 13}, ackNumbers)

	recv.Tick(130)

	require.Equal(t, []uint32{1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 13, 13}, ackNumbers)
}

func TestRecvBelated(t *testing.T) {
	recv := mockLiveRecv(
		func(seq circular.Number, light bool) {},
		func(list []circular.Number) {},
		func(p packet.Packet) {},
	)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for i := range 3 {
		p := packet.NewPacket(addr)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(i + 1)

		recv.Push(p)
	}

	require.Equal(t, uint64(3), recv.statistics.Pkt)
	require.Equal(t, uint64(3), recv.statistics.PktBuf)
	require.Equal(t, uint64(0), recv.statistics.PktLoss)
	require.Equal(t, uint64(0), recv.statistics.PktBelated)

	p := packet.NewPacket(addr)
	p.Header().PacketSequenceNumber = circular.New(uint32(4), packet.MAX_SEQUENCENUMBER)
	p.Header().PktTsbpdTime = uint64(4 + 1)

	recv.Push(p)

	require.Equal(t, uint64(4), recv.statistics.Pkt)
	require.Equal(t, uint64(4), recv.statistics.PktBuf)
	require.Equal(t, uint64(1), recv.statistics.PktLoss)
	require.Equal(t, uint64(0), recv.statistics.PktBelated)

	recv.Tick(10) // ACK period

	p = packet.NewPacket(addr)
	p.Header().PacketSequenceNumber = circular.New(uint32(3), packet.MAX_SEQUENCENUMBER)
	p.Header().PktTsbpdTime = uint64(3 + 1)

	recv.Push(p)

	require.Equal(t, uint64(5), recv.statistics.Pkt)
	require.Equal(t, uint64(0), recv.statistics.PktBuf)
	require.Equal(t, uint64(1), recv.statistics.PktLoss)
	require.Equal(t, uint64(1), recv.statistics.PktBelated)
}

func TestRecvLate(t *testing.T) {
	recv := mockLiveRecv(
		func(seq circular.Number, light bool) {},
		func(list []circular.Number) {},
		func(p packet.Packet) {},
	)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for i := range 3 {
		p := packet.NewPacket(addr)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(i + 1)

		recv.Push(p)
	}

	require.Equal(t, uint64(3), recv.statistics.Pkt)
	require.Equal(t, uint64(3), recv.statistics.PktBuf)
	require.Equal(t, uint64(0), recv.statistics.PktLoss)
	require.Equal(t, uint64(0), recv.statistics.PktBelated)
	require.Equal(t, uint64(0), recv.statistics.PktLate)

	p := packet.NewPacket(addr)
	p.Header().PacketSequenceNumber = circular.New(uint32(4), packet.MAX_SEQUENCENUMBER)
	p.Header().PktTsbpdTime = uint64(4 + 1)

	recv.Push(p)

	require.Equal(t, uint64(4), recv.statistics.Pkt)
	require.Equal(t, uint64(4), recv.statistics.PktBuf)
	require.Equal(t, uint64(1), recv.statistics.PktLoss)
	require.Equal(t, uint64(0), recv.statistics.PktBelated)
	require.Equal(t, uint64(0), recv.statistics.PktLate)

	p = packet.NewPacket(addr)
	p.Header().PacketSequenceNumber = circular.New(uint32(3), packet.MAX_SEQUENCENUMBER)
	p.Header().PktTsbpdTime = uint64(3 + 1)

	recv.Push(p)

	require.Equal(t, uint64(5), recv.statistics.Pkt)
	require.Equal(t, uint64(5), recv.statistics.PktBuf)
	require.Equal(t, uint64(1), recv.statistics.PktLoss)
	require.Equal(t, uint64(0), recv.statistics.PktBelated)
	require.Equal(t, uint64(1), recv.statistics.PktLate)
}

func TestRecvLost(t *testing.T) {
	recv := mockLiveRecv(
		func(seq circular.Number, light bool) {},
		func(list []circular.Number) {},
		func(p packet.Packet) {},
	)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	for i := 1; i < 5; i++ {
		p := packet.NewPacket(addr)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(i + 1)

		recv.Push(p)
	}

	require.Equal(t, uint64(4), recv.statistics.Pkt)
	require.Equal(t, uint64(4), recv.statistics.PktBuf)
	require.Equal(t, uint64(1), recv.statistics.PktLoss)
	require.Equal(t, uint64(0), recv.statistics.PktLost)

	for i := 7; i < 10; i++ {
		p := packet.NewPacket(addr)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(i + 1)

		recv.Push(p)
	}

	require.Equal(t, uint64(7), recv.statistics.Pkt)
	require.Equal(t, uint64(7), recv.statistics.PktBuf)
	require.Equal(t, uint64(3), recv.statistics.PktLoss)
	require.Equal(t, uint64(0), recv.statistics.PktLost)

	recv.Tick(10) // ACK period

	require.Equal(t, uint64(7), recv.statistics.Pkt)
	require.Equal(t, uint64(0), recv.statistics.PktBuf)
	require.Equal(t, uint64(3), recv.statistics.PktLoss)
	require.Equal(t, uint64(3), recv.statistics.PktLost)
}

func mockReorderRecv(maxTolerance uint32, nakList *[][]uint32) *receiver {
	return NewReceiver(ReceiveConfig{
		InitialSequenceNumber: circular.New(0, packet.MAX_SEQUENCENUMBER),
		PeriodicACKInterval:   10,
		PeriodicNAKInterval:   20,
		ReorderTolerance:      maxTolerance,
		OnSendNAK: func(list []circular.Number) {
			l := []uint32{}
			for _, n := range list {
				l = append(l, n.Val())
			}
			*nakList = append(*nakList, l)
		},
	}).(*receiver)
}

func pushSeq(recv *receiver, i uint32, retransmitted bool) {
	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	p := packet.NewPacket(addr)
	p.Header().PacketSequenceNumber = circular.New(i, packet.MAX_SEQUENCENUMBER)
	p.Header().PktTsbpdTime = uint64(i + 1_000_000)
	p.Header().RetransmittedPacketFlag = retransmitted

	recv.Push(p)
}

func TestRecvReorderTolerance(t *testing.T) {
	nakList := [][]uint32{}
	recv := mockReorderRecv(30, &nakList)

	require.Equal(t, uint64(30), recv.Stats().PktReorderTolerance)

	// 5 arrives 10 packets late
	for i := uint32(0); i <= 15; i++ {
		if i == 5 {
			continue
		}
		pushSeq(recv, i, false)
	}
	pushSeq(recv, 5, false)

	// The gap is counted as loss right away, but no NAK is sent
	require.Equal(t, 0, len(nakList))
	require.Equal(t, uint64(1), recv.statistics.PktLoss)
	require.Equal(t, uint64(1), recv.statistics.PktLate)
	require.Equal(t, uint64(10), recv.statistics.PktReorderDistance)
	require.Equal(t, 0, len(recv.freshLoss))

	// The periodic NAK doesn't find a gap either
	recv.Tick(100)
	require.Equal(t, 0, len(nakList))
}

func TestRecvReorderToleranceExpired(t *testing.T) {
	nakList := [][]uint32{}
	recv := mockReorderRecv(30, &nakList)

	// 20 is missing, it is reported after 30 more packets arrived
	for i := uint32(0); i <= 50; i++ {
		if i == 20 {
			continue
		}
		pushSeq(recv, i, false)
	}

	require.Equal(t, 0, len(nakList))

	pushSeq(recv, 51, false)

	require.Equal(t, [][]uint32{{20, 20}}, nakList)
	require.Equal(t, 0, len(recv.freshLoss))

	// It is reported only once
	pushSeq(recv, 52, false)
	require.Equal(t, 1, len(nakList))
}

func TestRecvReorderToleranceAdapts(t *testing.T) {
	nakList := [][]uint32{}
	recv := mockReorderRecv(30, &nakList)

	// The tolerance decreases by one after 50 packets in order
	seq := uint32(0)
	for ; seq < 500; seq++ {
		pushSeq(recv, seq, false)
	}

	require.Equal(t, uint64(20), recv.Stats().PktReorderTolerance)

	reorder := func(distance uint32) {
		// The packet at seq is missing and arrives after distance more packets
		missing := seq
		for i := uint32(1); i <= distance; i++ {
			pushSeq(recv, missing+i, false)
		}
		pushSeq(recv, missing, false)
		seq += distance + 1
	}

	// A reordered original increases the tolerance
	reorder(25)
	require.Equal(t, uint64(25), recv.Stats().PktReorderTolerance)

	// But not beyond the max.
	reorder(40)
	require.Equal(t, uint64(30), recv.Stats().PktReorderTolerance)
	require.Equal(t, uint64(40), recv.Stats().PktReorderDistance)

	// A retransmission doesn't increase the tolerance
	for ; seq < 1000; seq++ {
		pushSeq(recv, seq, false)
	}
	tolerance := recv.Stats().PktReorderTolerance
	pushSeq(recv, seq+5, false)
	pushSeq(recv, seq+4, true)
	require.Equal(t, tolerance, recv.Stats().PktReorderTolerance)
	seq += 6

	// 10 reordered packets in a row that arrived early decrease the tolerance by one
	tolerance = recv.Stats().PktReorderTolerance
	for range 10 {
		reorder(1)
	}
	require.Equal(t, tolerance-1, recv.Stats().PktReorderTolerance)

	// Only the packets that arrived later than the tolerance at that time allowed have been
	// reported with a NAK, 500 (25 late, tolerance 20) and 526 (40 late, tolerance 25).
	require.Equal(t, [][]uint32{{500, 500}, {526, 526}}, nakList)
}

func TestRecvReorderToleranceDuplicate(t *testing.T) {
	nakList := [][]uint32{}
	recv := mockReorderRecv(30, &nakList)

	seq := uint32(0)
	for ; seq < 40; seq++ {
		pushSeq(recv, seq, false)
	}

	// A retransmitted duplicate doesn't interrupt the packets in order
	pushSeq(recv, 20, true)

	for ; seq < 50; seq++ {
		pushSeq(recv, seq, false)
	}

	require.Equal(t, uint64(29), recv.Stats().PktReorderTolerance)

	for ; seq < 90; seq++ {
		pushSeq(recv, seq, false)
	}

	// An original duplicate does, as in libsrt
	pushSeq(recv, 70, false)

	for ; seq < 110; seq++ {
		pushSeq(recv, seq, false)
	}

	require.Equal(t, uint64(29), recv.Stats().PktReorderTolerance)

	for ; seq < 140; seq++ {
		pushSeq(recv, seq, false)
	}

	require.Equal(t, uint64(28), recv.Stats().PktReorderTolerance)
	require.Equal(t, uint64(2), recv.statistics.PktDrop)
	require.Equal(t, 0, len(nakList))
}

func TestRecvReorderToleranceTLPKTDROP(t *testing.T) {
	nakList := [][]uint32{}
	recv := mockReorderRecv(30, &nakList)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	push := func(i uint32) {
		p := packet.NewPacket(addr)
		p.Header().PacketSequenceNumber = circular.New(i, packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(i + 1)

		recv.Push(p)
	}

	// 2 is missing
	push(0)
	push(1)
	push(3)
	push(4)

	// The delivery skips 2
	recv.Tick(10)
	require.Equal(t, 0, len(recv.freshLoss))

	// 2 is not reported later
	nakList = nakList[:0]
	for i := uint32(5); i < 50; i++ {
		push(i)
	}
	for _, l := range nakList {
		require.NotContains(t, l, uint32(2))
	}
}

func TestRecvFreshLossRanges(t *testing.T) {
	nakList := [][]uint32{}
	recv := mockReorderRecv(30, &nakList)

	n := func(i uint32) circular.Number { return circular.New(i, packet.MAX_SEQUENCENUMBER) }
	ranges := func() [][]uint32 {
		l := [][]uint32{}
		for _, f := range recv.freshLoss {
			l = append(l, []uint32{f.from.Val(), f.to.Val(), uint32(f.ttl)})
		}
		return l
	}

	recv.registerLoss(n(10), n(20))
	recv.registerLoss(n(30), n(30))

	// Split
	require.Equal(t, 30, recv.removeFreshLoss(n(15)))
	require.Equal(t, [][]uint32{{10, 14, 30}, {16, 20, 30}, {30, 30, 30}}, ranges())

	// Shrink and delete
	recv.removeFreshLoss(n(10))
	recv.removeFreshLoss(n(20))
	recv.removeFreshLoss(n(30))
	require.Equal(t, [][]uint32{{11, 14, 30}, {16, 19, 30}}, ranges())

	// Not in any range
	require.Equal(t, 0, recv.removeFreshLoss(n(15)))

	// Revoke up to 17
	recv.revokeFreshLoss(n(17))
	require.Equal(t, [][]uint32{{18, 19, 30}}, ranges())
}

func TestRecvReorderDistance(t *testing.T) {
	recv := mockLiveRecv(nil, nil, nil)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	push := func(i uint32, retransmitted bool) {
		p := packet.NewPacket(addr)
		p.Header().PacketSequenceNumber = circular.New(i, packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(i + 100)
		p.Header().RetransmittedPacketFlag = retransmitted

		recv.Push(p)
	}

	// 3 and 20 are missing
	for i := uint32(0); i <= 25; i++ {
		if i == 3 || i == 20 {
			continue
		}
		push(i, false)
	}

	require.Equal(t, uint64(0), recv.Stats().PktReorderDistance)

	// The original of 3 arrives out of order
	push(3, false)
	require.Equal(t, uint64(22), recv.Stats().PktReorderDistance)

	// A retransmission doesn't count
	push(20, true)
	require.Equal(t, uint64(22), recv.Stats().PktReorderDistance)

	// A smaller distance doesn't decrease the value
	push(30, false)
	push(28, false)
	require.Equal(t, uint64(22), recv.Stats().PktReorderDistance)

	// PktLate counts all packets that filled a gap, original or retransmitted
	require.Equal(t, uint64(3), recv.statistics.PktLate)
}

func TestRecvReorderToleranceSequenceWrap(t *testing.T) {
	nakList := [][]uint32{}
	recv := NewReceiver(ReceiveConfig{
		InitialSequenceNumber: circular.New(packet.MAX_SEQUENCENUMBER-20, packet.MAX_SEQUENCENUMBER),
		PeriodicACKInterval:   10,
		PeriodicNAKInterval:   20,
		ReorderTolerance:      30,
		OnSendNAK: func(list []circular.Number) {
			l := []uint32{}
			for _, n := range list {
				l = append(l, n.Val())
			}
			nakList = append(nakList, l)
		},
	}).(*receiver)

	seq := func(i uint32) uint32 { return (packet.MAX_SEQUENCENUMBER - 20 + i) & packet.MAX_SEQUENCENUMBER }

	// Across the wrap of the sequence number: one packet arrives 10 packets late, one doesn't arrive at all
	for i := uint32(0); i <= 60; i++ {
		if i == 15 || i == 25 {
			continue
		}
		pushSeq(recv, seq(i), false)
		if i == 25 {
			continue
		}
		if i == 26 {
			pushSeq(recv, seq(15), false)
		}
	}

	require.Equal(t, uint64(2), recv.statistics.PktLoss)
	require.Equal(t, uint64(11), recv.statistics.PktReorderDistance)

	// Only the packet that never arrived is reported, after the reorder tolerance
	require.Equal(t, [][]uint32{{seq(25), seq(25)}}, nakList)

	// The ACK moves past the wrap and revokes nothing that is still pending
	recv.Tick(10)
	require.Equal(t, 0, len(recv.freshLoss))
}
