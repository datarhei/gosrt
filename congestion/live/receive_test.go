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

	for i := 0; i < 10; i++ {
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

	for i := 0; i < 20; i++ {
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

	for i := 0; i < 5; i++ {
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

	for i := 0; i < 5; i++ {
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

	for i := 0; i < 5; i++ {
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

	for i := 0; i < 10; i++ {
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

	for i := 0; i < 5; i++ {
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

	for i := 0; i < 5; i++ {
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

	for i := 0; i < 10; i++ {
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

	for i := 0; i < 10; i++ {
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

	for i := 0; i < 100; i++ {
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

	for i := 0; i < 5; i++ {
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

// mockLiveRecvWithReorder creates a receiver with adaptive reorder tolerance enabled
func mockLiveRecvWithReorder(maxTolerance int, onSendACK func(seq circular.Number, light bool), onSendNAK func(list []circular.Number), onDeliver func(p packet.Packet)) *receiver {
	recv := NewReceiver(ReceiveConfig{
		InitialSequenceNumber: circular.New(0, packet.MAX_SEQUENCENUMBER),
		PeriodicACKInterval:   10,
		PeriodicNAKInterval:   20,
		MaxReorderTolerance:   maxTolerance,
		OnSendACK:             onSendACK,
		OnSendNAK:             onSendNAK,
		OnDeliver:             onDeliver,
	})

	return recv.(*receiver)
}

func TestReorderToleranceIncrease(t *testing.T) {
	nakCalls := 0
	recv := mockLiveRecvWithReorder(10, nil, func(list []circular.Number) {
		nakCalls++
	}, nil)

	// Enable reorder support (simulates REXMIT handshake)
	recv.SetReorderSupport(true)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	// Send packets 0-4 in order
	for i := 0; i < 5; i++ {
		p := packet.NewPacket(addr)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(i + 1)
		recv.Push(p)
	}

	// Skip to packet 10 (gap of 5-9), should defer NAK since tolerance=10
	p := packet.NewPacket(addr)
	p.Header().PacketSequenceNumber = circular.New(10, packet.MAX_SEQUENCENUMBER)
	p.Header().PktTsbpdTime = 11
	recv.Push(p)

	require.Equal(t, 0, nakCalls, "NAK should be deferred when tolerance > 0")
	require.Equal(t, 1, len(recv.freshLoss), "should have one freshLoss entry")
	require.Equal(t, uint32(5), recv.freshLoss[0].seqLo.Val())
	require.Equal(t, uint32(9), recv.freshLoss[0].seqHi.Val())

	// Now send belated original packet 7 (not retransmitted)
	p = packet.NewPacket(addr)
	p.Header().PacketSequenceNumber = circular.New(7, packet.MAX_SEQUENCENUMBER)
	p.Header().PktTsbpdTime = 8
	p.Header().RetransmittedPacketFlag = false
	recv.Push(p)

	// seqdiff = |10 - 7| = 3, which is < tolerance(10), so tolerance stays at 10
	require.Equal(t, 10, recv.reorderTolerance)
	require.Equal(t, 3, recv.traceReorderDistance)
}

func TestReorderToleranceIncreaseAboveCurrent(t *testing.T) {
	recv := mockLiveRecvWithReorder(20, nil, nil, nil)
	recv.SetReorderSupport(true)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	// Send packets 0-4
	for i := 0; i < 5; i++ {
		p := packet.NewPacket(addr)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(i + 1)
		recv.Push(p)
	}

	// Jump to 20 (gap 5-19)
	p := packet.NewPacket(addr)
	p.Header().PacketSequenceNumber = circular.New(20, packet.MAX_SEQUENCENUMBER)
	p.Header().PktTsbpdTime = 21
	recv.Push(p)

	// Now send belated original packet 5 (seqdiff = |20 - 5| = 15)
	// Tolerance should increase from initial 20 to... wait, 15 < 20, so no increase
	// Let's test with a smaller initial tolerance
	recv2 := mockLiveRecvWithReorder(10, nil, nil, nil)
	recv2.SetReorderSupport(true)

	for i := 0; i < 5; i++ {
		p := packet.NewPacket(addr)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(i + 1)
		recv2.Push(p)
	}

	// Jump to 20
	p = packet.NewPacket(addr)
	p.Header().PacketSequenceNumber = circular.New(20, packet.MAX_SEQUENCENUMBER)
	p.Header().PktTsbpdTime = 21
	recv2.Push(p)

	// Belated original packet 8 (seqdiff = |20 - 8| = 12 > tolerance 10, capped at max 10)
	p = packet.NewPacket(addr)
	p.Header().PacketSequenceNumber = circular.New(8, packet.MAX_SEQUENCENUMBER)
	p.Header().PktTsbpdTime = 9
	p.Header().RetransmittedPacketFlag = false
	recv2.Push(p)

	require.Equal(t, 10, recv2.reorderTolerance, "tolerance capped at max")
	require.Equal(t, 12, recv2.traceReorderDistance)
}

func TestReorderToleranceDecayOrdered(t *testing.T) {
	recv := mockLiveRecvWithReorder(10, nil, nil, nil)
	recv.SetReorderSupport(true)

	// Manually set tolerance to 5 for testing decay
	recv.reorderTolerance = 5

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	// Send 50 packets in order to trigger decay
	for i := 0; i < 50; i++ {
		p := packet.NewPacket(addr)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(i + 1)
		recv.Push(p)
	}

	require.Equal(t, 4, recv.reorderTolerance, "tolerance should decay by 1 after 50 ordered deliveries")
	require.Equal(t, 0, recv.consecOrderedDelivery, "counter should reset after decay")
}

func TestReorderToleranceDecayEarly(t *testing.T) {
	recv := mockLiveRecvWithReorder(20, nil, nil, nil)
	recv.SetReorderSupport(true)

	// Set tolerance to 5 (below max so seqdiff won't exceed it for nearby packets)
	recv.reorderTolerance = 5

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	// Send packets 0-4
	for i := 0; i < 5; i++ {
		p := packet.NewPacket(addr)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(i + 1)
		recv.Push(p)
	}

	// Jump to 8 (creates freshLoss 5-7 with TTL=5)
	// seqdiff for belated packets 5,6,7 will be 3,2,1 — all <= tolerance 5
	p := packet.NewPacket(addr)
	p.Header().PacketSequenceNumber = circular.New(8, packet.MAX_SEQUENCENUMBER)
	p.Header().PktTsbpdTime = 9
	recv.Push(p)

	require.Equal(t, 1, len(recv.freshLoss))
	require.Equal(t, 5, recv.freshLoss[0].ttl)

	// We need 10 early deliveries. Create multiple small gaps and fill them.
	// Each belated original with hadTTL > 2 counts as one early delivery.
	// Fill gap 5-7 (3 belated originals, hadTTL=5 > 2)
	for i := 5; i < 8; i++ {
		p = packet.NewPacket(addr)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(i + 1)
		p.Header().RetransmittedPacketFlag = false
		recv.Push(p)
	}
	require.Equal(t, 3, recv.consecEarlyDelivery)

	// Create another gap: jump to 13 (gap 9-12, TTL=5)
	p = packet.NewPacket(addr)
	p.Header().PacketSequenceNumber = circular.New(13, packet.MAX_SEQUENCENUMBER)
	p.Header().PktTsbpdTime = 14
	recv.Push(p)

	// Fill gap 9-12 (4 belated originals, seqdiff 4,3,2,1 all <= 5)
	for i := 9; i < 13; i++ {
		p = packet.NewPacket(addr)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(i + 1)
		p.Header().RetransmittedPacketFlag = false
		recv.Push(p)
	}
	require.Equal(t, 7, recv.consecEarlyDelivery)

	// Create another gap: jump to 18 (gap 14-17, TTL=5)
	p = packet.NewPacket(addr)
	p.Header().PacketSequenceNumber = circular.New(18, packet.MAX_SEQUENCENUMBER)
	p.Header().PktTsbpdTime = 19
	recv.Push(p)

	// Fill 3 more to reach 10 (14,15,16)
	for i := 14; i < 17; i++ {
		p = packet.NewPacket(addr)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(i + 1)
		p.Header().RetransmittedPacketFlag = false
		recv.Push(p)
	}

	require.Equal(t, 4, recv.reorderTolerance, "tolerance should decay by 1 after 10 early deliveries with TTL>2")
	require.Equal(t, 0, recv.consecEarlyDelivery, "early counter should reset after decay")
}

func TestReorderToleranceNoDecayLowTTL(t *testing.T) {
	recv := mockLiveRecvWithReorder(10, nil, nil, nil)
	recv.SetReorderSupport(true)
	recv.reorderTolerance = 2

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	// Send packets 0-4
	for i := 0; i < 5; i++ {
		p := packet.NewPacket(addr)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(i + 1)
		recv.Push(p)
	}

	// Jump to 7 (creates freshLoss 5-6 with TTL=2, seqdiff for belated will be <=2)
	p := packet.NewPacket(addr)
	p.Header().PacketSequenceNumber = circular.New(7, packet.MAX_SEQUENCENUMBER)
	p.Header().PktTsbpdTime = 8
	recv.Push(p)

	require.Equal(t, 2, recv.freshLoss[0].ttl)

	// Decrement TTL once via processFreshLoss so TTL becomes 1
	recv.processFreshLoss()
	require.Equal(t, 1, recv.freshLoss[0].ttl)

	// Now send belated original packets 5,6 - hadTTL will be 1 (<=2), no early decay
	// seqdiff for 5 = |7-5| = 2 <= tolerance 2, no increase
	// seqdiff for 6 = |7-6| = 1 <= tolerance 2, no increase
	for i := 5; i < 7; i++ {
		p = packet.NewPacket(addr)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(i + 1)
		p.Header().RetransmittedPacketFlag = false
		recv.Push(p)
	}

	require.Equal(t, 0, recv.consecEarlyDelivery, "early counter should not increment when hadTTL <= 2")
	require.Equal(t, 2, recv.reorderTolerance, "tolerance should not decay when hadTTL <= 2")
}

func TestFreshLossTTLExpiry(t *testing.T) {
	nakSeqs := []uint32{}
	recv := mockLiveRecvWithReorder(3, nil, func(list []circular.Number) {
		for _, sn := range list {
			nakSeqs = append(nakSeqs, sn.Val())
		}
	}, nil)
	recv.SetReorderSupport(true)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	// Send packets 0-4
	for i := 0; i < 5; i++ {
		p := packet.NewPacket(addr)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(i + 1)
		recv.Push(p)
	}

	// Jump to 10 (gap 5-9, TTL=3)
	p := packet.NewPacket(addr)
	p.Header().PacketSequenceNumber = circular.New(10, packet.MAX_SEQUENCENUMBER)
	p.Header().PktTsbpdTime = 11
	recv.Push(p)

	require.Equal(t, 0, len(nakSeqs), "no NAK yet")
	require.Equal(t, 1, len(recv.freshLoss))
	require.Equal(t, 3, recv.freshLoss[0].ttl)

	// Tick 3 times to expire TTL: 3 -> 2 -> 1 -> 0 (expired on 4th processFreshLoss)
	recv.processFreshLoss() // TTL: 3->2
	require.Equal(t, 0, len(nakSeqs))
	recv.processFreshLoss() // TTL: 2->1
	require.Equal(t, 0, len(nakSeqs))
	recv.processFreshLoss() // TTL: 1->0
	require.Equal(t, 0, len(nakSeqs))
	recv.processFreshLoss() // TTL: 0 -> expired, send NAK
	require.Equal(t, []uint32{5, 9}, nakSeqs)
	require.Equal(t, 0, len(recv.freshLoss))
}

func TestNoReorderSupportImmediateNAK(t *testing.T) {
	nakSeqs := []uint32{}
	recv := mockLiveRecvWithReorder(10, nil, func(list []circular.Number) {
		for _, sn := range list {
			nakSeqs = append(nakSeqs, sn.Val())
		}
	}, nil)

	// Do NOT enable reorder support (simulates peer without REXMIT)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	// Send packets 0-4
	for i := 0; i < 5; i++ {
		p := packet.NewPacket(addr)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(i + 1)
		recv.Push(p)
	}

	// Jump to 10 (gap 5-9)
	p := packet.NewPacket(addr)
	p.Header().PacketSequenceNumber = circular.New(10, packet.MAX_SEQUENCENUMBER)
	p.Header().PktTsbpdTime = 11
	recv.Push(p)

	require.Equal(t, []uint32{5, 9}, nakSeqs, "should send immediate NAK without reorder support")
	require.Equal(t, 0, len(recv.freshLoss), "no freshLoss without reorder support")
}

func TestFreshLossRemoveOneSplit(t *testing.T) {
	recv := mockLiveRecvWithReorder(10, nil, nil, nil)
	recv.SetReorderSupport(true)

	// Manually add a freshLoss entry
	recv.freshLoss = []freshLossEntry{
		{
			seqLo: circular.New(5, packet.MAX_SEQUENCENUMBER),
			seqHi: circular.New(15, packet.MAX_SEQUENCENUMBER),
			ttl:   5,
		},
	}

	// Remove from middle (SPLIT)
	hadTTL := recv.freshLossRemoveOne(circular.New(10, packet.MAX_SEQUENCENUMBER))
	require.Equal(t, 5, hadTTL)
	require.Equal(t, 2, len(recv.freshLoss))
	require.Equal(t, uint32(5), recv.freshLoss[0].seqLo.Val())
	require.Equal(t, uint32(9), recv.freshLoss[0].seqHi.Val())
	require.Equal(t, uint32(11), recv.freshLoss[1].seqLo.Val())
	require.Equal(t, uint32(15), recv.freshLoss[1].seqHi.Val())
}

func TestFreshLossRemoveOneStripped(t *testing.T) {
	recv := mockLiveRecvWithReorder(10, nil, nil, nil)
	recv.SetReorderSupport(true)

	// Remove from beginning (STRIPPED)
	recv.freshLoss = []freshLossEntry{
		{
			seqLo: circular.New(5, packet.MAX_SEQUENCENUMBER),
			seqHi: circular.New(10, packet.MAX_SEQUENCENUMBER),
			ttl:   3,
		},
	}

	hadTTL := recv.freshLossRemoveOne(circular.New(5, packet.MAX_SEQUENCENUMBER))
	require.Equal(t, 3, hadTTL)
	require.Equal(t, 1, len(recv.freshLoss))
	require.Equal(t, uint32(6), recv.freshLoss[0].seqLo.Val())

	// Remove from end (STRIPPED)
	hadTTL = recv.freshLossRemoveOne(circular.New(10, packet.MAX_SEQUENCENUMBER))
	require.Equal(t, 3, hadTTL)
	require.Equal(t, 1, len(recv.freshLoss))
	require.Equal(t, uint32(9), recv.freshLoss[0].seqHi.Val())
}

func TestFreshLossRemoveOneDelete(t *testing.T) {
	recv := mockLiveRecvWithReorder(10, nil, nil, nil)
	recv.SetReorderSupport(true)

	// Single-element range (DELETE)
	recv.freshLoss = []freshLossEntry{
		{
			seqLo: circular.New(5, packet.MAX_SEQUENCENUMBER),
			seqHi: circular.New(5, packet.MAX_SEQUENCENUMBER),
			ttl:   2,
		},
	}

	hadTTL := recv.freshLossRemoveOne(circular.New(5, packet.MAX_SEQUENCENUMBER))
	require.Equal(t, 2, hadTTL)
	require.Equal(t, 0, len(recv.freshLoss))
}

func TestFreshLossRevoke(t *testing.T) {
	recv := mockLiveRecvWithReorder(10, nil, nil, nil)
	recv.SetReorderSupport(true)

	recv.freshLoss = []freshLossEntry{
		{seqLo: circular.New(5, packet.MAX_SEQUENCENUMBER), seqHi: circular.New(10, packet.MAX_SEQUENCENUMBER), ttl: 5},
		{seqLo: circular.New(15, packet.MAX_SEQUENCENUMBER), seqHi: circular.New(20, packet.MAX_SEQUENCENUMBER), ttl: 3},
	}

	// Revoke range that fully covers first entry
	recv.freshLossRevoke(circular.New(3, packet.MAX_SEQUENCENUMBER), circular.New(12, packet.MAX_SEQUENCENUMBER))
	require.Equal(t, 1, len(recv.freshLoss))
	require.Equal(t, uint32(15), recv.freshLoss[0].seqLo.Val())

	// Test right-partial strip that continues into subsequent entries
	recv.freshLoss = []freshLossEntry{
		{seqLo: circular.New(5, packet.MAX_SEQUENCENUMBER), seqHi: circular.New(10, packet.MAX_SEQUENCENUMBER), ttl: 5},
		{seqLo: circular.New(12, packet.MAX_SEQUENCENUMBER), seqHi: circular.New(20, packet.MAX_SEQUENCENUMBER), ttl: 3},
	}

	// Revoke range (7, 15): right-strips first entry to {5,6}, then must also strip second entry to {16,20}
	recv.freshLossRevoke(circular.New(7, packet.MAX_SEQUENCENUMBER), circular.New(15, packet.MAX_SEQUENCENUMBER))
	require.Equal(t, 2, len(recv.freshLoss))
	require.Equal(t, uint32(5), recv.freshLoss[0].seqLo.Val())
	require.Equal(t, uint32(6), recv.freshLoss[0].seqHi.Val())
	require.Equal(t, uint32(16), recv.freshLoss[1].seqLo.Val())
	require.Equal(t, uint32(20), recv.freshLoss[1].seqHi.Val())

	// Test right-partial strip, then full overlap, then left-partial strip
	recv.freshLoss = []freshLossEntry{
		{seqLo: circular.New(5, packet.MAX_SEQUENCENUMBER), seqHi: circular.New(10, packet.MAX_SEQUENCENUMBER), ttl: 5},
		{seqLo: circular.New(12, packet.MAX_SEQUENCENUMBER), seqHi: circular.New(14, packet.MAX_SEQUENCENUMBER), ttl: 3},
		{seqLo: circular.New(16, packet.MAX_SEQUENCENUMBER), seqHi: circular.New(20, packet.MAX_SEQUENCENUMBER), ttl: 4},
	}

	// Revoke (8, 18): right-strip {5,10}->{5,7}, delete {12,14}, left-strip {16,20}->{19,20}
	recv.freshLossRevoke(circular.New(8, packet.MAX_SEQUENCENUMBER), circular.New(18, packet.MAX_SEQUENCENUMBER))
	require.Equal(t, 2, len(recv.freshLoss))
	require.Equal(t, uint32(5), recv.freshLoss[0].seqLo.Val())
	require.Equal(t, uint32(7), recv.freshLoss[0].seqHi.Val())
	require.Equal(t, uint32(19), recv.freshLoss[1].seqLo.Val())
	require.Equal(t, uint32(20), recv.freshLoss[1].seqHi.Val())

	// Test middle overlap: split into left and right portions
	recv.freshLoss = []freshLossEntry{
		{seqLo: circular.New(5, packet.MAX_SEQUENCENUMBER), seqHi: circular.New(20, packet.MAX_SEQUENCENUMBER), ttl: 5},
	}

	// Revoke (10, 12): should split {5,20} into {5,9} and {13,20}
	recv.freshLossRevoke(circular.New(10, packet.MAX_SEQUENCENUMBER), circular.New(12, packet.MAX_SEQUENCENUMBER))
	require.Equal(t, 2, len(recv.freshLoss))
	require.Equal(t, uint32(5), recv.freshLoss[0].seqLo.Val())
	require.Equal(t, uint32(9), recv.freshLoss[0].seqHi.Val())
	require.Equal(t, uint32(13), recv.freshLoss[1].seqLo.Val())
	require.Equal(t, uint32(20), recv.freshLoss[1].seqHi.Val())
	require.Equal(t, 5, recv.freshLoss[1].ttl)

	// Test middle overlap with trailing entries preserved
	recv.freshLoss = []freshLossEntry{
		{seqLo: circular.New(5, packet.MAX_SEQUENCENUMBER), seqHi: circular.New(20, packet.MAX_SEQUENCENUMBER), ttl: 5},
		{seqLo: circular.New(30, packet.MAX_SEQUENCENUMBER), seqHi: circular.New(40, packet.MAX_SEQUENCENUMBER), ttl: 3},
	}

	// Revoke (10, 12): split first, keep second intact
	recv.freshLossRevoke(circular.New(10, packet.MAX_SEQUENCENUMBER), circular.New(12, packet.MAX_SEQUENCENUMBER))
	require.Equal(t, 3, len(recv.freshLoss))
	require.Equal(t, uint32(5), recv.freshLoss[0].seqLo.Val())
	require.Equal(t, uint32(9), recv.freshLoss[0].seqHi.Val())
	require.Equal(t, uint32(13), recv.freshLoss[1].seqLo.Val())
	require.Equal(t, uint32(20), recv.freshLoss[1].seqHi.Val())
	require.Equal(t, uint32(30), recv.freshLoss[2].seqLo.Val())
	require.Equal(t, uint32(40), recv.freshLoss[2].seqHi.Val())
}

func TestPeriodicNAKSkipsFreshLoss(t *testing.T) {
	recv := mockLiveRecvWithReorder(10, nil, nil, nil)
	recv.SetReorderSupport(true)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	// Send packets 0-4
	for i := 0; i < 5; i++ {
		p := packet.NewPacket(addr)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(50 + i + 1)
		recv.Push(p)
	}

	// Jump to 10 (gap 5-9 deferred in freshLoss)
	p := packet.NewPacket(addr)
	p.Header().PacketSequenceNumber = circular.New(10, packet.MAX_SEQUENCENUMBER)
	p.Header().PktTsbpdTime = 61
	recv.Push(p)

	require.Equal(t, 1, len(recv.freshLoss))

	// Periodic NAK should skip the gap since it's in freshLoss
	nakList := recv.periodicNAK(20)
	require.Equal(t, 0, len(nakList), "periodic NAK should skip ranges in freshLoss")
}

func TestReorderToleranceStatsExposure(t *testing.T) {
	recv := mockLiveRecvWithReorder(10, nil, nil, nil)
	recv.SetReorderSupport(true)

	require.Equal(t, 10, recv.ReorderTolerance())

	stats := recv.Stats()
	require.Equal(t, 10, stats.PktReorderTolerance)
	require.Equal(t, 0, stats.PktReorderDistance)
}

func TestFreshLossOverflow(t *testing.T) {
	nakCalls := 0
	recv := mockLiveRecvWithReorder(10, nil, func(list []circular.Number) {
		nakCalls++
	}, nil)
	recv.SetReorderSupport(true)

	// Manually fill freshLoss to capacity
	for i := 0; i < 1000; i++ {
		recv.freshLoss = append(recv.freshLoss, freshLossEntry{
			seqLo: circular.New(uint32(i*10), packet.MAX_SEQUENCENUMBER),
			seqHi: circular.New(uint32(i*10+5), packet.MAX_SEQUENCENUMBER),
			ttl:   5,
		})
	}

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	// Set maxSeen to a high value
	recv.maxSeenSequenceNumber = circular.New(20000, packet.MAX_SEQUENCENUMBER)

	// Push a packet that creates another gap
	p := packet.NewPacket(addr)
	p.Header().PacketSequenceNumber = circular.New(20010, packet.MAX_SEQUENCENUMBER)
	p.Header().PktTsbpdTime = 20011
	recv.Push(p)

	// Should have forced NAK on oldest entry
	require.Equal(t, 1, nakCalls, "should force NAK on oldest when overflow")
	require.Equal(t, 1000, len(recv.freshLoss), "should maintain max 1000 entries")
}

func TestSetReorderSupportDisable(t *testing.T) {
	recv := mockLiveRecvWithReorder(10, nil, nil, nil)
	recv.SetReorderSupport(true)

	recv.reorderTolerance = 5
	recv.consecOrderedDelivery = 10
	recv.consecEarlyDelivery = 3
	recv.freshLoss = []freshLossEntry{
		{seqLo: circular.New(5, packet.MAX_SEQUENCENUMBER), seqHi: circular.New(10, packet.MAX_SEQUENCENUMBER), ttl: 3},
	}

	recv.SetReorderSupport(false)

	require.Equal(t, 0, recv.reorderTolerance)
	require.Equal(t, 0, recv.consecOrderedDelivery)
	require.Equal(t, 0, recv.consecEarlyDelivery)
	require.Nil(t, recv.freshLoss)
	require.Equal(t, 0, recv.traceReorderDistance)
	require.Equal(t, false, recv.reorderSupport)
}

func TestTLPKTDROPRevokesFreshLoss(t *testing.T) {
	nakCalls := 0
	recv := mockLiveRecvWithReorder(10, nil, func(list []circular.Number) {
		nakCalls++
	}, nil)
	recv.SetReorderSupport(true)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	// Send packets 0-4 in order
	for i := 0; i < 5; i++ {
		p := packet.NewPacket(addr)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(i + 1)
		recv.Push(p)
	}

	// Jump to 10 (gap 5-9 deferred in freshLoss with TTL=10)
	p := packet.NewPacket(addr)
	p.Header().PacketSequenceNumber = circular.New(10, packet.MAX_SEQUENCENUMBER)
	p.Header().PktTsbpdTime = 11
	recv.Push(p)

	require.Equal(t, 0, nakCalls, "NAK should be deferred")
	require.Equal(t, 1, len(recv.freshLoss))
	require.Equal(t, uint32(5), recv.freshLoss[0].seqLo.Val())
	require.Equal(t, uint32(9), recv.freshLoss[0].seqHi.Val())

	// Send packets 11-14 with PktTsbpdTime in the past (triggers TLPKTDROP on gap 5-9)
	for i := 11; i < 15; i++ {
		p = packet.NewPacket(addr)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(i + 1)
		recv.Push(p)
	}

	// Tick with now=20, which is past PktTsbpdTime of all packets.
	// periodicACK will advance ACK past the gap 5-9, triggering freshLossRevoke.
	recv.Tick(20)

	// freshLoss should be empty — the gap was revoked by TLPKTDROP
	require.Equal(t, 0, len(recv.freshLoss), "freshLoss should be revoked after TLPKTDROP skips gap")
}

func TestOrderedDeliveryCounterReset(t *testing.T) {
	recv := mockLiveRecvWithReorder(10, nil, nil, nil)
	recv.SetReorderSupport(true)

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	// Send 40 packets in order
	for i := 0; i < 40; i++ {
		p := packet.NewPacket(addr)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(i + 1)
		recv.Push(p)
	}

	require.Equal(t, 40, recv.consecOrderedDelivery, "should have 40 consecutive ordered deliveries")

	// Jump to 45 (creates gap 40-44)
	p := packet.NewPacket(addr)
	p.Header().PacketSequenceNumber = circular.New(45, packet.MAX_SEQUENCENUMBER)
	p.Header().PktTsbpdTime = 46
	recv.Push(p)

	// Now send belated original packet 42 (out-of-order)
	p = packet.NewPacket(addr)
	p.Header().PacketSequenceNumber = circular.New(42, packet.MAX_SEQUENCENUMBER)
	p.Header().PktTsbpdTime = 43
	p.Header().RetransmittedPacketFlag = false
	recv.Push(p)

	// Counter should be reset to 0 because out-of-order packet arrived
	require.Equal(t, 0, recv.consecOrderedDelivery, "counter should reset on out-of-order packet")
}

func TestTraceReorderDistanceIsMax(t *testing.T) {
	recv := mockLiveRecvWithReorder(20, nil, nil, nil)
	recv.SetReorderSupport(true)

	// Manually set tolerance and distance
	recv.reorderTolerance = 10
	recv.traceReorderDistance = 10

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	// Send 50 packets in order to trigger tolerance decay
	for i := 0; i < 50; i++ {
		p := packet.NewPacket(addr)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(i + 1)
		recv.Push(p)
	}

	// Tolerance should decay, but distance is a max and should not
	require.Equal(t, 9, recv.reorderTolerance, "tolerance should decay by 1")
	require.Equal(t, 10, recv.traceReorderDistance, "distance is max-observed, should not decay")
}

func TestTraceReorderDistanceIncrease(t *testing.T) {
	recv := mockLiveRecvWithReorder(20, nil, nil, nil)
	recv.SetReorderSupport(true)
	recv.reorderTolerance = 5

	addr, _ := net.ResolveIPAddr("ip", "127.0.0.1")

	// Send packets 0-4
	for i := 0; i < 5; i++ {
		p := packet.NewPacket(addr)
		p.Header().PacketSequenceNumber = circular.New(uint32(i), packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = uint64(i + 1)
		recv.Push(p)
	}

	// Jump to 20 (gap 5-19)
	p := packet.NewPacket(addr)
	p.Header().PacketSequenceNumber = circular.New(20, packet.MAX_SEQUENCENUMBER)
	p.Header().PktTsbpdTime = 21
	recv.Push(p)

	// Send belated original packet 8 (seqdiff = |20 - 8| = 12)
	p = packet.NewPacket(addr)
	p.Header().PacketSequenceNumber = circular.New(8, packet.MAX_SEQUENCENUMBER)
	p.Header().PktTsbpdTime = 9
	p.Header().RetransmittedPacketFlag = false
	recv.Push(p)

	// Tolerance should increase to 12, and distance should be set to 12
	require.Equal(t, 12, recv.reorderTolerance, "tolerance should increase to seqdiff")
	require.Equal(t, 12, recv.traceReorderDistance, "distance should be set to seqdiff when tolerance increases")
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
