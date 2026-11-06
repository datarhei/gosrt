package live

import (
	"sync"
	"testing"

	"github.com/datarhei/gosrt/circular"
	"github.com/datarhei/gosrt/packet"
	"github.com/stretchr/testify/require"
)

func dropSeq(n uint32) circular.Number { return circular.New(n, packet.MAX_SEQUENCENUMBER) }

func dropPacket(n uint32) packet.Packet {
	p := packet.NewPacket(nil)
	p.Header().PacketSequenceNumber = dropSeq(n)
	p.Header().PktTsbpdTime = 1_000_000_000_000
	p.SetData([]byte{byte(n)})
	return p
}

func dropReceiver(initial uint32) *receiver {
	return NewReceiver(ReceiveConfig{
		InitialSequenceNumber: dropSeq(initial),
		PeriodicACKInterval:   10,
		PeriodicNAKInterval:   20,
	}).(*receiver)
}

func nakValues(numbers []circular.Number) []uint32 {
	values := make([]uint32, len(numbers))
	for i, n := range numbers {
		values[i] = n.Val()
	}
	return values
}

func TestDropPreservesOtherGapsAndBufferedData(t *testing.T) {
	for _, base := range []uint32{100, packet.MAX_SEQUENCENUMBER - 7} {
		r := dropReceiver(base)
		seq := func(offset uint32) circular.Number { return dropSeq(base).Add(offset) }
		var delivered []uint32
		r.deliver = func(p packet.Packet) { delivered = append(delivered, p.Header().PacketSequenceNumber.Val()) }
		for _, i := range []uint32{0, 3, 6, 9} {
			r.Push(dropPacket(seq(i).Val()))
		}
		r.Drop(seq(4), seq(7)) // Includes received packet 6, but not gap 1..2 or 8.
		r.Drop(seq(5), seq(7)) // Duplicate/overlap is idempotent.
		r.Tick(20)
		require.Equal(t, seq(0), r.lastACKSequenceNumber)
		require.Equal(t, []uint32{seq(1).Val(), seq(2).Val(), seq(8).Val(), seq(8).Val()}, nakValues(r.periodicNAK(40)))
		require.Equal(t, uint64(4), r.Stats().PktBuf)
		require.Equal(t, uint64(4), r.Stats().ByteBuf)
		r.Push(dropPacket(seq(2).Val()))
		r.Push(dropPacket(seq(1).Val()))
		r.Tick(60)
		require.Equal(t, seq(7), r.lastACKSequenceNumber)
		require.Empty(t, r.dropRanges)
		require.Equal(t, []uint32{seq(8).Val(), seq(8).Val()}, nakValues(r.periodicNAK(80)))
		r.Push(dropPacket(seq(8).Val()))
		r.Tick(100)
		require.Equal(t, seq(9), r.lastACKSequenceNumber)
		require.Empty(t, delivered)
		r.Tick(1_000_000_000_000)
		want := []uint32{seq(0).Val(), seq(1).Val(), seq(2).Val(), seq(3).Val(), seq(6).Val(), seq(8).Val(), seq(9).Val()}
		require.Equal(t, want, delivered)
		require.Zero(t, r.Stats().PktBuf)
		require.Zero(t, r.Stats().ByteBuf)
		require.Equal(t, uint64(3), r.Stats().PktLost)
	}
}

func TestDropOvertakesDataAndSuppressesImmediateNAK(t *testing.T) {
	for _, base := range []uint32{100, packet.MAX_SEQUENCENUMBER - 2} {
		r := dropReceiver(base)
		seq := func(i uint32) circular.Number { return dropSeq(base).Add(i) }
		var naks []uint32
		r.sendNAK = func(numbers []circular.Number) { naks = append(naks, nakValues(numbers)...) }
		r.Drop(seq(3), seq(4))
		require.Equal(t, seq(0).Dec(), r.maxSeenSequenceNumber)
		r.Push(dropPacket(seq(0).Val()))
		r.Push(dropPacket(seq(5).Val()))
		require.Equal(t, []uint32{seq(1).Val(), seq(2).Val()}, naks)
		r.Tick(20)
		require.Equal(t, seq(0), r.lastACKSequenceNumber)
		r.Push(dropPacket(seq(1).Val()))
		r.Push(dropPacket(seq(2).Val()))
		r.Tick(40)
		require.Equal(t, seq(5), r.lastACKSequenceNumber)
		require.Empty(t, r.periodicNAK(60))
	}
}

func TestDropExtendsUnseenTailAndKeepsArrivalsUntilACK(t *testing.T) {
	for _, initial := range []uint32{100, packet.MAX_SEQUENCENUMBER - 1} {
		r := dropReceiver(initial)
		first := dropSeq(initial)
		r.Drop(first, first.Add(3))
		require.Equal(t, first.Add(3), r.maxSeenSequenceNumber)
		r.Push(dropPacket(first.Inc().Val())) // No later buffered packet exists yet.
		r.Push(dropPacket(first.Add(3).Val()))
		require.Equal(t, 2, r.packetList.Len())
		r.Tick(20)
		require.Equal(t, first.Add(3), r.lastACKSequenceNumber)
		require.Empty(t, r.dropRanges)
		r.Push(dropPacket(first.Add(3).Val())) // Already ACKed endpoint must not reenter the buffer.
		require.Equal(t, 2, r.packetList.Len())
		r.Push(dropPacket(first.Add(4).Val()))
		require.Equal(t, first.Add(4), r.maxSeenSequenceNumber)
		require.Empty(t, r.periodicNAK(40))
	}
}

func TestDropFutureRangeBecomesAdjacent(t *testing.T) {
	r := dropReceiver(100)
	r.Drop(dropSeq(103), dropSeq(105))
	for _, seq := range []uint32{100, 101, 102} {
		r.Push(dropPacket(seq))
	}
	require.Equal(t, dropSeq(105), r.maxSeenSequenceNumber)
	r.Tick(20)
	require.Equal(t, dropSeq(105), r.lastACKSequenceNumber)
	var naks []uint32
	r.sendNAK = func(numbers []circular.Number) { naks = append(naks, nakValues(numbers)...) }
	r.Push(dropPacket(106))
	require.Empty(t, naks)
}

func TestDropFutureRangeFollowsOutOfOrderData(t *testing.T) {
	r := dropReceiver(100)
	r.Drop(dropSeq(104), dropSeq(106))
	r.Push(dropPacket(103)) // The packet before the drop also follows a gap.
	for _, seq := range []uint32{100, 101, 102} {
		r.Push(dropPacket(seq))
	}
	r.Tick(20)
	require.Equal(t, dropSeq(106), r.lastACKSequenceNumber)
	require.Empty(t, r.dropRanges)
	var naks []uint32
	r.sendNAK = func(numbers []circular.Number) { naks = append(naks, nakValues(numbers)...) }
	r.Push(dropPacket(107))
	require.Empty(t, naks)
	require.Equal(t, dropSeq(107), r.maxSeenSequenceNumber)
}

func TestDropValidationAndStaleRequests(t *testing.T) {
	r := dropReceiver(100)
	r.maxDropDistance = 32
	for _, bounds := range [][2]uint32{{90, 99}, {100, 99}, {100, 132}, {100, 1 << 30}, {100, 100 + packet.MAX_SEQUENCENUMBER/2}} {
		r.Drop(dropSeq(bounds[0]), dropSeq(bounds[1]))
		require.Empty(t, r.dropRanges)
		require.Equal(t, dropSeq(99), r.maxSeenSequenceNumber)
	}
	r.Drop(dropSeq(90), dropSeq(102)) // Clip a stale prefix to the ACK point.
	r.Tick(20)
	require.Equal(t, dropSeq(102), r.lastACKSequenceNumber)
	r.Drop(dropSeq(90), dropSeq(102))
	r.Tick(40)
	require.Equal(t, dropSeq(102), r.lastACKSequenceNumber)
	require.Empty(t, r.dropRanges)
	for _, window := range []uint32{0, packet.MAX_SEQUENCENUMBER / 2, 1 << 30, ^uint32(0)} {
		r := NewReceiver(ReceiveConfig{MaxDropDistance: window}).(*receiver)
		require.Equal(t, uint32(25600), r.maxDropDistance)
	}
}

func TestDropMetadataBoundMergeAndFlush(t *testing.T) {
	r := dropReceiver(0)
	r.Push(dropPacket(10000))
	for i := uint32(0); i < maxDropRanges; i++ {
		r.Drop(dropSeq(2*i+2), dropSeq(2*i+2))
	}
	require.Len(t, r.dropRanges, maxDropRanges)
	r.Drop(dropSeq(9000), dropSeq(9001))
	require.Len(t, r.dropRanges, maxDropRanges)
	require.Equal(t, uint32(2048), r.dropRanges[len(r.dropRanges)-1].last.Val())
	r.Drop(dropSeq(2), dropSeq(2048)) // Merging is allowed even at the bound.
	require.Len(t, r.dropRanges, 1)
	r.Drop(dropSeq(0), dropSeq(1))
	r.Tick(20)
	require.Equal(t, dropSeq(2048), r.lastACKSequenceNumber)
	require.Empty(t, r.dropRanges)
	r.Drop(dropSeq(2050), dropSeq(2051))
	r.Flush()
	require.Empty(t, r.dropRanges)
	require.Empty(t, r.packetList.Len())
}

func TestDropConcurrentReceiverOperations(t *testing.T) {
	r := reorderDropReceiver(0, 8)
	var wg sync.WaitGroup
	for worker := range 4 {
		wg.Go(func() {
			for i := uint32(0); i < 300; i++ {
				switch worker {
				case 0:
					r.Push(dropPacket(i))
				case 1:
					r.Drop(dropSeq(i), dropSeq(i+1))
				case 2:
					r.Tick(uint64(i+1) * 20)
				case 3:
					r.Stats()
					r.SetNAKInterval(20)
				}
			}
		})
	}
	wg.Wait()
	require.LessOrEqual(t, len(r.dropRanges), maxDropRanges)
}

func FuzzDropReceiverModel(f *testing.F) {
	f.Add(uint32(100), []byte{0, 0, 0, 0, 7, 0, 1, 2, 5, 0, 1, 0})
	f.Add(packet.MAX_SEQUENCENUMBER-10, []byte{1, 5, 7, 0, 0, 0, 0, 8, 0, 1, 1, 4})
	f.Fuzz(func(t *testing.T, initial uint32, operations []byte) {
		checkDropReceiverModel(t, initial, operations, 0)
	})
}

func FuzzDropReorderReceiverModel(f *testing.F) {
	f.Add(uint32(100), uint8(3), []byte{128, 0, 0, 128, 10, 0, 129, 1, 9, 128, 11, 0, 128, 12, 0, 128, 13, 0})
	f.Add(uint32(0x7ffffffb), uint8(4), []byte{129, 3, 5, 128, 0, 0, 128, 8, 0, 0, 9, 0, 0, 10, 0})
	f.Fuzz(func(t *testing.T, initial uint32, tolerance uint8, operations []byte) {
		checkDropReceiverModel(t, initial, operations, uint32(tolerance%8)+1)
	})
}

func checkDropReceiverModel(t *testing.T, initial uint32, operations []byte, tolerance uint32) {
	if len(operations) > 600 {
		operations = operations[:600]
	}
	initial &= packet.MAX_SEQUENCENUMBER
	r := reorderDropReceiver(initial, tolerance)
	seq := func(i int) circular.Number { return dropSeq(initial).Add(uint32(i)) }
	var received, dropped [64]bool
	ack := -1
	r.sendNAK = func(numbers []circular.Number) {
		for j := 0; j+1 < len(numbers); j += 2 {
			for n := numbers[j]; ; n = n.Inc() {
				index := int((n.Val() - initial) & packet.MAX_SEQUENCENUMBER)
				require.Greater(t, index, ack)
				require.Less(t, index, len(received))
				require.False(t, received[index], "NAK for received packet")
				require.False(t, dropped[index], "NAK for dropped packet")
				if n.Equals(numbers[j+1]) {
					break
				}
			}
		}
	}
	var delivered []uint32
	r.deliver = func(p packet.Packet) { delivered = append(delivered, p.Header().PacketSequenceNumber.Val()) }
	for i := 0; i+2 < len(operations); i += 3 {
		a, b := int(operations[i+1]%64), int(operations[i+2]%64)
		if operations[i]%2 == 0 {
			r.Push(dropPacket(seq(a).Val()))
			if a > ack {
				received[a] = true
			}
		} else {
			if a > b {
				a, b = b, a
			}
			r.Drop(seq(a), seq(b))
			for k := a; k <= b; k++ {
				dropped[k] = true
			}
		}
		now := uint64(i+1) * 20
		if tolerance == 0 || operations[i]&0x80 == 0 {
			for ack+1 < 64 && (received[ack+1] || dropped[ack+1]) {
				ack++
			}
			r.Tick(now)
		}
		wantACK := dropSeq(initial).Dec()
		if ack >= 0 {
			wantACK = seq(ack)
		}
		require.Equal(t, wantACK, r.lastACKSequenceNumber)
		// Expand the reported NAK intervals and compare to a per-packet oracle.
		got := make(map[uint32]bool)
		for naks, j := r.periodicNAK(now+20), 0; j+1 < len(naks); j += 2 {
			for n := naks[j]; ; n = n.Inc() {
				got[n.Val()] = true
				if n.Equals(naks[j+1]) {
					break
				}
				require.LessOrEqual(t, len(got), 64)
			}
		}
		lastReceived := -1
		for k, yes := range received {
			if yes {
				lastReceived = k
			}
		}
		want := make(map[uint32]bool)
		for k := ack + 1; k < lastReceived; k++ {
			if !received[k] && !dropped[k] {
				want[seq(k).Val()] = true
			}
		}
		require.Equal(t, want, got)
	}
	r.Tick(1_000_000_000_000)
	var want []uint32
	for i, yes := range received {
		if yes {
			want = append(want, seq(i).Val())
		}
	}
	require.Equal(t, want, delivered)
	require.Zero(t, r.Stats().PktBuf)
	require.Zero(t, r.Stats().ByteBuf)
}
