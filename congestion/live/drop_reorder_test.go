package live

import (
	"strconv"
	"testing"

	"github.com/datarhei/gosrt/circular"
	"github.com/stretchr/testify/require"
)

func reorderDropReceiver(initial, tolerance uint32) *receiver {
	r := dropReceiver(initial)
	r.maxReorderTolerance = tolerance
	r.reorderTolerance = tolerance
	return r
}

func TestDropRemovesFreshLossBeforeTTLExpires(t *testing.T) {
	for _, base := range []uint32{100, 0x7ffffffb} {
		t.Run(strconv.FormatUint(uint64(base), 10), func(t *testing.T) {
			r := reorderDropReceiver(base, 3)
			seq := func(n uint32) circular.Number { return dropSeq(base).Add(n) }
			var naks [][]uint32
			r.sendNAK = func(numbers []circular.Number) { naks = append(naks, nakValues(numbers)) }
			for _, n := range []uint32{0, 10, 14} {
				r.Push(dropPacket(seq(n).Val()))
			}
			require.Equal(t, []freshLoss{{seq(1), seq(9), 1}, {seq(11), seq(13), 2}}, r.freshLoss)
			before := r.Stats()
			r.Drop(seq(4), seq(6))
			require.Equal(t, []freshLoss{{seq(1), seq(3), 1}, {seq(7), seq(9), 1}, {seq(11), seq(13), 2}}, r.freshLoss)
			require.Equal(t, before, r.Stats())
			r.Push(dropPacket(seq(15).Val()))
			require.Empty(t, naks)
			r.Push(dropPacket(seq(16).Val()))
			require.Equal(t, [][]uint32{{seq(1).Val(), seq(3).Val(), seq(7).Val(), seq(9).Val()}}, naks)
			r.Push(dropPacket(seq(17).Val()))
			require.Equal(t, []uint32{seq(11).Val(), seq(13).Val()}, naks[1])
			require.Empty(t, r.freshLoss)
		})
	}
}

func TestDropOvertakesFreshLossRegistration(t *testing.T) {
	for _, base := range []uint32{100, 0x7ffffffc} {
		for _, tolerance := range []uint32{0, 3} {
			t.Run(strconv.FormatUint(uint64(base), 10)+"/"+strconv.FormatUint(uint64(tolerance), 10), func(t *testing.T) {
				r := reorderDropReceiver(base, tolerance)
				seq := func(n uint32) circular.Number { return dropSeq(base).Add(n) }
				var naks [][]uint32
				r.sendNAK = func(numbers []circular.Number) { naks = append(naks, nakValues(numbers)) }
				r.Drop(seq(3), seq(5))
				r.Push(dropPacket(seq(0).Val()))
				r.Push(dropPacket(seq(8).Val()))
				want := []uint32{seq(1).Val(), seq(2).Val(), seq(6).Val(), seq(7).Val()}
				if tolerance != 0 {
					require.Empty(t, naks)
					require.Equal(t, []freshLoss{{seq(1), seq(2), 2}, {seq(6), seq(7), 2}}, r.freshLoss)
					for n := uint32(9); n <= 11; n++ {
						r.Push(dropPacket(seq(n).Val()))
					}
				}
				require.Equal(t, [][]uint32{want}, naks)
			})
		}
	}
}

func TestDropRemovesExpiredFreshLossAtZeroTolerance(t *testing.T) {
	for _, ttl := range []int{-1, 0} {
		r := reorderDropReceiver(100, 0)
		r.Push(dropPacket(100))
		r.Push(dropPacket(105))
		r.freshLoss = []freshLoss{{dropSeq(101), dropSeq(104), ttl}}
		r.Drop(dropSeq(102), dropSeq(103))
		var naks []uint32
		r.sendNAK = func(numbers []circular.Number) { naks = append(naks, nakValues(numbers)...) }
		r.Push(dropPacket(106))
		require.Equal(t, []uint32{101, 101, 104, 104}, naks)
	}
}

func TestRejectedDropPreservesFreshLoss(t *testing.T) {
	r := reorderDropReceiver(0, 5)
	r.Push(dropPacket(10000))
	for n := uint32(0); n < maxDropRanges; n++ {
		r.Drop(dropSeq(2*n+2), dropSeq(2*n+2))
	}
	before := append([]freshLoss(nil), r.freshLoss...)
	r.Drop(dropSeq(9000), dropSeq(9001))
	require.Equal(t, before, r.freshLoss)
	r.Drop(dropSeq(2), dropSeq(2048))
	require.Equal(t, []freshLoss{{dropSeq(0), dropSeq(1), 4}, {dropSeq(2049), dropSeq(9999), 4}}, r.freshLoss)
}

func TestDropTailInsertionPreservesReorderAccounting(t *testing.T) {
	r := reorderDropReceiver(100, 8)
	r.Push(dropPacket(100))
	r.Push(dropPacket(105))
	r.Drop(dropSeq(103), dropSeq(104))
	r.Drop(dropSeq(106), dropSeq(108))
	require.Equal(t, []freshLoss{{dropSeq(101), dropSeq(102), 7}}, r.freshLoss)

	// A packet behind a dropped tail has no later packet to insert before.
	r.Push(dropPacket(107))
	require.Equal(t, []freshLoss{{dropSeq(101), dropSeq(102), 6}}, r.freshLoss)
	require.Equal(t, uint64(1), r.Stats().PktReorderDistance)
	require.Zero(t, r.consecOrdered)
	before := append([]freshLoss(nil), r.freshLoss...)
	r.Push(dropPacket(107))
	require.Equal(t, before, r.freshLoss, "duplicate packets must not age the TTL")
	require.Equal(t, 3, r.packetList.Len())

	p := dropPacket(108)
	p.Header().RetransmittedPacketFlag = true
	r.Push(p)
	require.Equal(t, []freshLoss{{dropSeq(101), dropSeq(102), 5}}, r.freshLoss)
	require.Equal(t, 1, r.consecOrdered)
	require.Equal(t, 4, r.packetList.Len())
	require.Equal(t, uint64(4), r.Stats().PktBuf)
	r.Flush()
	require.Empty(t, r.freshLoss)
	require.Empty(t, r.dropRanges)
	require.Zero(t, r.packetList.Len())
}
