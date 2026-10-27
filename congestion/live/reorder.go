package live

import (
	"github.com/datarhei/gosrt/circular"
	"github.com/datarhei/gosrt/packet"
)

// The handling of reordered packets follows libsrt (SRTO_LOSSMAXTTL, CUDT::unlose and m_FreshLoss in core.cpp).
// A gap in the sequence numbers is not reported with an immediate NAK, but only after the reorder tolerance
// number of packets arrived and the gap is still not filled. The reorder tolerance starts with the max. value
// (LossMaxTTL). It is increased up to that value if an original packet arrives out of order, and it is decreased
// as long as packets arrive in order.
//
// Unlike libsrt, the ranges of missing packets are maintained further if the tolerance decreased to 0. libsrt
// leaves them untouched until the tolerance increases again, and then it may send a NAK for packets that already
// arrived or were dropped in the meantime.

// freshLoss is a range of missing packets that is reported with a NAK after ttl more packets arrived.
type freshLoss struct {
	from circular.Number
	to   circular.Number
	ttl  int
}

// registerLoss registers a range of missing packets. If there's no reorder tolerance, a NAK is sent immediately.
// The caller must hold the lock.
func (r *receiver) registerLoss(from, to circular.Number) {
	if r.reorderTolerance == 0 {
		r.sendNAK([]circular.Number{from, to})
		return
	}

	r.freshLoss = append(r.freshLoss, freshLoss{
		from: from,
		to:   to,
		ttl:  int(r.reorderTolerance),
	})
}

// inserted is called after a packet has been added to the buffer. The ranges of missing packets whose TTL
// expired are reported with a NAK and the TTL of all others is decreased. The caller must hold the lock.
func (r *receiver) inserted(inOrder bool) {
	if len(r.freshLoss) != 0 {
		list := []circular.Number{}

		i := 0
		for ; i < len(r.freshLoss) && r.freshLoss[i].ttl <= 0; i++ {
			list = append(list, r.freshLoss[i].from, r.freshLoss[i].to)
		}

		r.freshLoss = append(r.freshLoss[:0], r.freshLoss[i:]...)

		for i := range r.freshLoss {
			r.freshLoss[i].ttl--
		}

		if len(list) != 0 {
			r.sendNAK(list)
		}
	}

	// After 50 packets in a row that were sent in order, decrease the reorder tolerance.
	if inOrder {
		r.consecOrdered++
		if r.consecOrdered >= 50 {
			r.consecOrdered = 0
			r.decreaseReorderTolerance()
		}
	}
}

// unlose is called for a packet that arrived with a sequence number lower than the highest received sequence
// number, i.e. it filled a gap or it's a redundant copy. It is removed from the ranges of missing packets and,
// if it's an original packet, the reorder tolerance is adjusted. The caller must hold the lock.
func (r *receiver) unlose(pkt packet.Packet) {
	original := !pkt.Header().RetransmittedPacketFlag
	increasedTolerance := false

	if original {
		distance := uint64(r.maxSeenSequenceNumber.Distance(pkt.Header().PacketSequenceNumber))
		if distance > r.statistics.PktReorderDistance {
			r.statistics.PktReorderDistance = distance
		}

		if distance > uint64(r.reorderTolerance) {
			r.reorderTolerance = uint32(min(distance, uint64(r.maxReorderTolerance)))
			increasedTolerance = true
		}
	}

	hadTTL := r.removeFreshLoss(pkt.Header().PacketSequenceNumber)

	if r.reorderTolerance == 0 || !original {
		return
	}

	r.consecOrdered = 0

	if increasedTolerance {
		r.consecEarly = 0
	} else if hadTTL > 2 {
		// The packet arrived quite early. After 10 times in a row, decrease the reorder tolerance.
		r.consecEarly++
		if r.consecEarly >= 10 {
			r.consecEarly = 0
			r.decreaseReorderTolerance()
		}
	}
}

// decreaseReorderTolerance decreases the reorder tolerance and the reorder distance by one. The caller must hold the lock.
func (r *receiver) decreaseReorderTolerance() {
	if r.reorderTolerance == 0 {
		return
	}

	r.reorderTolerance--

	if r.statistics.PktReorderDistance > 0 {
		r.statistics.PktReorderDistance--
	}
}

// removeFreshLoss removes a sequence number from the ranges of missing packets. It returns the TTL
// the range had, or 0 if the sequence number is not in any range. The caller must hold the lock.
func (r *receiver) removeFreshLoss(seq circular.Number) int {
	for i := range r.freshLoss {
		l := &r.freshLoss[i]

		if seq.Lt(l.from) || seq.Gt(l.to) {
			continue
		}

		ttl := l.ttl

		switch {
		case l.from.Equals(l.to):
			r.freshLoss = append(r.freshLoss[:i], r.freshLoss[i+1:]...)
		case seq.Equals(l.from):
			l.from = seq.Inc()
		case seq.Equals(l.to):
			l.to = seq.Dec()
		default:
			// Split the range
			upper := freshLoss{
				from: seq.Inc(),
				to:   l.to,
				ttl:  l.ttl,
			}
			l.to = seq.Dec()

			r.freshLoss = append(r.freshLoss[:i+1], append([]freshLoss{upper}, r.freshLoss[i+1:]...)...)
		}

		return ttl
	}

	return 0
}

// revokeFreshLoss removes all sequence numbers up to and including seq from the ranges of missing packets,
// because they will not be delivered anymore. The caller must hold the lock.
func (r *receiver) revokeFreshLoss(seq circular.Number) {
	kept := r.freshLoss[:0]
	for _, l := range r.freshLoss {
		if l.to.Lte(seq) {
			continue
		}

		if l.from.Lte(seq) {
			l.from = seq.Inc()
		}

		kept = append(kept, l)
	}

	r.freshLoss = kept
}
