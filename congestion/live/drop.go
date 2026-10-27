package live

import (
	"github.com/datarhei/gosrt/circular"
	"github.com/datarhei/gosrt/packet"
)

// Bound metadata even if a peer sends many disjoint requests behind a gap.
// At the limit, a new disjoint request is ignored rather than acknowledging
// packets outside the ranges already recorded. Overlaps can still merge.
const maxDropRanges = 1024

type dropRange struct {
	first circular.Number
	last  circular.Number
}

func sequenceDistance(first, last circular.Number) uint32 {
	return (last.Val() - first.Val()) & packet.MAX_SEQUENCENUMBER
}

// Drop records sender-side drops. All ranges are sorted relative to the ACK
// point and coalesced. Received data is preserved, as in libsrt's live mode.
func (r *receiver) Drop(first, last circular.Number) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if sequenceDistance(first, last) >= packet.MAX_SEQUENCENUMBER/2 {
		return
	}
	end := sequenceDistance(r.lastACKSequenceNumber, last)
	if end == 0 || end >= 1<<30 || end > r.maxDropDistance {
		return
	}
	start := sequenceDistance(r.lastACKSequenceNumber, first)
	if start == 0 || start >= 1<<30 {
		first = r.lastACKSequenceNumber.Inc()
		start = 1
	}
	if start > end {
		return
	}

	i := 0
	for i < len(r.dropRanges) && sequenceDistance(r.lastACKSequenceNumber, r.dropRanges[i].last)+1 < start {
		i++
	}
	j := i
	for j < len(r.dropRanges) && sequenceDistance(r.lastACKSequenceNumber, r.dropRanges[j].first) <= end+1 {
		if r.dropRanges[j].first.Lt(first) {
			first = r.dropRanges[j].first
		}
		if r.dropRanges[j].last.Gt(last) {
			last = r.dropRanges[j].last
			end = sequenceDistance(r.lastACKSequenceNumber, last)
		}
		j++
	}
	if i == j {
		if len(r.dropRanges) == maxDropRanges {
			return
		}
		r.dropRanges = append(r.dropRanges, dropRange{})
		copy(r.dropRanges[i+1:], r.dropRanges[i:])
	} else {
		copy(r.dropRanges[i+1:], r.dropRanges[j:])
		r.dropRanges = r.dropRanges[:len(r.dropRanges)-(j-i)+1]
	}
	r.dropRanges[i] = dropRange{first: first, last: last}
	// A control packet can overtake data. Retain future ranges within the
	// window, but only extend maxSeen across drops adjacent to known data.
	r.maxSeenSequenceNumber = r.skipDropped(r.maxSeenSequenceNumber)
}

// skipDropped advances only across a drop adjacent to the current ACK point.
// Callers hold r.lock; the same applies to appendMissing and pruneDrops.
func (r *receiver) skipDropped(ack circular.Number) circular.Number {
	for _, d := range r.dropRanges {
		if d.first.Gt(ack.Inc()) {
			break
		}
		if d.last.Gt(ack) {
			ack = d.last
		}
	}
	return ack
}

func (r *receiver) appendMissing(missing []circular.Number, first, last circular.Number) []circular.Number {
	for _, d := range r.dropRanges {
		if d.last.Lt(first) {
			continue
		}
		if d.first.Gt(last) {
			break
		}
		if d.first.Gt(first) {
			missing = append(missing, first, d.first.Dec())
		}
		first = d.last.Inc()
		if first.Gt(last) {
			return missing
		}
	}
	return append(missing, first, last)
}

func (r *receiver) pruneDrops() {
	i := 0
	for i < len(r.dropRanges) && r.dropRanges[i].last.Lte(r.lastACKSequenceNumber) {
		i++
	}
	copy(r.dropRanges, r.dropRanges[i:])
	r.dropRanges = r.dropRanges[:len(r.dropRanges)-i]
	if len(r.dropRanges) != 0 && r.dropRanges[0].first.Lte(r.lastACKSequenceNumber) {
		r.dropRanges[0].first = r.lastACKSequenceNumber.Inc()
	}
}
