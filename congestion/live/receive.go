package live

import (
	"container/list"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/datarhei/gosrt/circular"
	"github.com/datarhei/gosrt/congestion"
	"github.com/datarhei/gosrt/packet"
)

// freshLossEntry represents a loss range whose NAK report is deferred by a TTL.
type freshLossEntry struct {
	seqLo circular.Number
	seqHi circular.Number
	ttl   int
}

// ReceiveConfig is the configuration for the liveRecv congestion control
type ReceiveConfig struct {
	InitialSequenceNumber circular.Number
	PeriodicACKInterval   uint64 // microseconds
	PeriodicNAKInterval   uint64 // microseconds
	MaxReorderTolerance   int
	OnSendACK             func(seq circular.Number, light bool)
	OnSendNAK             func(list []circular.Number)
	OnDeliver             func(p packet.Packet)
}

// receiver implements the Receiver interface
type receiver struct {
	maxSeenSequenceNumber       circular.Number
	lastACKSequenceNumber       circular.Number
	lastDeliveredSequenceNumber circular.Number
	packetList                  *list.List
	lock                        sync.RWMutex

	nPackets uint

	periodicACKInterval uint64 // config
	periodicNAKInterval uint64 // config

	lastPeriodicACK uint64
	lastPeriodicNAK uint64

	avgPayloadSize  float64 // bytes
	avgLinkCapacity float64 // packets per second

	probeTime    time.Time
	probeNextSeq circular.Number

	statistics congestion.ReceiveStats

	// Adaptive reorder tolerance state (mirrors libsrt m_iReorderTolerance)
	maxReorderTolerance   int
	reorderTolerance      int
	reorderSupport        bool
	consecOrderedDelivery int
	consecEarlyDelivery   int
	freshLoss            []freshLossEntry
	traceReorderDistance int

	rate struct {
		last   uint64 // microseconds
		period uint64

		packets      uint64
		bytes        uint64
		bytesRetrans uint64

		packetsPerSecond float64
		bytesPerSecond   float64

		pktLossRate float64
	}

	sendACK func(seq circular.Number, light bool)
	sendNAK func(list []circular.Number)
	deliver func(p packet.Packet)
}

// NewReceiver takes a ReceiveConfig and returns a new Receiver
func NewReceiver(config ReceiveConfig) congestion.Receiver {
	r := &receiver{
		maxSeenSequenceNumber:       config.InitialSequenceNumber.Dec(),
		lastACKSequenceNumber:       config.InitialSequenceNumber.Dec(),
		lastDeliveredSequenceNumber: config.InitialSequenceNumber.Dec(),
		packetList:                  list.New(),

		periodicACKInterval: config.PeriodicACKInterval,
		periodicNAKInterval: config.PeriodicNAKInterval,

		avgPayloadSize: 1456, //  5.1.2. SRT's Default LiveCC Algorithm

		maxReorderTolerance: config.MaxReorderTolerance,
		reorderTolerance:    config.MaxReorderTolerance,
		reorderSupport:      false,

		sendACK: config.OnSendACK,
		sendNAK: config.OnSendNAK,
		deliver: config.OnDeliver,
	}

	if r.sendACK == nil {
		r.sendACK = func(seq circular.Number, light bool) {}
	}

	if r.sendNAK == nil {
		r.sendNAK = func(list []circular.Number) {}
	}

	if r.deliver == nil {
		r.deliver = func(p packet.Packet) {}
	}

	r.rate.last = 0
	r.rate.period = uint64(time.Second.Microseconds())

	return r
}

func (r *receiver) Stats() congestion.ReceiveStats {
	r.lock.Lock()
	defer r.lock.Unlock()

	r.statistics.BytePayload = uint64(r.avgPayloadSize)
	r.statistics.MbpsEstimatedRecvBandwidth = r.rate.bytesPerSecond * 8 / 1024 / 1024
	r.statistics.MbpsEstimatedLinkCapacity = r.avgLinkCapacity * packet.MAX_PAYLOAD_SIZE * 8 / 1024 / 1024
	r.statistics.PktLossRate = r.rate.pktLossRate
	r.statistics.PktReorderTolerance = r.reorderTolerance
	r.statistics.PktReorderDistance = r.traceReorderDistance

	return r.statistics
}

func (r *receiver) PacketRate() (pps, bps, capacity float64) {
	r.lock.Lock()
	defer r.lock.Unlock()

	pps = r.rate.packetsPerSecond
	bps = r.rate.bytesPerSecond
	capacity = r.avgLinkCapacity

	return
}

func (r *receiver) Flush() {
	r.lock.Lock()
	defer r.lock.Unlock()

	r.packetList = r.packetList.Init()
}

func (r *receiver) Push(pkt packet.Packet) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if pkt == nil {
		return
	}

	// This is not really well (not at all) described in the specs. See core.cpp and window.h
	// and search for PUMASK_SEQNO_PROBE (0xF). Every 16th and 17th packet are
	// sent in pairs. This is used as a probe for the theoretical capacity of the link.
	if !pkt.Header().RetransmittedPacketFlag {
		probe := pkt.Header().PacketSequenceNumber.Val() & 0xF
		if probe == 0 {
			r.probeTime = time.Now()
			r.probeNextSeq = pkt.Header().PacketSequenceNumber.Inc()
		} else if probe == 1 && pkt.Header().PacketSequenceNumber.Equals(r.probeNextSeq) && !r.probeTime.IsZero() && pkt.Len() != 0 {
			// The time between packets scaled to a fully loaded packet
			diff := float64(time.Since(r.probeTime).Microseconds()) * (packet.MAX_PAYLOAD_SIZE / float64(pkt.Len()))
			if diff != 0 {
				// Here we're doing an average of the measurements.
				r.avgLinkCapacity = 0.875*r.avgLinkCapacity + 0.125*1_000_000/diff
			}
		} else {
			r.probeTime = time.Time{}
		}
	} else {
		r.probeTime = time.Time{}
	}

	r.nPackets++

	pktLen := pkt.Len()

	r.rate.packets++
	r.rate.bytes += pktLen

	r.statistics.Pkt++
	r.statistics.Byte += pktLen

	//pkt.PktTsbpdTime = pkt.Timestamp + r.delay
	if pkt.Header().RetransmittedPacketFlag {
		r.statistics.PktRetrans++
		r.statistics.ByteRetrans += pktLen

		r.rate.bytesRetrans += pktLen
	}

	//  5.1.2. SRT's Default LiveCC Algorithm
	r.avgPayloadSize = 0.875*r.avgPayloadSize + 0.125*float64(pktLen)

	if pkt.Header().PacketSequenceNumber.Lte(r.lastDeliveredSequenceNumber) {
		// Too old, because up until r.lastDeliveredSequenceNumber, we already delivered
		r.statistics.PktBelated++
		r.statistics.ByteBelated += pktLen

		r.statistics.PktDrop++
		r.statistics.ByteDrop += pktLen

		return
	}

	if pkt.Header().PacketSequenceNumber.Lt(r.lastACKSequenceNumber) {
		// Already acknowledged, ignoring
		r.statistics.PktDrop++
		r.statistics.ByteDrop += pktLen

		return
	}

	wasSentInOrder := true

	if pkt.Header().PacketSequenceNumber.Equals(r.maxSeenSequenceNumber.Inc()) {
		// In order, the packet we expected
		r.maxSeenSequenceNumber = pkt.Header().PacketSequenceNumber
	} else if pkt.Header().PacketSequenceNumber.Lte(r.maxSeenSequenceNumber) {
		// Out of order, is it a missing piece? put it in the correct position
		inserted := false
		for e := r.packetList.Front(); e != nil; e = e.Next() {
			p := e.Value.(packet.Packet)

			if p.Header().PacketSequenceNumber == pkt.Header().PacketSequenceNumber {
				// Already received (has been sent more than once), ignoring
				r.statistics.PktDrop++
				r.statistics.ByteDrop += pktLen

				return
			} else if p.Header().PacketSequenceNumber.Gt(pkt.Header().PacketSequenceNumber) {
				// Late arrival, this fills a gap
				r.statistics.PktBuf++
				r.statistics.PktUnique++

				r.statistics.ByteBuf += pktLen
				r.statistics.ByteUnique += pktLen

				r.packetList.InsertBefore(pkt, e)
				inserted = true

				break
			}
		}

		if !inserted {
			return
		}

		// This is a belated packet (seq <= maxSeenSequenceNumber). Apply unlose logic.
		r.unlose(pkt)

		// Belated original (not retransmitted) means out-of-order delivery
		if !pkt.Header().RetransmittedPacketFlag {
			wasSentInOrder = false
		}

		// After unlose, handle ordered delivery counter and return
		r.updateOrderedDelivery(wasSentInOrder)
		return
	} else {
		// Too far ahead, there are some missing sequence numbers
		lossLen := uint64(pkt.Header().PacketSequenceNumber.Distance(r.maxSeenSequenceNumber))
		r.statistics.PktLoss += lossLen
		r.statistics.ByteLoss += lossLen * uint64(r.avgPayloadSize)

		// Determine initial loss TTL based on reorder support
		initialLossTTL := 0
		if r.reorderSupport {
			initialLossTTL = r.reorderTolerance
		}

		if initialLossTTL > 0 {
			// Defer NAK: add to freshLoss with current tolerance as TTL
			r.freshLoss = append(r.freshLoss, freshLossEntry{
				seqLo: r.maxSeenSequenceNumber.Inc(),
				seqHi: pkt.Header().PacketSequenceNumber.Dec(),
				ttl:   initialLossTTL,
			})

			// Enforce freshLoss size limit - collect overflow NAKs to send outside lock
			var overflowNAKs []circular.Number
			for len(r.freshLoss) > 1000 {
				// Force NAK on oldest entry
				oldest := r.freshLoss[0]
				r.freshLoss = r.freshLoss[1:]
				overflowNAKs = append(overflowNAKs, oldest.seqLo, oldest.seqHi)
			}

			// Send overflow NAKs outside the critical section below
			if len(overflowNAKs) > 0 {
				defer r.sendNAK(overflowNAKs)
			}
		} else {
			// Immediate NAK report
			r.sendNAK([]circular.Number{
				r.maxSeenSequenceNumber.Inc(),
				pkt.Header().PacketSequenceNumber.Dec(),
			})
		}

		r.maxSeenSequenceNumber = pkt.Header().PacketSequenceNumber
	}

	r.statistics.PktBuf++
	r.statistics.PktUnique++

	r.statistics.ByteBuf += pktLen
	r.statistics.ByteUnique += pktLen

	r.packetList.PushBack(pkt)

	// Update ordered delivery counter for in-order or retransmitted packets
	r.updateOrderedDelivery(wasSentInOrder)
}

func (r *receiver) periodicACK(now uint64) (ok bool, sequenceNumber circular.Number, lite bool) {
	r.lock.Lock()
	defer r.lock.Unlock()

	// 4.8.1. Packet Acknowledgement (ACKs, ACKACKs)
	if now-r.lastPeriodicACK < r.periodicACKInterval {
		if r.nPackets >= 64 {
			lite = true // Send light ACK
		} else {
			return
		}
	}

	minPktTsbpdTime, maxPktTsbpdTime := uint64(0), uint64(0)
	ackSequenceNumber := r.lastACKSequenceNumber

	e := r.packetList.Front()
	if e != nil {
		p := e.Value.(packet.Packet)

		minPktTsbpdTime = p.Header().PktTsbpdTime
		maxPktTsbpdTime = p.Header().PktTsbpdTime
	}

	// Find the sequence number up until we have all in a row.
	// Where the first gap is (or at the end of the list) is where we can ACK to.

	for e := r.packetList.Front(); e != nil; e = e.Next() {
		p := e.Value.(packet.Packet)

		// Skip packets that we already ACK'd.
		if p.Header().PacketSequenceNumber.Lte(ackSequenceNumber) {
			continue
		}

		// If there are packets that should have been delivered by now, move forward.
		if p.Header().PktTsbpdTime <= now {
			ackSequenceNumber = p.Header().PacketSequenceNumber
			continue
		}

		// Check if the packet is the next in the row.
		if p.Header().PacketSequenceNumber.Equals(ackSequenceNumber.Inc()) {
			ackSequenceNumber = p.Header().PacketSequenceNumber
			maxPktTsbpdTime = p.Header().PktTsbpdTime
			continue
		}

		break
	}

	ok = true
	sequenceNumber = ackSequenceNumber.Inc()

	// If ACK advanced past gaps (TLPKTDROP), revoke skipped sequences from freshLoss
	if len(r.freshLoss) > 0 && ackSequenceNumber.Gt(r.lastACKSequenceNumber) {
		r.freshLossRevoke(r.lastACKSequenceNumber.Inc(), ackSequenceNumber)
	}

	// Keep track of the last ACK's sequence number. With this we can faster ignore
	// packets that come in late that have a lower sequence number.
	r.lastACKSequenceNumber = ackSequenceNumber

	r.lastPeriodicACK = now
	r.nPackets = 0

	r.statistics.MsBuf = (maxPktTsbpdTime - minPktTsbpdTime) / 1_000

	return
}

func (r *receiver) periodicNAK(now uint64) []circular.Number {
	r.lock.Lock()
	defer r.lock.Unlock()

	if now-r.lastPeriodicNAK < r.periodicNAKInterval {
		return nil
	}

	nakList := []circular.Number{}

	// Send a periodic NAK

	ackSequenceNumber := r.lastACKSequenceNumber

	// Send a NAK for all gaps, but skip ranges that are still pending in freshLoss.
	for e := r.packetList.Front(); e != nil; e = e.Next() {
		p := e.Value.(packet.Packet)

		// Skip packets that we already ACK'd.
		if p.Header().PacketSequenceNumber.Lte(ackSequenceNumber) {
			continue
		}

		// If this packet is not in sequence, we stop here and report that gap.
		if !p.Header().PacketSequenceNumber.Equals(ackSequenceNumber.Inc()) {
			gapLo := ackSequenceNumber.Inc()
			gapHi := p.Header().PacketSequenceNumber.Dec()

			// Skip this gap if it overlaps with any freshLoss entry
			if !r.isInFreshLoss(gapLo, gapHi) {
				nakList = append(nakList, gapLo)
				nakList = append(nakList, gapHi)
			}
		}

		ackSequenceNumber = p.Header().PacketSequenceNumber
	}

	r.lastPeriodicNAK = now

	return nakList
}

func (r *receiver) Tick(now uint64) {
	if ok, sequenceNumber, lite := r.periodicACK(now); ok {
		r.sendACK(sequenceNumber, lite)
	}

	if nakList := r.periodicNAK(now); len(nakList) != 0 {
		r.sendNAK(nakList)
	}

	// Process freshLoss TTL expiry
	r.processFreshLoss()

	// Deliver packets whose PktTsbpdTime is ripe
	r.lock.Lock()
	removeList := make([]*list.Element, 0, r.packetList.Len())
	for e := r.packetList.Front(); e != nil; e = e.Next() {
		p := e.Value.(packet.Packet)

		if p.Header().PacketSequenceNumber.Lte(r.lastACKSequenceNumber) && p.Header().PktTsbpdTime <= now {
			r.statistics.PktBuf--
			r.statistics.ByteBuf -= p.Len()

			r.lastDeliveredSequenceNumber = p.Header().PacketSequenceNumber

			r.deliver(p)
			removeList = append(removeList, e)
		} else {
			break
		}
	}

	for _, e := range removeList {
		r.packetList.Remove(e)
	}
	r.lock.Unlock()

	r.lock.Lock()
	tdiff := now - r.rate.last // microseconds

	if tdiff > r.rate.period {
		r.rate.packetsPerSecond = float64(r.rate.packets) / (float64(tdiff) / 1000 / 1000)
		r.rate.bytesPerSecond = float64(r.rate.bytes) / (float64(tdiff) / 1000 / 1000)
		if r.rate.bytes != 0 {
			r.rate.pktLossRate = float64(r.rate.bytesRetrans) / float64(r.rate.bytes) * 100
		} else {
			r.rate.bytes = 0
		}

		r.rate.packets = 0
		r.rate.bytes = 0
		r.rate.bytesRetrans = 0

		r.rate.last = now
	}
	r.lock.Unlock()
}

func (r *receiver) SetNAKInterval(nakInterval uint64) {
	r.lock.Lock()
	defer r.lock.Unlock()

	r.periodicNAKInterval = nakInterval
}

func (r *receiver) ReorderTolerance() int {
	r.lock.RLock()
	defer r.lock.RUnlock()

	return r.reorderTolerance
}

func (r *receiver) SetReorderSupport(enabled bool) {
	r.lock.Lock()
	defer r.lock.Unlock()

	r.reorderSupport = enabled
	if enabled {
		r.reorderTolerance = r.maxReorderTolerance
	} else {
		r.reorderTolerance = 0
		r.consecOrderedDelivery = 0
		r.consecEarlyDelivery = 0
		r.freshLoss = nil
		r.traceReorderDistance = 0
	}
}

// unlose adjusts reorder tolerance for a belated packet. Mirrors libsrt CUDT::unlose().
func (r *receiver) unlose(pkt packet.Packet) {
	hasIncreasedTolerance := false
	wasReordered := false

	if r.reorderSupport {
		// Original (not retransmitted) belated packet means reordering
		wasReordered = !pkt.Header().RetransmittedPacketFlag
		if wasReordered {
			seqdiff := int(r.maxSeenSequenceNumber.Distance(pkt.Header().PacketSequenceNumber))
			if seqdiff > r.traceReorderDistance {
				r.traceReorderDistance = seqdiff
			}
			if seqdiff > r.reorderTolerance {
				newTolerance := seqdiff
				if newTolerance > r.maxReorderTolerance {
					newTolerance = r.maxReorderTolerance
				}
				r.reorderTolerance = newTolerance
				hasIncreasedTolerance = true
			}
		}
	}

	// Early return if adaptive reorder is not active (mirrors libsrt)
	if !r.reorderSupport || r.reorderTolerance == 0 {
		return
	}

	// Remove this sequence from freshLoss
	hadTTL := r.freshLossRemoveOne(pkt.Header().PacketSequenceNumber)

	if wasReordered {
		r.consecOrderedDelivery = 0
		if hasIncreasedTolerance {
			r.consecEarlyDelivery = 0
		} else if hadTTL > 2 {
			r.consecEarlyDelivery++
			if r.consecEarlyDelivery >= 10 {
				r.consecEarlyDelivery = 0
				if r.reorderTolerance > 0 {
					r.reorderTolerance--
				}
			}
		}
	}
}

// updateOrderedDelivery tracks in-order delivery and decays tolerance after 50 consecutive.
func (r *receiver) updateOrderedDelivery(wasSentInOrder bool) {
	if !r.reorderSupport {
		return
	}

	if wasSentInOrder {
		r.consecOrderedDelivery++
		if r.consecOrderedDelivery >= 50 {
			r.consecOrderedDelivery = 0
			if r.reorderTolerance > 0 {
				r.reorderTolerance--
			}
		}
	} else {
		r.consecOrderedDelivery = 0
	}
}

// processFreshLoss sends NAK for expired freshLoss entries and decrements TTL of the rest.
func (r *receiver) processFreshLoss() {
	r.lock.Lock()

	if len(r.freshLoss) == 0 {
		r.lock.Unlock()
		return
	}

	var lossdata []circular.Number

	// Phase 1: collect entries with TTL <= 0
	expiredCount := 0
	for i := range r.freshLoss {
		if r.freshLoss[i].ttl <= 0 {
			lossdata = append(lossdata, r.freshLoss[i].seqLo, r.freshLoss[i].seqHi)
			expiredCount = i + 1
		} else {
			break
		}
	}

	// Remove expired entries
	if expiredCount > 0 {
		r.freshLoss = r.freshLoss[expiredCount:]
	}

	// Phase 2: decrement TTL of remaining entries
	for i := range r.freshLoss {
		r.freshLoss[i].ttl--
	}

	r.lock.Unlock()

	// Send NAK for expired entries (outside lock to avoid deadlock with sendNAK)
	if len(lossdata) > 0 {
		r.sendNAK(lossdata)
	}
}

// freshLossRemoveOne removes a single sequence number from the freshLoss queue.
// Returns the TTL the entry had when removed, or 0 if not found.
func (r *receiver) freshLossRemoveOne(seq circular.Number) int {
	for i := 0; i < len(r.freshLoss); i++ {
		entry := &r.freshLoss[i]

		if seq.Lt(entry.seqLo) || seq.Gt(entry.seqHi) {
			continue
		}

		hadTTL := entry.ttl

		if entry.seqLo.Equals(entry.seqHi) {
			// DELETE: single-element range
			r.freshLoss = append(r.freshLoss[:i], r.freshLoss[i+1:]...)
		} else if seq.Equals(entry.seqLo) {
			// STRIPPED: remove from beginning
			entry.seqLo = entry.seqLo.Inc()
		} else if seq.Equals(entry.seqHi) {
			// STRIPPED: remove from end
			entry.seqHi = entry.seqHi.Dec()
		} else {
			// SPLIT: split into two ranges
			newEntry := freshLossEntry{
				seqLo: seq.Inc(),
				seqHi: entry.seqHi,
				ttl:   entry.ttl,
			}
			entry.seqHi = seq.Dec()

			// Insert newEntry after current position
			r.freshLoss = append(r.freshLoss, freshLossEntry{})
			copy(r.freshLoss[i+2:], r.freshLoss[i+1:])
			r.freshLoss[i+1] = newEntry
		}

		return hadTTL
	}

	return 0
}

// freshLossRevoke removes a range [lo, hi] from the freshLoss queue.
// Used when packets are dropped (e.g., TLPKTDROP).
func (r *receiver) freshLossRevoke(lo, hi circular.Number) {
	result := make([]freshLossEntry, 0, len(r.freshLoss))

	for i := 0; i < len(r.freshLoss); i++ {
		entry := r.freshLoss[i]

		// Past the revoke range: copy remaining entries and stop
		if hi.Lt(entry.seqLo) {
			result = append(result, r.freshLoss[i:]...)
			break
		}

		// Before the revoke range, keep entry as-is
		if lo.Gt(entry.seqHi) {
			result = append(result, entry)
			continue
		}

		// Full overlap: skip (delete) this entry
		if lo.Lte(entry.seqLo) && hi.Gte(entry.seqHi) {
			continue
		}

		// Partial overlap from the left only: strip left side
		if lo.Lte(entry.seqLo) {
			entry.seqLo = hi.Inc()
			result = append(result, entry)
			continue
		}

		// Partial overlap from the right only: strip right side
		if hi.Gte(entry.seqHi) {
			entry.seqHi = lo.Dec()
			result = append(result, entry)
			continue
		}

		// Middle overlap: split into left [seqLo, lo-1] and right [hi+1, seqHi]
		leftEntry := freshLossEntry{
			seqLo: entry.seqLo,
			seqHi: lo.Dec(),
			ttl:   entry.ttl,
		}
		rightEntry := freshLossEntry{
			seqLo: hi.Inc(),
			seqHi: entry.seqHi,
			ttl:   entry.ttl,
		}
		result = append(result, leftEntry, rightEntry)
	}

	r.freshLoss = result
}

// isInFreshLoss checks if a gap range [lo, hi] overlaps with any freshLoss entry.
func (r *receiver) isInFreshLoss(lo, hi circular.Number) bool {
	for i := range r.freshLoss {
		entry := &r.freshLoss[i]
		// Overlap check: !(hi < entry.seqLo || lo > entry.seqHi)
		if !hi.Lt(entry.seqLo) && !lo.Gt(entry.seqHi) {
			return true
		}
	}
	return false
}

func (r *receiver) String(t uint64) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("maxSeen=%d lastACK=%d lastDelivered=%d\n", r.maxSeenSequenceNumber.Val(), r.lastACKSequenceNumber.Val(), r.lastDeliveredSequenceNumber.Val()))

	r.lock.RLock()
	for e := r.packetList.Front(); e != nil; e = e.Next() {
		p := e.Value.(packet.Packet)

		b.WriteString(fmt.Sprintf("   %d @ %d (in %d)\n", p.Header().PacketSequenceNumber.Val(), p.Header().PktTsbpdTime, int64(p.Header().PktTsbpdTime)-int64(t)))
	}
	r.lock.RUnlock()

	return b.String()
}
