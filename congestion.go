// Copyright 2020 FOSS GmbH. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package srt

import (
	"container/list"
	"fmt"
	"strings"
	"sync"
	"time"
)

type liveStatsCounter struct {
	pushed uint64
	delivered                   uint64
	buffer                  uint64
	retransmitted           uint64
	retransmittedAndDropped uint64
	dropped                 uint64
	droppedTooLate          uint64
}

type liveStats struct {
	packets liveStatsCounter
	bytes   liveStatsCounter
}

type liveSendConfig struct {
	initialSequenceNumber circular
	dropInterval uint64
	maxBW int64
	inputBW int64
	minInputBW int64
	overheadBW int64
}

type liveSend struct {
	nextSequenceNumber circular

	packetList *list.List
	lossList   *list.List
	lock       sync.RWMutex

	dropInterval uint64 // microseconds

	avgPayloadSize float64 // bytes
	pktSndPeriod float64 // microseconds
	maxBW float64 // bytes/s
	inputBW float64 // bytes/s
	overheadBW float64 // percent

	estimatedInputBW float64
	period time.Duration
	last time.Time

	statistics liveStats
	prevStatistics liveStats

	deliver func(p packet)
}

func newLiveSend(config liveSendConfig) *liveSend {
	s := &liveSend{
		nextSequenceNumber: config.initialSequenceNumber,
		packetList:         list.New(),
		lossList:           list.New(),

		dropInterval: config.dropInterval, // microseconds

		avgPayloadSize: 1456, //  5.1.2. SRT's Default LiveCC Algorithm
		maxBW: float64(config.maxBW),
		inputBW: float64(config.inputBW),
		overheadBW: float64(config.overheadBW),

		estimatedInputBW: 0,
		period: time.Second,
		last: time.Now(),

		deliver: func(p packet) {},
	}

	s.maxBW = 128 * 1024 * 1024 // 1 Gbit/s
	s.pktSndPeriod = (s.avgPayloadSize + 16) * 1000000 / s.maxBW

	return s
}

func (s *liveSend) Stats() liveStats {
	return s.statistics
}

func (s *liveSend) Flush() {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.packetList = s.packetList.Init()
	s.lossList = s.lossList.Init()
}

func (s *liveSend) Push(p packet) {
	p.Header().packetSequenceNumber = s.nextSequenceNumber
	s.nextSequenceNumber = s.nextSequenceNumber.Inc()

	// packets put into send buffer
	s.statistics.packets.buffer++
	s.statistics.packets.pushed++
	// bytes put into send buffer
	s.statistics.bytes.buffer += p.Len()
	s.statistics.bytes.pushed += p.Len()

	now := time.Now()
	tdiff := now.Sub(s.last)

	if tdiff > s.period {
		s.estimatedInputBW = float64(s.statistics.bytes.pushed - s.prevStatistics.bytes.pushed) / tdiff.Seconds()

		s.prevStatistics = s.statistics
		s.last = now
	}

	//log("got %d @ %d\n", p.packetSequenceNumber, p.PktTsbpdTime)

	p.Header().timestamp = uint32(p.Header().pktTsbpdTime & uint64(MAX_TIMESTAMP))

	s.lock.Lock()
	s.packetList.PushBack(p)
	s.lock.Unlock()
}

func (s *liveSend) Tick(now uint64) {
	//log("tick @ %d\n", now)

	// deliver packets whose PktTsbpdTime is ripe
	s.lock.Lock()
	removeList := []*list.Element{}
	for e := s.packetList.Front(); e != nil; e = e.Next() {
		p := e.Value.(packet)
		if p.Header().pktTsbpdTime <= now {
			//log("delivering %d @ %d (%d bytes)\n", p.packetSequenceNumber, p.PktTsbpdTime, p.Len())

			// packets delivered
			s.statistics.packets.delivered++
			// bytes delivered
			s.statistics.bytes.delivered += p.Len()

			//  5.1.2. SRT's Default LiveCC Algorithm
			s.avgPayloadSize = 0.875 * s.avgPayloadSize + 0.125 * float64(p.Len())

			s.deliver(p)
			//log("   adding %d @ %d to losslist (%d)\n", p.packetSequenceNumber, p.PktTsbpdTime, now)
			removeList = append(removeList, e)
		} else {
			break
		}
	}

	for _, e := range removeList {
		s.lossList.PushBack(e.Value)
		s.packetList.Remove(e)
	}
	s.lock.Unlock()

	s.lock.Lock()
	removeList = nil
	for e := s.lossList.Front(); e != nil; e = e.Next() {
		p := e.Value.(packet)

		if p.Header().pktTsbpdTime+s.dropInterval <= now {
			// dropped packet because too old
			s.statistics.packets.dropped++
			s.statistics.packets.dropped += p.Len()

			//log("   dropping %d @ %d from losslist (%d, %d)\n", p.packetSequenceNumber, p.PktTsbpdTime, p.PktTsbpdTime + s.dropInterval, now)
			removeList = append(removeList, e)
		}
		/*
			if s.dropInterval > now {
				if p.PktTsbpdTime > s.dropInterval - now {
					log("   dropping %d @ %d from losslist\n", p.packetSequenceNumber, p.PktTsbpdTime)
					removeList = append(removeList, e)
				}
			} else {
				if p.PktTsbpdTime <= now - s.dropInterval {
					log("   dropping %d @ %d from losslist\n", p.packetSequenceNumber, p.PktTsbpdTime)
					removeList = append(removeList, e)
				}
			}
		*/
	}

	// These packets are not needed anymore (too late)
	for _, e := range removeList {
		p := e.Value.(packet)

		// packets in buffer --
		s.statistics.packets.buffer--
		// bytes in buffer --
		s.statistics.bytes.buffer -= p.Len()

		s.lossList.Remove(e)

		// This packet has been ACK'd and we don't need it anymore
		p.Decommission()
	}
	s.lock.Unlock()
}

func (s *liveSend) ACK(sequenceNumber circular) {
	//log("got ACK for %d\n", sequenceNumber)
	s.lock.Lock()
	removeList := []*list.Element{}
	for e := s.lossList.Front(); e != nil; e = e.Next() {
		p := e.Value.(packet)
		if p.Header().packetSequenceNumber.Lt(sequenceNumber) {
			// remove packet from buffer because it has been successfully transmitted
			//log("   deleting %d @ %d from losslist\n", p.packetSequenceNumber, p.PktTsbpdTime)
			removeList = append(removeList, e)
		} else {
			break
		}
	}

	// These packets are not needed anymore (ACK'd)
	for _, e := range removeList {
		p := e.Value.(packet)

		// packets in buffer --
		s.statistics.packets.buffer--
		// bytes in buffer --
		s.statistics.bytes.buffer -= p.Len()

		s.lossList.Remove(e)

		// This packet has been ACK'd and we don't need it anymore
		p.Decommission()
	}

	s.pktSndPeriod = (s.avgPayloadSize + 16) * 1000000 / s.maxBW

	s.lock.Unlock()
}

func (s *liveSend) NAK(sequenceNumbers []circular) {
	if len(sequenceNumbers) == 0 {
		return
	}

	//log("got NAK for %v\n", sequenceNumber)

	s.lock.RLock()
	for e := s.lossList.Back(); e != nil; e = e.Prev() {
		p := e.Value.(packet)

		for i := 0; i < len(sequenceNumbers); i += 2 {
			if p.Header().packetSequenceNumber.Gte(sequenceNumbers[i]) && p.Header().packetSequenceNumber.Lte(sequenceNumbers[i+1]) {
				// packets retransmitted++
				s.statistics.packets.retransmitted++
				// bytes retransmitted++
				s.statistics.bytes.retransmitted += p.Len()

				//  5.1.2. SRT's Default LiveCC Algorithm
				s.avgPayloadSize = 0.875 * s.avgPayloadSize + 0.125 * float64(p.Len())

				//log("   retransmitting %d @ %d from losslist\n", p.packetSequenceNumber, p.PktTsbpdTime)

				p.Header().retransmittedPacketFlag = true
				s.deliver(p)
			}
		}
	}
	s.lock.RUnlock()
}

type liveRecvConfig struct {
	initialSequenceNumber circular
	periodicACKInterval uint64
	periodicNAKInterval uint64
}

type liveRecv struct {
	maxSeenSequenceNumber circular
	lastACKSequenceNumber circular
	lastPktTsbpdTime      uint64
	packetList            *list.List
	lock                  sync.RWMutex

	start uint32
	ticks uint32

	nPackets uint

	periodicACKInterval uint64 // config
	periodicNAKInterval uint64 // config

	lastPeriodicACK uint64
	lastPeriodicNAK uint64

	statistics liveStats
	prevStatistics liveStats

	last time.Time
	period time.Duration

	pps uint32
	bps uint32

	sendACK func(seq uint32, light bool)
	sendNAK func(from, to uint32)
	deliver func(p packet)
}

func newLiveRecv(config liveRecvConfig) *liveRecv {
	r := &liveRecv{
		maxSeenSequenceNumber: config.initialSequenceNumber.Dec(),
		lastACKSequenceNumber: config.initialSequenceNumber.Dec(),
		packetList:            list.New(),

		periodicACKInterval: config.periodicACKInterval, // microseconds
		periodicNAKInterval: config.periodicNAKInterval, // microseconds
	}

	r.sendACK = func(seq uint32, light bool) {}
	r.sendNAK = func(from, to uint32) {}
	r.deliver = func(p packet) {}

	r.last = time.Now()
	r.period = time.Second

	return r
}

func (r *liveRecv) Stats() liveStats {
	return r.statistics
}

func (r *liveRecv) PacketRate() (pps, bps uint32) {
	r.lock.Lock()
	defer r.lock.Unlock()

	tdiff := time.Since(r.last)

	if tdiff < r.period {
		pps = r.pps
		bps = r.bps

		return
	}

	pdiff := r.statistics.packets.pushed - r.prevStatistics.packets.pushed
	bdiff := r.statistics.bytes.pushed - r.prevStatistics.bytes.pushed

	r.pps = uint32(float64(pdiff) / tdiff.Seconds())
	r.bps = uint32(float64(bdiff) / tdiff.Seconds())

	r.prevStatistics = r.statistics
	r.last = time.Now()

	pps = r.pps
	bps = r.bps

	return
}

func (r *liveRecv) Flush() {
	r.lock.Lock()
	defer r.lock.Unlock()

	r.packetList = r.packetList.Init()
}

func (r *liveRecv) Push(pkt packet) {
	r.lock.Lock()
	defer r.lock.Unlock()

	r.nPackets++

	// total received packets
	r.statistics.packets.pushed++
	// total received bytes
	r.statistics.bytes.pushed += pkt.Len()

	//pkt.PktTsbpdTime = pkt.Timestamp + r.delay

	//logIn("new packet %d @ %d, expecting %d\n", pkt.packetSequenceNumber.Val(), pkt.PktTsbpdTime, r.maxSeenSequenceNumber.Inc())

	if pkt.Header().pktTsbpdTime < r.lastPktTsbpdTime {
		// too old
		//log("too old packet. got: %d, expecting >= %d (%d)\n", pkt.pktTsbpdTime, r.lastPktTsbpdTime, pkt.packetSequenceNumber.Val())

		r.statistics.packets.droppedTooLate++
		r.statistics.bytes.droppedTooLate += pkt.Len()

		return
	}

	if pkt.Header().packetSequenceNumber.Equals(r.maxSeenSequenceNumber.Inc()) {
		// in order
		r.maxSeenSequenceNumber = pkt.Header().packetSequenceNumber

		//logIn("   the packet we expected\n")
	} else if pkt.Header().packetSequenceNumber.Lte(r.maxSeenSequenceNumber) {
		// out of order
		//log("a missing piece? got: %d, expecting: %d\n", pkt.packetSequenceNumber.Val(), r.maxSeenSequenceNumber.Inc().Val())

		if pkt.Header().packetSequenceNumber.Lt(r.lastACKSequenceNumber) {
			// already acknowledged
			r.statistics.packets.dropped++
			r.statistics.bytes.dropped += pkt.Len()

			//log("   => we already ACK'd this packet. ignoring\n")
			return
		}

		// put it in the correct position
		for e := r.packetList.Front(); e != nil; e = e.Next() {
			p := e.Value.(packet)

			if p.Header().packetSequenceNumber == pkt.Header().packetSequenceNumber {
				// already received (has been sent more than once)
				r.statistics.packets.retransmittedAndDropped++
				r.statistics.bytes.retransmittedAndDropped += pkt.Len()

				// we already have this packet, ignore
				//log("   => we already have it, but not yet ACK'd, ignoring\n")
				break
			} else if p.Header().packetSequenceNumber.Gt(pkt.Header().packetSequenceNumber) {
				// late arrival. this fills a gap

				// packets in buffer ++
				r.statistics.packets.buffer++
				// bytes in buffer ++
				r.statistics.bytes.buffer += pkt.Len()

				if pkt.Header().retransmittedPacketFlag == true {
					r.statistics.packets.retransmitted++
					r.statistics.bytes.retransmitted += pkt.Len()
				}

				r.packetList.InsertBefore(pkt, e)
				//log("   => adding it before %d\n", p.packetSequenceNumber.Val())
				break
			}
		}

		return
	} else {
		// out of order, immediate NAK report
		// here we can prevent a possibly unecessary NAK with SRTO_LOXXMAXTTL
		// the sequence number is too big
		// send a NAK for all sequences that are bigger than the one we know until
		// the one we have at hand, both ends exluding.
		//log("sending NAK for (%d, %d)\n", r.maxSeenSequenceNumber.Inc().Val(), pkt.packetSequenceNumber.Dec().Val())
		r.sendNAK(r.maxSeenSequenceNumber.Inc().Val(), pkt.Header().packetSequenceNumber.Dec().Val())

		//log("there are some missing sequence numbers. got: %d, expecting %d\n", pkt.packetSequenceNumber.Val(), r.maxSeenSequenceNumber.Inc().Val())

		r.maxSeenSequenceNumber = pkt.Header().packetSequenceNumber
	}

	// packets in buffer ++
	r.statistics.packets.buffer++
	// bytes in buffer ++
	r.statistics.bytes.buffer += pkt.Len()

	r.packetList.PushBack(pkt)
}

func (r *liveRecv) periodicACK(now uint64) (ok bool, sequenceNumber uint32, lite bool) {
	r.lock.RLock()
	defer r.lock.RUnlock()

	if now-r.lastPeriodicACK <= r.periodicACKInterval && r.nPackets >= 64 {
		return
	}

	// send a periodic or light ACK
	if r.nPackets >= 64 {
		lite = true
	}

	// find the sequence number up until we have all in a row.
	// where the first gap is (or at the end of the list) is where we can ACK to.
	e := r.packetList.Front()
	if e != nil {
		p := e.Value.(packet)

		ackSequenceNumber := p.Header().packetSequenceNumber

		if p.Header().pktTsbpdTime > r.lastPktTsbpdTime {
			ackSequenceNumber = r.lastACKSequenceNumber
		} else {
			for e = e.Next(); e != nil; e = e.Next() {
				p = e.Value.(packet)
				if p.Header().packetSequenceNumber.Equals(ackSequenceNumber.Inc()) == false {
					break
				}

				ackSequenceNumber = p.Header().packetSequenceNumber
			}
		}

		ok = true
		sequenceNumber = ackSequenceNumber.Inc().Val()

		// keep track of the last ACK's sequence. with this we can faster ignore
		// packets that come in that have a lower sequence number.
		r.lastACKSequenceNumber = ackSequenceNumber
	}

	r.lastPeriodicACK = now
	r.nPackets = 0

	return
}

func (r *liveRecv) periodicNAK(now uint64) (ok bool, from, to uint32) {
	r.lock.RLock()
	defer r.lock.RUnlock()

	if now-r.lastPeriodicNAK <= r.periodicNAKInterval {
		return
	}

	// send a periodic NAK

	// find the first sequence number which is missing and send a
	// NAK up until the latest sequence number we know.
	// this is inefficient because this will potentially trigger a re-send
	// of many packets that we already have.
	// alternatively send a NAK only for the first gap.
	// alternatively send a NAK for max. X gaps because the size of the NAK packet is limited
	e := r.packetList.Front()
	if e != nil {
		p := e.Value.(packet)

		ackSequenceNumber := p.Header().packetSequenceNumber

		for e = e.Next(); e != nil; e = e.Next() {
			p = e.Value.(packet)
			if p.Header().packetSequenceNumber.Equals(ackSequenceNumber.Inc()) == false {
				nackSequenceNumber := ackSequenceNumber.Inc()

				ok = true
				from = nackSequenceNumber.Val()
				to = p.Header().packetSequenceNumber.Dec().Val()
				break
			}

			ackSequenceNumber = p.Header().packetSequenceNumber
		}
	}

	r.lastPeriodicNAK = now

	return
}

func (r *liveRecv) Tick(now uint64) {
	if ok, sequenceNumber, lite := r.periodicACK(now); ok == true {
		//log("sending periodic ACK for up to %d (lite: %v)\n", sequenceNumber, lite)
		r.sendACK(sequenceNumber, lite)
	}

	if ok, from, to := r.periodicNAK(now); ok == true {
		//log("sending periodic NAK for (%d, %d)\n", nackSequenceNumber.Val(), p.packetSequenceNumber.Dec().Val())
		r.sendNAK(from, to)
	}

	// deliver packets whose PktTsbpdTime is ripe
	r.lock.Lock()
	defer r.lock.Unlock()

	removeList := []*list.Element{}
	for e := r.packetList.Front(); e != nil; e = e.Next() {
		p := e.Value.(packet)

		if p.Header().packetSequenceNumber.Lte(r.lastACKSequenceNumber) && p.Header().pktTsbpdTime <= now {
			// packets in buffer --
			r.statistics.packets.buffer--
			r.statistics.packets.delivered--
			// bytes in buffer --
			r.statistics.bytes.buffer -= p.Len()
			r.statistics.bytes.delivered -= p.Len()

			r.deliver(p)
			removeList = append(removeList, e)
		} else {
			break
		}
	}

	for _, e := range removeList {
		r.packetList.Remove(e)
	}

	r.lastPktTsbpdTime = now

	//logIn("@%d: %s", t, r.String(t))
}

func (r *liveRecv) SetNAKInterval(nakInterval uint64) {
	//log("waiting for the lock\n")
	r.lock.Lock()
	defer r.lock.Unlock()

	//log("got the lock\n")

	r.periodicNAKInterval = nakInterval
}

func (r *liveRecv) String(t uint64) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("maxSeen=%d lastACK=%d\n", r.maxSeenSequenceNumber.Val(), r.lastACKSequenceNumber.Val()))

	r.lock.RLock()
	for e := r.packetList.Front(); e != nil; e = e.Next() {
		p := e.Value.(packet)

		b.WriteString(fmt.Sprintf("   %d @ %d (in %d)\n", p.Header().packetSequenceNumber.Val(), p.Header().pktTsbpdTime, int64(p.Header().pktTsbpdTime)-int64(t)))
	}
	r.lock.RUnlock()

	return b.String()
}

/*
	ticks := uint32(0)

	send := newLiveSend(42, 10)
	send.deliver = func(p *Packet) {
		log("delivering %d @ %d\n", p.packetSequenceNumber, p.PktTsbpdTime)
	}
	send.tick(ticks)
	ticks++

	p := &Packet{
		PktTsbpdTime: 3,
	}
	send.push(p)
	send.tick(ticks)
	ticks++

	p = &Packet{
		PktTsbpdTime: 4,
	}
	send.push(p)
	send.tick(ticks)
	ticks++

	p = &Packet{
		PktTsbpdTime: 5,
	}
	send.push(p)
	send.tick(ticks)
	ticks++

	p = &Packet{
		PktTsbpdTime: 6,
	}
	send.push(p)
	send.tick(ticks)
	ticks++

	send.nak([]uint32{42,42})

	p = &Packet{
		PktTsbpdTime: 7,
	}
	send.push(p)
	send.tick(ticks)
	ticks++

	p = &Packet{
		PktTsbpdTime: 8,
	}
	send.push(p)
	send.tick(ticks)
	ticks++

	send.tick(ticks)
	ticks++

	send.tick(ticks)
	ticks++

	send.ack(46)

	send.tick(ticks)
	ticks++

	send.tick(ticks)
	ticks++

	send.tick(ticks)
	ticks++

	send.tick(ticks)
	ticks++

	send.tick(ticks)
	ticks++

	send.tick(ticks)
	ticks++

	send.tick(ticks)
	ticks++
*/
/*
	recv := newLiveRecv(1, 2, 4)
	recv.tick(ticks)
	ticks++

	p := &Packet{
		packetSequenceNumber: 1,
		timestamp: 0,
		PktTsbpdTime: 10,
	}
	recv.push(p)
	recv.tick(ticks)
	ticks++

	p = &Packet{
		packetSequenceNumber: 2,
		timestamp: 1,
		PktTsbpdTime: 11,
	}
	recv.push(p)
	recv.tick(ticks)
	ticks++

	p = &Packet{
		packetSequenceNumber: 4,
		timestamp: 3,
		PktTsbpdTime: 14,
	}
	recv.push(p)
	recv.tick(ticks)
	ticks++

	p = &Packet{
		packetSequenceNumber: 5,
		timestamp: 4,
		PktTsbpdTime: 15,
	}
	recv.push(p)
	recv.tick(ticks)
	ticks++

	p = &Packet{
		packetSequenceNumber: 6,
		timestamp: 5,
		PktTsbpdTime: 16,
	}
	recv.push(p)
	recv.tick(ticks)
	ticks++

	p = &Packet{
		packetSequenceNumber: 3,
		timestamp: 2,
		PktTsbpdTime: 13,
	}
	//recv.push(p)
	recv.tick(ticks)
	ticks++

	recv.tick(ticks)
	ticks++

	p = &Packet{
		packetSequenceNumber: 5,
		timestamp: 4,
		PktTsbpdTime: 15,
	}
	recv.push(p)

	recv.tick(ticks)
	ticks++
	recv.tick(ticks)
	ticks++
	recv.tick(ticks)
	ticks++
	recv.tick(ticks)
	ticks++

	p = &Packet{
		packetSequenceNumber: 3,
		timestamp: 2,
		PktTsbpdTime: 13,
	}
	recv.push(p)
	recv.tick(ticks)
	ticks++
*/
