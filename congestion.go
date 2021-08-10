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

type liveSendStats struct {
	pktSent  uint64
	byteSent uint64

	pktSentUnique  uint64
	byteSentUnique uint64

	pktSndLoss  uint64
	byteSndLoss uint64

	pktRetrans  uint64
	byteRetrans uint64

	usSndDuration uint64 // microseconds

	pktSndDrop  uint64
	byteSndDrop uint64

	// instantaneous
	pktSndBuf  uint64
	byteSndBuf uint64
	msSndBuf   uint64

	pktFlightSize uint64

	usPktSndPeriod float64 // microseconds
	bytePayload    uint64
}

type liveSendConfig struct {
	initialSequenceNumber circular
	dropInterval          uint64
	maxBW                 int64
	inputBW               int64
	minInputBW            int64
	overheadBW            int64
	onDeliver             func(p packet)
}

type liveSend struct {
	nextSequenceNumber circular

	packetList *list.List
	lossList   *list.List
	lock       sync.RWMutex

	dropInterval uint64 // microseconds

	avgPayloadSize float64 // bytes
	pktSndPeriod   float64 // microseconds
	maxBW          float64 // bytes/s
	inputBW        float64 // bytes/s
	overheadBW     float64 // percent

	statistics liveSendStats

	rate struct {
		period time.Duration
		last   time.Time

		bytes     uint64
		prevBytes uint64

		estimatedInputBW float64 // bytes/s
	}

	deliver func(p packet)
}

func newLiveSend(config liveSendConfig) *liveSend {
	s := &liveSend{
		nextSequenceNumber: config.initialSequenceNumber,
		packetList:         list.New(),
		lossList:           list.New(),

		dropInterval: config.dropInterval, // microseconds

		avgPayloadSize: 1456, //  5.1.2. SRT's Default LiveCC Algorithm
		maxBW:          float64(config.maxBW),
		inputBW:        float64(config.inputBW),
		overheadBW:     float64(config.overheadBW),

		deliver: config.onDeliver,
	}

	if s.deliver == nil {
		s.deliver = func(p packet) {}
	}

	s.maxBW = 128 * 1024 * 1024 // 1 Gbit/s
	s.pktSndPeriod = (s.avgPayloadSize + 16) * 1_000_000 / s.maxBW

	s.rate.period = time.Second
	s.rate.last = time.Now()

	return s
}

func (s *liveSend) Stats() liveSendStats {
	s.lock.RLock()
	defer s.lock.RUnlock()

	s.statistics.usPktSndPeriod = s.pktSndPeriod
	s.statistics.bytePayload = uint64(s.avgPayloadSize)
	s.statistics.msSndBuf = 0

	max := s.lossList.Back()
	min := s.lossList.Front()

	if max != nil && min != nil {
		s.statistics.msSndBuf = (max.Value.(packet).Header().pktTsbpdTime - min.Value.(packet).Header().pktTsbpdTime) / 1_000
	}

	return s.statistics
}

func (s *liveSend) Flush() {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.packetList = s.packetList.Init()
	s.lossList = s.lossList.Init()
}

func (s *liveSend) Push(p packet) {
	s.lock.Lock()
	defer s.lock.Unlock()

	// give to the packet a sequence number
	p.Header().packetSequenceNumber = s.nextSequenceNumber
	s.nextSequenceNumber = s.nextSequenceNumber.Inc()

	pktLen := p.Len()

	s.statistics.pktSndBuf++
	s.statistics.byteSndBuf += pktLen

	// bandwidth calculation
	s.rate.bytes += pktLen

	now := time.Now()
	tdiff := now.Sub(s.rate.last)

	if tdiff > s.rate.period {
		s.rate.estimatedInputBW = float64(s.rate.bytes-s.rate.prevBytes) / tdiff.Seconds()

		s.rate.prevBytes = s.rate.bytes
		s.rate.last = now
	}

	p.Header().timestamp = uint32(p.Header().pktTsbpdTime & uint64(MAX_TIMESTAMP))

	s.packetList.PushBack(p)

	s.statistics.pktFlightSize = uint64(s.packetList.Len())
}

func (s *liveSend) Tick(now uint64) {
	// deliver packets whose PktTsbpdTime is ripe
	s.lock.Lock()
	removeList := make([]*list.Element, 0, s.packetList.Len())
	for e := s.packetList.Front(); e != nil; e = e.Next() {
		p := e.Value.(packet)
		if p.Header().pktTsbpdTime <= now {
			s.statistics.pktSent++
			s.statistics.pktSentUnique++

			s.statistics.byteSent += p.Len()
			s.statistics.byteSentUnique += p.Len()

			s.statistics.usSndDuration += uint64(s.pktSndPeriod)

			//  5.1.2. SRT's Default LiveCC Algorithm
			s.avgPayloadSize = 0.875*s.avgPayloadSize + 0.125*float64(p.Len())

			s.deliver(p)
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
	removeList = make([]*list.Element, 0, s.lossList.Len())
	for e := s.lossList.Front(); e != nil; e = e.Next() {
		p := e.Value.(packet)

		if p.Header().pktTsbpdTime+s.dropInterval <= now {
			// dropped packet because too old
			s.statistics.pktSndDrop++
			s.statistics.pktSndLoss++
			s.statistics.byteSndDrop += p.Len()
			s.statistics.byteSndLoss += p.Len()

			removeList = append(removeList, e)
		}
	}

	// These packets are not needed anymore (too late)
	for _, e := range removeList {
		p := e.Value.(packet)

		s.statistics.pktSndBuf--
		s.statistics.byteSndBuf -= p.Len()

		s.lossList.Remove(e)

		// This packet has been ACK'd and we don't need it anymore
		p.Decommission()
	}
	s.lock.Unlock()
}

func (s *liveSend) ACK(sequenceNumber circular) {
	s.lock.Lock()
	defer s.lock.Unlock()

	removeList := make([]*list.Element, 0, s.lossList.Len())
	for e := s.lossList.Front(); e != nil; e = e.Next() {
		p := e.Value.(packet)
		if p.Header().packetSequenceNumber.Lt(sequenceNumber) {
			// remove packet from buffer because it has been successfully transmitted
			removeList = append(removeList, e)
		} else {
			break
		}
	}

	// These packets are not needed anymore (ACK'd)
	for _, e := range removeList {
		p := e.Value.(packet)

		s.statistics.pktSndBuf--
		s.statistics.byteSndBuf -= p.Len()

		s.lossList.Remove(e)

		// This packet has been ACK'd and we don't need it anymore
		p.Decommission()
	}

	s.pktSndPeriod = (s.avgPayloadSize + 16) * 1000000 / s.maxBW
}

func (s *liveSend) NAK(sequenceNumbers []circular) {
	if len(sequenceNumbers) == 0 {
		return
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	for e := s.lossList.Back(); e != nil; e = e.Prev() {
		p := e.Value.(packet)

		for i := 0; i < len(sequenceNumbers); i += 2 {
			if p.Header().packetSequenceNumber.Gte(sequenceNumbers[i]) && p.Header().packetSequenceNumber.Lte(sequenceNumbers[i+1]) {
				s.statistics.pktRetrans++
				s.statistics.pktSent++
				s.statistics.pktSndLoss++

				s.statistics.byteRetrans += p.Len()
				s.statistics.byteSent += p.Len()
				s.statistics.byteSndLoss += p.Len()

				//  5.1.2. SRT's Default LiveCC Algorithm
				s.avgPayloadSize = 0.875*s.avgPayloadSize + 0.125*float64(p.Len())

				p.Header().retransmittedPacketFlag = true
				s.deliver(p)
			}
		}
	}
}

type liveRecvStats struct {
	pktRecv  uint64
	byteRecv uint64

	pktRecvUnique  uint64
	byteRecvUnique uint64

	pktRcvLoss  uint64
	byteRcvLoss uint64

	pktRcvRetrans  uint64
	byteRcvRetrans uint64

	pktRcvDrop  uint64
	byteRcvDrop uint64

	// instantaneous
	pktRcvBuf  uint64
	byteRcvBuf uint64
	msRcvBuf   uint64

	bytePayload uint64
}

type liveRecvConfig struct {
	initialSequenceNumber circular
	periodicACKInterval   uint64 // microseconds
	periodicNAKInterval   uint64 // microseconds
	onSendACK             func(seq circular, light bool)
	onSendNAK             func(from, to circular)
	onDeliver             func(p packet)
}

type liveRecv struct {
	maxSeenSequenceNumber       circular
	lastACKSequenceNumber       circular
	lastDeliveredSequenceNumber circular
	packetList                  *list.List
	lock                        sync.RWMutex

	nPackets uint

	periodicACKInterval uint64 // config
	periodicNAKInterval uint64 // config

	lastPeriodicACK uint64
	lastPeriodicNAK uint64

	avgPayloadSize float64 // bytes

	statistics liveRecvStats

	rate struct {
		last   time.Time
		period time.Duration

		packets     uint64
		prevPackets uint64
		bytes       uint64
		prevBytes   uint64

		pps uint32
		bps uint32
	}

	sendACK func(seq circular, light bool)
	sendNAK func(from, to circular)
	deliver func(p packet)
}

func newLiveRecv(config liveRecvConfig) *liveRecv {
	r := &liveRecv{
		maxSeenSequenceNumber:       config.initialSequenceNumber.Dec(),
		lastACKSequenceNumber:       config.initialSequenceNumber.Dec(),
		lastDeliveredSequenceNumber: config.initialSequenceNumber.Dec(),
		packetList:                  list.New(),

		periodicACKInterval: config.periodicACKInterval,
		periodicNAKInterval: config.periodicNAKInterval,

		avgPayloadSize: 1456, //  5.1.2. SRT's Default LiveCC Algorithm

		sendACK: config.onSendACK,
		sendNAK: config.onSendNAK,
		deliver: config.onDeliver,
	}

	if r.sendACK == nil {
		r.sendACK = func(seq circular, light bool) {}
	}

	if r.sendNAK == nil {
		r.sendNAK = func(from, to circular) {}
	}

	if r.deliver == nil {
		r.deliver = func(p packet) {}
	}

	r.rate.last = time.Now()
	r.rate.period = time.Second

	return r
}

func (r *liveRecv) Stats() liveRecvStats {
	r.lock.RLock()
	defer r.lock.RUnlock()

	r.statistics.bytePayload = uint64(r.avgPayloadSize)

	return r.statistics
}

func (r *liveRecv) PacketRate() (pps, bps uint32) {
	r.lock.Lock()
	defer r.lock.Unlock()

	tdiff := time.Since(r.rate.last)

	if tdiff < r.rate.period {
		pps = r.rate.pps
		bps = r.rate.bps

		return
	}

	pdiff := r.rate.packets - r.rate.prevPackets
	bdiff := r.rate.bytes - r.rate.prevBytes

	r.rate.pps = uint32(float64(pdiff) / tdiff.Seconds())
	r.rate.bps = uint32(float64(bdiff) / tdiff.Seconds())

	r.rate.prevPackets, r.rate.prevBytes = r.rate.packets, r.rate.bytes
	r.rate.last = time.Now()

	pps = r.rate.pps
	bps = r.rate.bps

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

	pktLen := pkt.Len()

	r.rate.packets++
	r.rate.bytes += pktLen

	r.statistics.pktRecv++
	r.statistics.byteRecv += pktLen

	//pkt.PktTsbpdTime = pkt.Timestamp + r.delay
	if pkt.Header().retransmittedPacketFlag {
		r.statistics.pktRcvRetrans++
		r.statistics.byteRcvRetrans += pktLen
	}

	//  5.1.2. SRT's Default LiveCC Algorithm
	r.avgPayloadSize = 0.875*r.avgPayloadSize + 0.125*float64(pktLen)

	if pkt.Header().packetSequenceNumber.Lte(r.lastDeliveredSequenceNumber) {
		// too old, because up until r.lastDeliveredSequenceNumber, we already delivered
		r.statistics.pktRcvDrop++
		r.statistics.byteRcvDrop += pktLen

		return
	}

	if pkt.Header().packetSequenceNumber.Lt(r.lastACKSequenceNumber) {
		// already acknowledged, ignoring
		r.statistics.pktRcvDrop++
		r.statistics.byteRcvDrop += pktLen

		return
	}

	if pkt.Header().packetSequenceNumber.Equals(r.maxSeenSequenceNumber.Inc()) {
		// in order, the packet we expected
		r.maxSeenSequenceNumber = pkt.Header().packetSequenceNumber
	} else if pkt.Header().packetSequenceNumber.Lte(r.maxSeenSequenceNumber) {
		// out of order, is it a missing piece? put it in the correct position
		for e := r.packetList.Front(); e != nil; e = e.Next() {
			p := e.Value.(packet)

			if p.Header().packetSequenceNumber == pkt.Header().packetSequenceNumber {
				// already received (has been sent more than once), ignoring
				r.statistics.pktRcvDrop++
				r.statistics.byteRcvDrop += pktLen

				break
			} else if p.Header().packetSequenceNumber.Gt(pkt.Header().packetSequenceNumber) {
				// late arrival, this fills a gap
				r.statistics.pktRcvBuf++
				r.statistics.pktRecvUnique++

				r.statistics.byteRcvBuf += pktLen
				r.statistics.byteRecvUnique += pktLen

				r.packetList.InsertBefore(pkt, e)

				break
			}
		}

		return
	} else {
		// too far ahead, there are some missing sequence numbers, immediate NAK report
		// here we can prevent a possibly unecessary NAK with SRTO_LOXXMAXTTL
		r.sendNAK(r.maxSeenSequenceNumber.Inc(), pkt.Header().packetSequenceNumber.Dec())

		len := uint64(pkt.Header().packetSequenceNumber.Distance(r.maxSeenSequenceNumber))
		r.statistics.pktRcvLoss += len
		r.statistics.byteRcvLoss += len * uint64(r.avgPayloadSize)

		r.maxSeenSequenceNumber = pkt.Header().packetSequenceNumber
	}

	r.statistics.pktRcvBuf++
	r.statistics.pktRecvUnique++

	r.statistics.byteRcvBuf += pktLen
	r.statistics.byteRecvUnique += pktLen

	r.packetList.PushBack(pkt)
}

func (r *liveRecv) periodicACK(now uint64) (ok bool, sequenceNumber circular, lite bool) {
	r.lock.RLock()
	defer r.lock.RUnlock()

	// 4.8.1. Packet Acknowledgement (ACKs, ACKACKs)
	if now-r.lastPeriodicACK < r.periodicACKInterval {
		if r.nPackets >= 64 {
			lite = true // send light ACK
		} else {
			return
		}
	}

	minPktTsbpdTime, maxPktTsbpdTime := uint64(0), uint64(0)

	ackSequenceNumber := r.lastDeliveredSequenceNumber

	// find the sequence number up until we have all in a row.
	// where the first gap is (or at the end of the list) is where we can ACK to.
	e := r.packetList.Front()
	if e != nil {
		p := e.Value.(packet)

		minPktTsbpdTime = p.Header().pktTsbpdTime
		maxPktTsbpdTime = p.Header().pktTsbpdTime

		if p.Header().packetSequenceNumber.Equals(ackSequenceNumber.Inc()) {
			ackSequenceNumber = p.Header().packetSequenceNumber

			for e = e.Next(); e != nil; e = e.Next() {
				p = e.Value.(packet)
				if !p.Header().packetSequenceNumber.Equals(ackSequenceNumber.Inc()) {
					break
				}

				ackSequenceNumber = p.Header().packetSequenceNumber
				maxPktTsbpdTime = p.Header().pktTsbpdTime
			}
		}

		ok = true
		sequenceNumber = ackSequenceNumber.Inc()

		// keep track of the last ACK's sequence. with this we can faster ignore
		// packets that come in that have a lower sequence number.
		r.lastACKSequenceNumber = ackSequenceNumber
	}

	r.lastPeriodicACK = now
	r.nPackets = 0

	r.statistics.msRcvBuf = (maxPktTsbpdTime - minPktTsbpdTime) / 1_000

	return
}

func (r *liveRecv) periodicNAK(now uint64) (ok bool, from, to circular) {
	r.lock.RLock()
	defer r.lock.RUnlock()

	if now-r.lastPeriodicNAK < r.periodicNAKInterval {
		return
	}

	// send a periodic NAK

	ackSequenceNumber := r.lastDeliveredSequenceNumber

	// send a NAK only for the first gap.
	// alternatively send a NAK for max. X gaps because the size of the NAK packet is limited
	for e := r.packetList.Front(); e != nil; e = e.Next() {
		p := e.Value.(packet)

		if !p.Header().packetSequenceNumber.Equals(ackSequenceNumber.Inc()) {
			nackSequenceNumber := ackSequenceNumber.Inc()

			ok = true
			from = nackSequenceNumber
			to = p.Header().packetSequenceNumber.Dec()

			break
		}

		ackSequenceNumber = p.Header().packetSequenceNumber
	}

	r.lastPeriodicNAK = now

	return
}

func (r *liveRecv) Tick(now uint64) {
	if ok, sequenceNumber, lite := r.periodicACK(now); ok {
		r.sendACK(sequenceNumber, lite)
	}

	if ok, from, to := r.periodicNAK(now); ok {
		r.sendNAK(from, to)
	}

	// deliver packets whose PktTsbpdTime is ripe
	r.lock.Lock()
	defer r.lock.Unlock()

	removeList := make([]*list.Element, 0, r.packetList.Len())
	for e := r.packetList.Front(); e != nil; e = e.Next() {
		p := e.Value.(packet)

		if p.Header().packetSequenceNumber.Lte(r.lastACKSequenceNumber) && p.Header().pktTsbpdTime <= now {
			r.statistics.pktRcvBuf--
			r.statistics.byteRcvBuf -= p.Len()

			r.lastDeliveredSequenceNumber = p.Header().packetSequenceNumber

			r.deliver(p)
			removeList = append(removeList, e)
		} else {
			break
		}
	}

	for _, e := range removeList {
		r.packetList.Remove(e)
	}
}

func (r *liveRecv) SetNAKInterval(nakInterval uint64) {
	r.lock.Lock()
	defer r.lock.Unlock()

	r.periodicNAKInterval = nakInterval
}

func (r *liveRecv) String(t uint64) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("maxSeen=%d lastACK=%d lastDelivered=%d\n", r.maxSeenSequenceNumber.Val(), r.lastACKSequenceNumber.Val(), r.lastDeliveredSequenceNumber.Val()))

	r.lock.RLock()
	for e := r.packetList.Front(); e != nil; e = e.Next() {
		p := e.Value.(packet)

		b.WriteString(fmt.Sprintf("   %d @ %d (in %d)\n", p.Header().packetSequenceNumber.Val(), p.Header().pktTsbpdTime, int64(p.Header().pktTsbpdTime)-int64(t)))
	}
	r.lock.RUnlock()

	return b.String()
}
