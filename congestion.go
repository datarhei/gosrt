package srt

import (
	"container/list"
	"fmt"
	"strings"
	"sync"
)

type liveSend struct {
	nextSequenceNumber uint32

	packetList *list.List
	lossList   *list.List
	lock       sync.RWMutex

	dropInterval uint32

	deliver func(p *Packet)
}

func newLiveSend(initalSequenceNumber, dropInterval uint32) *liveSend {
	s := &liveSend{
		nextSequenceNumber: initalSequenceNumber,
		packetList:         list.New(),
		lossList:           list.New(),

		dropInterval: dropInterval, // ticks

		deliver: func(p *Packet) {},
	}

	return s
}

func (s *liveSend) push(p *Packet) {
	p.packetSequenceNumber = s.nextSequenceNumber
	s.nextSequenceNumber++

	//log("got %d @ %d\n", p.packetSequenceNumber, p.PktTsbpdTime)

	s.lock.Lock()
	s.packetList.PushBack(p)
	s.lock.Unlock()
}

func (s *liveSend) tick(now uint32) {
	//log("tick @ %d\n", now)

	// deliver packets whose PktTsbpdTime is ripe
	s.lock.Lock()
	removeList := []*list.Element{}
	for e := s.packetList.Front(); e != nil; e = e.Next() {
		p := e.Value.(*Packet)
		if p.PktTsbpdTime <= now {
			//log("delivering %d @ %d (%d bytes)\n", p.packetSequenceNumber, p.PktTsbpdTime, len(p.data))
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
		p := e.Value.(*Packet)

		if p.PktTsbpdTime+s.dropInterval <= now {
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

	for _, e := range removeList {
		s.lossList.Remove(e)
	}
	s.lock.Unlock()
}

func (s *liveSend) ack(sequenceNumber uint32) {
	//log("got ACK for %d\n", sequenceNumber)
	s.lock.Lock()
	removeList := []*list.Element{}
	for e := s.lossList.Front(); e != nil; e = e.Next() {
		p := e.Value.(*Packet)
		if p.packetSequenceNumber < sequenceNumber {
			//log("   deleting %d @ %d from losslist\n", p.packetSequenceNumber, p.PktTsbpdTime)
			removeList = append(removeList, e)
		} else {
			break
		}
	}

	for _, e := range removeList {
		s.lossList.Remove(e)
	}
	s.lock.Unlock()
}

func (s *liveSend) nak(sequenceNumber []uint32) {
	if len(sequenceNumber) == 0 {
		return
	}

	//log("got NAK for %v\n", sequenceNumber)

	s.lock.RLock()
	for e := s.lossList.Back(); e != nil; e = e.Prev() {
		p := e.Value.(*Packet)

		for i := 0; i < len(sequenceNumber); i += 2 {
			if p.packetSequenceNumber >= sequenceNumber[i] && p.packetSequenceNumber <= sequenceNumber[i+1] {
				//log("   retransmitting %d @ %d from losslist\n", p.packetSequenceNumber, p.PktTsbpdTime)
				p.retransmittedPacketFlag = true
				s.deliver(p)
			}
		}
	}
	s.lock.RUnlock()
}

type liveRecv struct {
	maxSeenSequenceNumber uint32
	lastACKSequenceNumber uint32
	packetList            *list.List
	lock                  sync.RWMutex

	delay uint32 // config
	start uint32
	ticks uint32

	nPackets uint

	periodicACKInterval uint32 // config
	periodicNAKInterval uint32 // config

	lastPeriodicACK uint32
	lastPeriodicNAK uint32

	sendACK func(seq uint32, light bool)
	sendNAK func(from, to uint32)
	deliver func(p *Packet)
}

func newLiveRecv(initialSequenceNumber, periodicACKInterval, periodicNAKInterval uint32) *liveRecv {
	r := &liveRecv{
		maxSeenSequenceNumber: initialSequenceNumber - 1,
		lastACKSequenceNumber: 0,
		packetList:            list.New(),

		periodicACKInterval: periodicACKInterval, // ticks
		periodicNAKInterval: periodicNAKInterval, // ticks
	}

	r.sendACK = func(seq uint32, light bool) {}
	r.sendNAK = func(from, to uint32) {}
	r.deliver = func(p *Packet) {}

	return r
}

func (r *liveRecv) push(packet *Packet) {
	r.nPackets++

	r.lock.Lock()
	defer r.lock.Unlock()
	//packet.PktTsbpdTime = packet.Timestamp + r.delay

	//logIn("new packet %d @ %d, expecting %d\n", packet.packetSequenceNumber, packet.PktTsbpdTime, r.maxSeenSequenceNumber + 1)

	if packet.packetSequenceNumber == r.maxSeenSequenceNumber+1 {
		r.maxSeenSequenceNumber = packet.packetSequenceNumber

		//logIn("   the packet we expected\n")
	} else if packet.packetSequenceNumber <= r.maxSeenSequenceNumber {
		//logIn("   a missing piece?\n")

		if packet.packetSequenceNumber < r.lastACKSequenceNumber {
			//logIn("   we already ACK'd this packet. ignoring\n")
			return
		}

		// put it in the correct position
		for e := r.packetList.Front(); e != nil; e = e.Next() {
			p := e.Value.(*Packet)
			if p.packetSequenceNumber == packet.packetSequenceNumber {
				// we already have this packet, ignore
				//logIn("   we already have it, but not yet ACK'd, ignoring\n")
				break
			} else if p.packetSequenceNumber > packet.packetSequenceNumber {
				r.packetList.InsertBefore(packet, e)
				//logIn("   adding it before %d @ %d\n", p.packetSequenceNumber, p.PktTsbpdTime)
				break
			}
		}

		return
	} else {
		// the sequence number is too big
		// send a NAK for all sequences that are bigger than the one we know until
		// the one we have at hand, both ends exluding.
		r.sendNAK(r.maxSeenSequenceNumber+1, packet.packetSequenceNumber-1)
		r.maxSeenSequenceNumber = packet.packetSequenceNumber

		//logIn("   there are some missing sequence numbers\n")
	}

	r.packetList.PushBack(packet)
}

func (r *liveRecv) tick(now uint32) {
	// deliver packets whose PktTsbpdTime is ripe
	r.lock.Lock()
	removeList := []*list.Element{}
	for e := r.packetList.Front(); e != nil; e = e.Next() {
		p := e.Value.(*Packet)
		if p.PktTsbpdTime <= now {
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

	if now-r.lastPeriodicACK > r.periodicACKInterval || r.nPackets >= 64 {
		// send a periodic or light ACK
		lite := false
		if r.nPackets >= 64 {
			lite = true
		}

		// find the sequence number up until we have all in a row.
		// where the first gap is (or at the end of the list) is where we can ACK to
		r.lock.RLock()
		e := r.packetList.Front()
		if e != nil {
			p := e.Value.(*Packet)

			ackSequenceNumber := p.packetSequenceNumber

			for e = e.Next(); e != nil; e = e.Next() {
				p = e.Value.(*Packet)
				if p.packetSequenceNumber != ackSequenceNumber+1 {
					break
				}

				ackSequenceNumber++
			}

			r.sendACK(ackSequenceNumber+1, lite)

			// keep track of the last ACK's sequence. with this we can faster ignore
			// packets that come in that have a lower sequence number.
			r.lastACKSequenceNumber = ackSequenceNumber
		}
		r.lock.RUnlock()

		r.lastPeriodicACK = now
		r.nPackets = 0
	}

	if now-r.lastPeriodicNAK > r.periodicNAKInterval {
		// send a periodic NAK

		// find the first sequence number which is missing and send a
		// NAK up until the latest sequence number we know.
		// this is inefficient because this will potentially trigger a re-send
		// of many packets that we already have.
		// alternatively send a NAK only for the first gap.
		// alternatively send a NAK for max. X gaps because the size of the NAK packet is limited
		r.lock.RLock()
		e := r.packetList.Front()
		if e != nil {
			p := e.Value.(*Packet)

			ackSequenceNumber := p.packetSequenceNumber

			for e = e.Next(); e != nil; e = e.Next() {
				p = e.Value.(*Packet)
				if p.packetSequenceNumber != ackSequenceNumber+1 {
					nackSequenceNumber := ackSequenceNumber + 1
					r.sendNAK(nackSequenceNumber, p.packetSequenceNumber-1)
					break
				}

				ackSequenceNumber++
			}
		}
		r.lock.RUnlock()

		r.lastPeriodicNAK = now
	}

	//logIn("@%d: %s", t, r.String(t))
}

func (r *liveRecv) String(t uint32) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("maxSeen=%d lastACK=%d\n", r.maxSeenSequenceNumber, r.lastACKSequenceNumber))

	r.lock.RLock()
	for e := r.packetList.Front(); e != nil; e = e.Next() {
		p := e.Value.(*Packet)

		b.WriteString(fmt.Sprintf("   %d @ %d (in %d)\n", p.packetSequenceNumber, p.PktTsbpdTime, int64(p.PktTsbpdTime)-int64(t)))
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
