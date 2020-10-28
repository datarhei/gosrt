package main

import (
	"encoding/binary"
	//"encoding/hex"
	"net"
	"sync"
	"time"
	"container/list"
)

type SubscriberConn struct {
	addr  net.Addr
	start time.Time

	isShutdown bool

	socketId     uint32
	peerSocketId uint32

	streamId string

	timeout *time.Timer

	rtt    float64
	rttVar float64

	nakInterval float64

	ackLock   sync.RWMutex
	ackNumber uint32
	ackLast   time.Time

	initialPacketSequenceNumber uint32

	TsbpdTimeBase uint32
	TsbpdDelay    uint32
	Drift         uint32

	packetQueue chan *Packet
	deliverQueue chan *Packet
	deliverTo PacketWriter

	stopReader chan struct{}
	stopWriter chan struct{}
	stopTicker chan struct{}

	send          func(p *Packet)
	createPacket  func() *Packet
	recyclePacket func(p *Packet)
	onShutdown    func(socketId uint32, streamId string)

	deliverData bool

	snd *SEND
}

func (c *SubscriberConn) ListenAndServe() {
	c.ackNumber = 1

	// 4.10.  Round-Trip Time Estimation
	c.rtt = float64((100 * time.Millisecond).Microseconds())
	c.rttVar = float64((50 * time.Millisecond).Microseconds())

	c.nakInterval = float64((20 * time.Millisecond).Microseconds())

	c.stopReader = make(chan struct{}, 1)
	c.stopWriter = make(chan struct{}, 1)
	c.stopTicker = make(chan struct{}, 1)

	c.packetQueue = make(chan *Packet, 128)
	c.deliverQueue = make(chan *Packet, 1024)

	c.timeout = time.AfterFunc(2 * time.Second, func() {
		log("conn %d: no more data received. shutting down\n", c.socketId)
		c.Shutdown(func() {})
	})

	c.snd = NewSEND(c.initialPacketSequenceNumber, 1000000)

	c.deliverTo = &NullWriter{}

	c.snd.deliver = c.deliver

	go c.reader()
	go c.writer()
	go c.ticker()
}

func (c *SubscriberConn) SocketId() uint32 {
	return c.socketId;
}

func (c *SubscriberConn) RemoteAddr() net.Addr {
	return c.addr
}

func (c *SubscriberConn) PeerSocketId() uint32 {
	return c.peerSocketId;
}

func (c *SubscriberConn) StreamId() string {
	return c.streamId;
}

func (c *SubscriberConn) Push(p *Packet) {
	if c.isShutdown == true {
		return
	}

	select {
	case c.packetQueue <- p:
	default:
	}
}

func (c *SubscriberConn) reader() {
	defer func() {
		log("conn %d: left reader loop\n", c.socketId)
	}()

	for {
		select {
		case <-c.stopReader:
			return
		case p := <-c.packetQueue:
			c.handlePacket(p)
		}
	}
}

func (c *SubscriberConn) writer() {
	defer func() {
		log("conn %d: left writer loop\n", c.socketId)
	}()

	for {
		select {
		case <-c.stopWriter:
			return
		case p := <-c.deliverQueue:
			//log("sending off\n%s\n", p.String())
			c.send(p)
		}
	}
}

func (c *SubscriberConn) handlePacket(p *Packet) {
	if p == nil {
		return
	}

	if !c.timeout.Stop() {
		<-c.timeout.C
	}
	c.timeout.Reset(2 * time.Second)

	if p.isControlPacket == true {
		if p.controlType == CTRLTYPE_KEEPALIVE {
			c.handleKeepAlive(p)
		} else if p.controlType == CTRLTYPE_SHUTDOWN {
			c.handleShutdown(p)
		} else if p.controlType == CTRLTYPE_NAK {
			c.handleNAK(p)
		} else if p.controlType == CTRLTYPE_ACK {
			c.handleACK(p)
		}
	} else {
		p.PktTsbpdTime = uint32(time.Now().Sub(c.start).Microseconds())

		c.snd.push(p)
	}
}

func (c *SubscriberConn) handleKeepAlive(p *Packet) {
	log("handle keepalive\n")

	p.timestamp = uint32(time.Now().Sub(c.start).Microseconds())
	p.destinationSocketId = c.peerSocketId

	c.send(p)
}

func (c *SubscriberConn) handleShutdown(p *Packet) {
	log("handle shutdown\n")

	c.recyclePacket(p)

	c.Shutdown(func() {})
}

func (c *SubscriberConn) ticker() {
	ticker := time.NewTicker(1 * time.Millisecond)
	defer ticker.Stop()
	defer func() {
		log("conn %d: left ticker loop\n", c.socketId)
	}()

	for {
		select {
		case <-c.stopTicker:
			return
		case t := <-ticker.C:
			tickTime := uint32(t.Sub(c.start).Microseconds())
			c.snd.tick(tickTime)
		}
	}
}

func (c *SubscriberConn) DeliverTo(w PacketWriter) {
	// Don't do anything
}

func (c *SubscriberConn) deliver(p *Packet) {
	p.addr = c.addr
	p.destinationSocketId = c.peerSocketId
	p.timestamp = uint32(time.Now().Sub(c.start).Microseconds())

	select {
	case c.deliverQueue <- p:
	default:
	}
}

func (c *SubscriberConn) sendACKACK(ackSequence uint32) {
	p := c.createPacket()

	p.addr = c.addr
	p.isControlPacket = true

	p.controlType = CTRLTYPE_ACKACK

	p.timestamp = uint32(time.Now().Sub(c.start).Microseconds())
	p.destinationSocketId = c.peerSocketId

	p.typeSpecific = ackSequence

	c.send(p)

	//c.recyclePacket(p)
}

func (c *SubscriberConn) sendShutdown() {
	p := c.createPacket()

	p.addr = c.addr
	p.isControlPacket = true

	p.controlType = 5 // Shutdown
	p.typeSpecific = 0

	p.timestamp = uint32(time.Now().Sub(c.start).Microseconds())
	p.destinationSocketId = c.peerSocketId

	p.data = make([]byte, 4)

	binary.BigEndian.PutUint32(p.data[0:], 0)

	c.send(p)

	c.recyclePacket(p)
}

func (c *SubscriberConn) handleACK(p *Packet) {
	cif := &CIFACK{}

	if err := cif.Unmarshal(p.data); err != nil {
		return
	}

	//logIn("%s\n", cif.String())

	c.snd.ack(cif.lastACKPacketSequenceNumber)

	if cif.isLite == false && cif.isSmall == false {
		c.sendACKACK(p.typeSpecific)
	}
}

func (c *SubscriberConn) handleNAK(p *Packet) {
	cif := &CIFNAK{}

	if err := cif.Unmarshal(p.data); err != nil {
		return
	}

	//logIn("%s\n", cif.String())

	c.snd.nak(cif.lostPacketSequenceNumber)
}

func (c *SubscriberConn) Close() {
	c.Shutdown(func(){})
}

func (c *SubscriberConn) Shutdown(bla func()) {
	c.isShutdown = true

	log("conn %d: stopping timeout\n", c.socketId)

	c.timeout.Stop()

	log("conn %d: sending shutdown message to peer\n", c.socketId)

	c.sendShutdown()

	log("conn %d: stopping reader\n", c.socketId)

	c.stopReader <- struct{}{}

	log("conn %d: stopping writer\n", c.socketId)

	c.stopWriter <- struct{}{}

	log("conn %d: stopping ticker\n", c.socketId)

	c.stopTicker <- struct{}{}

	log("conn %d: closing packet queue\n", c.socketId)

	close(c.packetQueue)
	close(c.deliverQueue)

	log("conn %d: shutdown\n", c.socketId)

	go func() {
		c.onShutdown(c.socketId, c.streamId)
		bla()
	}()
}

type SEND struct {
	nextSequenceNumber uint32

	packetList *list.List
	lossList *list.List
	lock sync.RWMutex

	dropInterval uint32

	deliver func(p *Packet)
}

func NewSEND(initalSequenceNumber, dropInterval uint32) *SEND {
	s := &SEND{
		nextSequenceNumber: initalSequenceNumber,
		packetList: list.New(),
		lossList: list.New(),

		dropInterval: dropInterval, // ticks

		deliver: func(p *Packet) {},
	}

	return s
}

func (s *SEND) push(p *Packet) {
	p.packetSequenceNumber = s.nextSequenceNumber
	s.nextSequenceNumber++

	//log("got %d @ %d\n", p.packetSequenceNumber, p.PktTsbpdTime)

	s.lock.Lock()
	s.packetList.PushBack(p)
	s.lock.Unlock()
}

func (s *SEND) tick(now uint32) {
	//log("tick @ %d\n", now)

	// deliver packets whose PktTsbpdTime is ripe
	s.lock.Lock()
	removeList := []*list.Element{}
	for e := s.packetList.Front(); e != nil; e = e.Next() {
		p := e.Value.(*Packet)
		if p.PktTsbpdTime <= now {
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

		if p.PktTsbpdTime + s.dropInterval <= now {
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

func (s *SEND) ack(sequenceNumber uint32) {
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

func (s *SEND) nak(sequenceNumber []uint32) {
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
