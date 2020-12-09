package old

import (
	"encoding/binary"
	//"encoding/hex"
	"fmt"
	"math"
	"net"
	"sync"
	"time"
	"container/list"
	"strings"
)

type NullWriter struct {}
func (n *NullWriter) Write(p *Packet) {
	log("writing to NullWriter\n")
}

type PublisherConn struct {
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

	recv *RECV
}

func (c *PublisherConn) ListenAndServe() {
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

	if c.deliverTo == nil {
		c.deliverTo = &NullWriter{}
	}

	c.recv = NewRECV(c.initialPacketSequenceNumber, 10 * 1000, 20 * 1000)

	c.recv.sendACK = c.sendACK
	c.recv.sendNAK = c.sendNAK
	c.recv.deliver = c.deliver

	go c.reader()
	go c.writer()
	go c.ticker()
}

func (c *PublisherConn) SocketId() uint32 {
	return c.socketId;
}

func (c *PublisherConn) RemoteAddr() net.Addr {
	return c.addr
}

func (c *PublisherConn) PeerSocketId() uint32 {
	return c.peerSocketId;
}

func (c *PublisherConn) StreamId() string {
	return c.streamId;
}

func (c *PublisherConn) Push(p *Packet) {
	if c.isShutdown == true {
		return
	}

	select {
	case c.packetQueue <- p:
	default:
	}
}

func (c *PublisherConn) reader() {
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

func (c *PublisherConn) writer() {
	defer func() {
		log("conn %d: left writer loop\n", c.socketId)
	}()

	for {
		select {
		case <-c.stopWriter:
			return
		case p := <-c.deliverQueue:
			c.deliverTo.Write(p)
			//binary.Write(os.Stdout, binary.BigEndian, p.data)
		}
	}
}

func (c *PublisherConn) handlePacket(p *Packet) {
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
		} else if p.controlType == CTRLTYPE_ACKACK {
			c.handleACKACK(p)
		}
	} else {
		p.PktTsbpdTime = c.TsbpdTimeBase + p.timestamp + c.TsbpdDelay + c.Drift

		c.recv.push(p)
	}
}

func (c *PublisherConn) handleKeepAlive(p *Packet) {
	log("handle keepalive\n")

	p.timestamp = uint32(time.Now().Sub(c.start).Microseconds())
	p.destinationSocketId = c.peerSocketId

	c.send(p)
}

func (c *PublisherConn) handleShutdown(p *Packet) {
	log("handle shutdown\n")

	c.recyclePacket(p)

	c.Shutdown(func() {})
}

func (c *PublisherConn) ticker() {
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
			tickTime := c.TsbpdTimeBase + uint32(t.Sub(c.start).Microseconds())
			c.recv.tick(tickTime)
		}
	}
}

func (c *PublisherConn) DeliverTo(w PacketWriter) {
	log("delivering to new PacketWriter\n")
	c.deliverTo = w
}

func (c *PublisherConn) deliver(p *Packet) {
	select {
	case c.deliverQueue <- p:
	default:
	}

	return
}

func (c *PublisherConn) sendNAK(from, to uint32) {
	p := c.createPacket()

	p.addr = c.addr
	p.isControlPacket = true

	p.controlType = CTRLTYPE_NAK

	p.timestamp = uint32(time.Now().Sub(c.start).Microseconds())
	p.destinationSocketId = c.peerSocketId

	// Appendix A
	if from == to {
		p.data = make([]byte, 4)

		binary.BigEndian.PutUint32(p.data[0:], from)
	} else {
		p.data = make([]byte, 8)

		from |= 0b10000000_00000000_00000000_00000000

		binary.BigEndian.PutUint32(p.data[0:], from)
		binary.BigEndian.PutUint32(p.data[4:], to)
	}

	c.send(p)

	c.recyclePacket(p)
}

func (c *PublisherConn) sendACK(seq uint32, lite bool) {
	p := c.createPacket()

	p.addr = c.addr
	p.isControlPacket = true

	p.controlType = CTRLTYPE_ACK

	p.timestamp = uint32(time.Now().Sub(c.start).Microseconds())
	p.destinationSocketId = c.peerSocketId

	if lite == true {
		p.typeSpecific = 0

		p.data = make([]byte, 4)

		binary.BigEndian.PutUint32(p.data[0:], seq)
	} else {
		p.typeSpecific = c.ackNumber

		p.data = make([]byte, 28)

		binary.BigEndian.PutUint32(p.data[0:], seq)
		binary.BigEndian.PutUint32(p.data[4:], uint32(c.rtt))
		binary.BigEndian.PutUint32(p.data[8:], uint32(c.rttVar))
		binary.BigEndian.PutUint32(p.data[12:], 100) // available buffer size (packets)
		binary.BigEndian.PutUint32(p.data[16:], 100) // packets receiving rate (packets/s)
		binary.BigEndian.PutUint32(p.data[20:], 100) // estimated link capacity (packets/s)
		binary.BigEndian.PutUint32(p.data[24:], 100) // receiving rate (bytes/s)
	}

	c.ackNumber++
	c.ackLast = time.Now()

	c.send(p)

	c.recyclePacket(p)
}

func (c *PublisherConn) sendShutdown() {
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

func (c *PublisherConn) handleACKACK(p *Packet) {
	c.ackLock.RLock()
	defer c.ackLock.RUnlock()

	// p.typeSpecific is the ACKNumber
	if p.typeSpecific != c.ackNumber-1 {
		return
	}

	c.recalculateRTT(time.Now().Sub(c.ackLast))
}

func (c *PublisherConn) recalculateRTT(rtt time.Duration) {
	// 4.10.  Round-Trip Time Estimation
	lastRTT := float64(rtt.Microseconds())

	c.rtt = c.rtt*0.875 + lastRTT*0.125
	c.rttVar = c.rttVar*0.75 + math.Abs(c.rtt-lastRTT)*0.25

	// 4.8.2.  Packet Retransmission (NAKs)
	nakInterval := (c.rtt + 4*c.rttVar) / 2
	if nakInterval < 20000 {
		c.nakInterval = 20000
	} else {
		c.nakInterval = nakInterval
	}

	//logIn("# RTT=%.0f RTTVar=%.0f NAKInterval=%.0f\n", c.rtt, c.rttVar, c.nakInterval)
}

func (c *PublisherConn) Close() {
	c.Shutdown(func(){})
}

func (c *PublisherConn) Shutdown(bla func()) {
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

type RECV struct {
	maxSeenSequenceNumber uint32
	lastACKSequenceNumber uint32
	packetList *list.List
	lock sync.RWMutex

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

func NewRECV(initialSequenceNumber, periodicACKInterval, periodicNAKInterval uint32) *RECV {
	r := &RECV{
		maxSeenSequenceNumber: initialSequenceNumber - 1,
		lastACKSequenceNumber: 0,
		packetList: list.New(),

		periodicACKInterval: periodicACKInterval, // ticks
		periodicNAKInterval: periodicNAKInterval, // ticks
	}

	r.sendACK = func(seq uint32, light bool) {}
	r.sendNAK = func(from, to uint32) {}
	r.deliver = func(p *Packet) {}

	return r
}

func (r *RECV) push(packet *Packet) {
	r.nPackets++

	r.lock.Lock()
	defer r.lock.Unlock()
	//packet.PktTsbpdTime = packet.Timestamp + r.delay

	//logIn("new packet %d @ %d, expecting %d\n", packet.packetSequenceNumber, packet.PktTsbpdTime, r.maxSeenSequenceNumber + 1)

	if packet.packetSequenceNumber == r.maxSeenSequenceNumber + 1 {
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
		r.sendNAK(r.maxSeenSequenceNumber + 1, packet.packetSequenceNumber - 1)
		r.maxSeenSequenceNumber = packet.packetSequenceNumber

		//logIn("   there are some missing sequence numbers\n")
	}

	r.packetList.PushBack(packet)
}

func (r *RECV) tick(now uint32) {
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

	if now - r.lastPeriodicACK > r.periodicACKInterval || r.nPackets >= 64 {
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
				if p.packetSequenceNumber != ackSequenceNumber + 1 {
					break
				}

				ackSequenceNumber++
			}

			r.sendACK(ackSequenceNumber + 1, lite)

			// keep track of the last ACK's sequence. with this we can faster ignore
			// packets that come in that have a lower sequence number.
			r.lastACKSequenceNumber = ackSequenceNumber
		}
		r.lock.RUnlock()

		r.lastPeriodicACK = now
		r.nPackets = 0
	}

	if now - r.lastPeriodicNAK > r.periodicNAKInterval {
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
				if p.packetSequenceNumber != ackSequenceNumber + 1 {
					nackSequenceNumber := ackSequenceNumber + 1
					r.sendNAK(nackSequenceNumber, p.packetSequenceNumber - 1)
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

func (r *RECV) String(t uint32) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("maxSeen=%d lastACK=%d\n", r.maxSeenSequenceNumber, r.lastACKSequenceNumber))

	r.lock.RLock()
	for e := r.packetList.Front(); e != nil; e = e.Next() {
		p := e.Value.(*Packet)

		b.WriteString(fmt.Sprintf("   %d @ %d (in %d)\n", p.packetSequenceNumber, p.PktTsbpdTime, int64(p.PktTsbpdTime) - int64(t)))
	}
	r.lock.RUnlock()

	return b.String()
}
