package srt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"net"
	"sync"
	"time"
)

var EOF = errors.New("EOF")
var EAGAIN = errors.New("EAGAIN")

type Conn interface {
	RemoteAddr() net.Addr
	SocketId() uint32
	PeerSocketId() uint32
	StreamId() string
	Close()

	Read(p []byte) (n int, err error)
	Write(p []byte) (n int, err error)
}

type srtConn struct {
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

	tsbpdTimeBase uint32
	tsbpdDelay    uint32
	drift         uint32

	// Queue for packets that are coming from the network
	networkQueue     chan *packet
	stopNetworkQueue chan struct{}

	// Queue for packets that are written with WritePacket() and will be send to the network
	writeQueue     chan *packet
	stopWriteQueue chan struct{}
	writeBuffer    bytes.Buffer

	// Queue for packets that will be read locally with ReadPacket()
	readQueue  chan *packet
	readBuffer bytes.Buffer

	stopTicker chan struct{}

	send       func(p *packet)
	onShutdown func(socketId uint32)

	// Congestion control
	recv *liveRecv
	snd  *liveSend
}

func (c *srtConn) SocketId() uint32 {
	return c.socketId
}

func (c *srtConn) RemoteAddr() net.Addr {
	return c.addr
}

func (c *srtConn) PeerSocketId() uint32 {
	return c.peerSocketId
}

func (c *srtConn) StreamId() string {
	return c.streamId
}

func (c *srtConn) listenAndServe() {
	if c.send == nil {
		c.send = func(p *packet) {}
	}

	if c.onShutdown == nil {
		c.onShutdown = func(socketId uint32) {}
	}

	c.ackNumber = 1

	// 4.10.  Round-Trip Time Estimation
	c.rtt = float64((100 * time.Millisecond).Microseconds())
	c.rttVar = float64((50 * time.Millisecond).Microseconds())

	c.nakInterval = float64((20 * time.Millisecond).Microseconds())

	c.networkQueue = make(chan *packet, 1024)
	c.stopNetworkQueue = make(chan struct{})

	c.writeQueue = make(chan *packet, 1024)
	c.stopWriteQueue = make(chan struct{})

	c.readQueue = make(chan *packet, 1024)

	c.stopTicker = make(chan struct{})

	c.timeout = time.AfterFunc(2*time.Second, func() {
		log("conn %d: no more data received. shutting down\n", c.socketId)
		c.shutdown(func() {})
	})

	c.recv = newLiveRecv(c.initialPacketSequenceNumber, 10*1000, 20*1000)
	c.snd = newLiveSend(c.initialPacketSequenceNumber, 1000000)

	c.recv.sendACK = c.sendACK
	c.recv.sendNAK = c.sendNAK
	c.recv.deliver = c.deliver

	c.snd.deliver = c.send

	go c.networkQueueReader()
	go c.writeQueueReader()
	go c.ticker()
}

func (c *srtConn) ticker() {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	defer func() {
		log("conn %d: left ticker loop\n", c.socketId)
		c.stopTicker <- struct{}{}
	}()

	for {
		select {
		case <-c.stopTicker:
			return
		case t := <-ticker.C:
			tickTime := uint32(t.Sub(c.start).Microseconds())

			c.recv.tick(c.tsbpdTimeBase + tickTime)
			c.snd.tick(tickTime)
		}
	}
}

func (c *srtConn) ReadPacket() (*packet, error) {
	if c.isShutdown == true {
		return nil, EOF
	}

	select {
	case p := <-c.readQueue:
		if p == nil {
			break
		}

		return p, nil
	}

	return nil, EOF
}

func (c *srtConn) Read(b []byte) (int, error) {
	if c.readBuffer.Len() != 0 {
		return c.readBuffer.Read(b)
	}

	c.readBuffer.Reset()

	p, err := c.ReadPacket()
	if err != nil {
		return 0, err
	}

	c.readBuffer.Write(p.data)

	return c.readBuffer.Read(b)
}

func (c *srtConn) WritePacket(p *packet) error {
	if c.isShutdown == true {
		return EOF
	}

	p.addr = c.addr
	p.timestamp = uint32(time.Now().Sub(c.start).Microseconds())
	p.destinationSocketId = c.peerSocketId

	// Give the packet a deliver timestamp
	p.pktTsbpdTime = uint32(time.Now().Sub(c.start).Microseconds())

	select {
	case c.writeQueue <- p:
		return nil
	default:
	}

	return EAGAIN
}

func (c *srtConn) Write(b []byte) (int, error) {
	c.writeBuffer.Write(b)

	bufferlen := c.writeBuffer.Len()

	if bufferlen < 188 {
		return len(b), nil
	}

	for {
		n := bufferlen % 188
		if n > 7 {
			n = 7
		}

		p := &packet{
			isControlPacket:         false,
			packetSequenceNumber:    0,
			packetPositionFlag:      singlePacket,
			orderFlag:               false,
			keyBaseEncryptionFlag:   unencryptedPacket,
			retransmittedPacketFlag: false,
			messageNumber:           0,
			data:                    make([]byte, n*188),
		}

		if _, err := c.writeBuffer.Read(p.data); err != nil {
			return 0, err
		}

		if err := c.WritePacket(p); err != nil {
			return 0, err
		}

		bufferlen = c.writeBuffer.Len()
		if bufferlen < 188 {
			break
		}
	}

	if bufferlen == 0 {
		c.writeBuffer.Reset()
	}

	return len(b), nil
}

// This is where packets from the network come in
func (c *srtConn) push(p *packet) {
	if c.isShutdown == true {
		return
	}

	// Non-blocking write to the network queue
	select {
	case c.networkQueue <- p:
	default:
		log("network queue is full")
	}
}

// reads from the network queue
func (c *srtConn) networkQueueReader() {
	defer func() {
		log("conn %d: left network queue reader loop\n", c.socketId)
		c.stopNetworkQueue <- struct{}{}
	}()

	for {
		select {
		case <-c.stopNetworkQueue:
			return
		case p := <-c.networkQueue:
			c.handlePacket(p)
		}
	}
}

func (c *srtConn) writeQueueReader() {
	defer func() {
		log("conn %d: left write queue reader loop\n", c.socketId)
		c.stopWriteQueue <- struct{}{}
	}()

	for {
		select {
		case <-c.stopWriteQueue:
			return
		case p := <-c.writeQueue:
			// Put the packet into the send congestion control
			c.snd.push(p)
		}
	}
}

func (c *srtConn) deliver(p *packet) {
	if c.isShutdown == true {
		return
	}

	// Non-blocking write to the read queue
	select {
	case c.readQueue <- p:
	default:
		log("readQueue was blocking, dropping packet\n")
	}
}

func (c *srtConn) handlePacket(p *packet) {
	if p == nil {
		return
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
		} else if p.controlType == CTRLTYPE_ACKACK {
			c.handleACKACK(p)
		}
	} else {
		p.pktTsbpdTime = c.tsbpdTimeBase + p.timestamp + c.tsbpdDelay + c.drift
		c.recv.push(p)
	}
}

func (c *srtConn) handleKeepAlive(p *packet) {
	log("handle keepalive\n")

	p.timestamp = uint32(time.Now().Sub(c.start).Microseconds())
	p.destinationSocketId = c.peerSocketId

	c.send(p)
}

func (c *srtConn) handleShutdown(p *packet) {
	log("handle shutdown\n")

	c.close()
}

func (c *srtConn) handleACK(p *packet) {
	cif := &cifACK{}

	if err := cif.Unmarshal(p.data); err != nil {
		return
	}

	//logIn("%s\n", cif.String())

	c.snd.ack(cif.lastACKPacketSequenceNumber)

	if cif.isLite == false && cif.isSmall == false {
		c.sendACKACK(p.typeSpecific)
	}
}

func (c *srtConn) handleNAK(p *packet) {
	cif := &cifNAK{}

	if err := cif.Unmarshal(p.data); err != nil {
		return
	}

	//logIn("%s\n", cif.String())

	c.snd.nak(cif.lostPacketSequenceNumber)
}

func (c *srtConn) handleACKACK(p *packet) {
	c.ackLock.RLock()
	defer c.ackLock.RUnlock()

	// p.typeSpecific is the ACKNumber
	if p.typeSpecific != c.ackNumber-1 {
		return
	}

	c.recalculateRTT(time.Now().Sub(c.ackLast))
}

func (c *srtConn) recalculateRTT(rtt time.Duration) {
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

func (c *srtConn) sendShutdown() {
	p := &packet{}

	p.addr = c.addr
	p.isControlPacket = true

	p.controlType = CTRLTYPE_SHUTDOWN
	p.typeSpecific = 0

	p.timestamp = uint32(time.Now().Sub(c.start).Microseconds())
	p.destinationSocketId = c.peerSocketId

	p.data = make([]byte, 4)

	binary.BigEndian.PutUint32(p.data[0:], 0)

	c.send(p)
}

func (c *srtConn) sendNAK(from, to uint32) {
	p := &packet{}

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
}

func (c *srtConn) sendACK(seq uint32, lite bool) {
	p := &packet{}

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
}

func (c *srtConn) sendACKACK(ackSequence uint32) {
	p := &packet{}

	p.addr = c.addr
	p.isControlPacket = true

	p.controlType = CTRLTYPE_ACKACK

	p.timestamp = uint32(time.Now().Sub(c.start).Microseconds())
	p.destinationSocketId = c.peerSocketId

	p.typeSpecific = ackSequence

	c.send(p)
}

func (c *srtConn) Close() {
	c.close()
}

func (c *srtConn) close() {
	if c.isShutdown == true {
		return
	}

	c.isShutdown = true

	log("conn %d: stopping timeout\n", c.socketId)

	c.timeout.Stop()

	log("conn %d: sending shutdown message to peer\n", c.socketId)

	c.sendShutdown()

	log("conn %d: stopping reader\n", c.socketId)

	// send nil to the readQueue in order to abort any pending ReadPacket call
	c.readQueue <- nil

	log("conn %d: stopping network reader\n", c.socketId)

	c.stopNetworkQueue <- struct{}{}

	select {
	case <-c.stopNetworkQueue:
	}

	log("conn %d: stopping writer\n", c.socketId)

	c.stopWriteQueue <- struct{}{}

	select {
	case <-c.stopWriteQueue:
	}

	log("conn %d: stopping ticker\n", c.socketId)

	c.stopTicker <- struct{}{}

	select {
	case <-c.stopTicker:
	}

	log("conn %d: closing queues\n", c.socketId)

	close(c.networkQueue)
	close(c.readQueue)
	close(c.writeQueue)

	log("conn %d: shutdown\n", c.socketId)

	go func() {
		c.onShutdown(c.socketId)
	}()
}

func (c *srtConn) shutdown(callback func()) {
	c.close()

	go func() {
		callback()
	}()
}
