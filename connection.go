// Copyright 2020 FOSS GmbH. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package srt

import (
	"bytes"
	"io"
	"math"
	"net"
	gosync "sync"
	"time"

	//"os"

	"github.com/datarhei/gosrt/sync"
)

type Conn interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)

	Close() error

	LocalAddr() net.Addr
	RemoteAddr() net.Addr

	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error

	SocketId() uint32
	PeerSocketId() uint32
	StreamId() string

	Stats() ConnStats
}

type srtConnStatsCounter struct {
	keepalive uint64
	shutdown  uint64
	ack       uint64
	ackack    uint64
	nak       uint64
	km        uint64
	invalid   uint64
}

type srtConnStats struct {
	send    srtConnStatsCounter
	receive srtConnStatsCounter
}

// Check if we implemenet the net.Conn interface
var _ net.Conn = &srtConn{}

type srtConn struct {
	localAddr  net.Addr
	remoteAddr net.Addr

	start time.Time

	isShutdown bool
	closeOnce  gosync.Once

	socketId     uint32
	peerSocketId uint32

	config Config

	crypto                 *crypto
	keyBaseEncryption      packetEncryption
	kmPreAnnounceCountdown uint64
	kmRefreshCountdown     uint64
	kmConfirmed            bool

	peerIdleTimeout *time.Timer

	rtt    float64
	rttVar float64

	nakInterval float64

	ackLock       gosync.RWMutex
	ackNumbers    map[uint32]time.Time
	nextACKNumber circular

	initialPacketSequenceNumber circular

	tsbpdTimeBase       uint64
	tsbpdWrapPeriod     bool
	tsbpdTimeBaseOffset uint64
	tsbpdDelay          uint64
	tsbpdDrift          uint64

	// Queue for packets that are coming from the network
	networkQueue     chan packet
	stopNetworkQueue sync.Stopper

	// Queue for packets that are written with WritePacket() and will be send to the network
	writeQueue     chan packet
	stopWriteQueue sync.Stopper
	writeBuffer    bytes.Buffer
	writeData      []byte

	// Queue for packets that will be read locally with ReadPacket()
	readQueue  chan packet
	readBuffer bytes.Buffer

	stopTicker sync.Stopper

	onSend     func(p packet)
	onShutdown func(socketId uint32)

	tick time.Duration

	// Congestion control
	recv *liveRecv
	snd  *liveSend

	statistics srtConnStats

	debug struct {
		expectedRcvPacketSequenceNumber  circular
		expectedReadPacketSequenceNumber circular
	}
}

type srtConnConfig struct {
	localAddr                   net.Addr
	remoteAddr                  net.Addr
	config                      Config
	start                       time.Time
	socketId                    uint32
	peerSocketId                uint32
	tsbpdTimeBase               uint64
	tsbpdDelay                  uint64
	initialPacketSequenceNumber circular
	crypto                      *crypto
	keyBaseEncryption           packetEncryption
	onSend                      func(p packet)
	onShutdown                  func(socketId uint32)
}

func newSRTConn(config srtConnConfig) *srtConn {
	c := &srtConn{
		localAddr:                   config.localAddr,
		remoteAddr:                  config.remoteAddr,
		config:                      config.config,
		start:                       config.start,
		socketId:                    config.socketId,
		peerSocketId:                config.peerSocketId,
		tsbpdTimeBase:               config.tsbpdTimeBase,
		tsbpdDelay:                  config.tsbpdDelay,
		initialPacketSequenceNumber: config.initialPacketSequenceNumber,
		crypto:                      config.crypto,
		keyBaseEncryption:           config.keyBaseEncryption,
		onSend:                      config.onSend,
		onShutdown:                  config.onShutdown,
	}

	if c.onSend == nil {
		c.onSend = func(p packet) {}
	}

	if c.onShutdown == nil {
		c.onShutdown = func(socketId uint32) {}
	}

	c.nextACKNumber = newCircular(1, MAX_TIMESTAMP)
	c.ackNumbers = make(map[uint32]time.Time)

	c.kmPreAnnounceCountdown = c.config.KMRefreshRate - c.config.KMPreAnnounce
	c.kmRefreshCountdown = c.config.KMRefreshRate

	// 4.10.  Round-Trip Time Estimation
	c.rtt = float64((100 * time.Millisecond).Microseconds())
	c.rttVar = float64((50 * time.Millisecond).Microseconds())

	c.nakInterval = float64((20 * time.Millisecond).Microseconds())

	c.networkQueue = make(chan packet, 1024)
	c.stopNetworkQueue = sync.NewStopper()

	c.writeQueue = make(chan packet, 1024)
	c.stopWriteQueue = sync.NewStopper()
	c.writeData = make([]byte, int(c.config.PayloadSize))

	c.readQueue = make(chan packet, 1024)

	c.stopTicker = sync.NewStopper()

	c.peerIdleTimeout = time.AfterFunc(c.config.PeerIdleTimeout, func() {
		log("conn %d: no more data received from peer for %s. shutting down\n", c.socketId, c.config.PeerIdleTimeout)
		go c.close()
	})

	c.tick = 10 * time.Millisecond

	// 4.8.1.  Packet Acknowledgement (ACKs, ACKACKs) -> periodicACK = 10 milliseconds
	// 4.8.2.  Packet Retransmission (NAKs) -> periodicNAK at least 20 milliseconds
	c.recv = newLiveRecv(liveRecvConfig{
		initialSequenceNumber: c.initialPacketSequenceNumber,
		periodicACKInterval:   10000,
		periodicNAKInterval:   20000,
	})

	c.recv.sendACK = c.sendACK
	c.recv.sendNAK = c.sendNAK
	c.recv.deliver = c.deliver

	// 4.6.  Too-Late Packet Drop -> 125% of SRT latency, at least 1 second
	c.snd = newLiveSend(liveSendConfig{
		initialSequenceNumber: c.initialPacketSequenceNumber,
		dropInterval:          uint64(c.config.SendDropDelay.Microseconds()),
		maxBW:                 c.config.MaxBW,
		inputBW:               c.config.InputBW,
		minInputBW:            c.config.MinInputBW,
		overheadBW:            c.config.OverheadBW,
	})

	c.snd.deliver = c.pop

	go c.networkQueueReader()
	go c.writeQueueReader()
	go c.ticker()

	c.debug.expectedRcvPacketSequenceNumber = c.initialPacketSequenceNumber
	c.debug.expectedReadPacketSequenceNumber = c.initialPacketSequenceNumber

	return c
}

func (c *srtConn) LocalAddr() net.Addr {
	addr, _ := net.ResolveUDPAddr("udp", c.localAddr.String())
	return addr
}

func (c *srtConn) RemoteAddr() net.Addr {
	addr, _ := net.ResolveUDPAddr("udp", c.remoteAddr.String())
	return addr
}

func (c *srtConn) SocketId() uint32 {
	return c.socketId
}

func (c *srtConn) PeerSocketId() uint32 {
	return c.peerSocketId
}

func (c *srtConn) StreamId() string {
	return c.config.StreamId
}

func (c *srtConn) ticker() {
	ticker := time.NewTicker(c.tick)
	defer ticker.Stop()
	defer func() {
		log("conn %d: left ticker loop\n", c.socketId)
		c.stopTicker.Done()
	}()

	for {
		select {
		case <-c.stopTicker.Check():
			return
		case t := <-ticker.C:
			tickTime := uint64(t.Sub(c.start).Microseconds())

			c.recv.Tick(c.tsbpdTimeBase + tickTime)
			c.snd.Tick(tickTime)
		}
	}
}

func (c *srtConn) ReadPacket() (packet, error) {
	if c.isShutdown {
		return nil, io.EOF
	}

	p := <-c.readQueue
	if p == nil {
		return nil, io.EOF
	}

	if p.Header().packetSequenceNumber.Gt(c.debug.expectedReadPacketSequenceNumber) {
		log("lost packets. got: %d, expected: %d (%d)\n", p.Header().packetSequenceNumber.Val(), c.debug.expectedReadPacketSequenceNumber.Val(), c.debug.expectedReadPacketSequenceNumber.Distance(p.Header().packetSequenceNumber))
	} else if p.Header().packetSequenceNumber.Lt(c.debug.expectedReadPacketSequenceNumber) {
		log("packet out of order. got: %d, expected: %d (%d)\n", p.Header().packetSequenceNumber.Val(), c.debug.expectedReadPacketSequenceNumber.Val(), c.debug.expectedReadPacketSequenceNumber.Distance(p.Header().packetSequenceNumber))
		return nil, io.EOF
	}

	c.debug.expectedReadPacketSequenceNumber = p.Header().packetSequenceNumber.Inc()

	return p, nil

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

	c.readBuffer.Write(p.Data())

	// The packet is out of congestion control and written to the read buffer
	p.Decommission()

	return c.readBuffer.Read(b)
}

func (c *srtConn) WritePacket(p packet) error {
	if c.isShutdown {
		return io.EOF
	}

	if p.Header().isControlPacket {
		// Ignore control packets
		return nil
	}

	_, err := c.Write(p.Data())
	if err != nil {
		return err
	}

	return nil
}

func (c *srtConn) Write(b []byte) (int, error) {
	c.writeBuffer.Write(b)

	for {
		n, err := c.writeBuffer.Read(c.writeData)
		if err != nil {
			return 0, err
		}

		p := newPacket(nil, nil)

		p.SetData(c.writeData[:n])

		p.Header().isControlPacket = false
		// Give the packet a deliver timestamp
		p.Header().pktTsbpdTime = c.getTimestamp()

		if c.isShutdown {
			return 0, io.EOF
		}

		select {
		case c.writeQueue <- p:
		default:
			return 0, io.EOF
		}

		if c.writeBuffer.Len() == 0 {
			break
		}
	}

	c.writeBuffer.Reset()

	return len(b), nil
}

// This is where packets come in from the network
func (c *srtConn) push(p packet) {
	if c.isShutdown {
		return
	}

	// Non-blocking write to the network queue
	select {
	case c.networkQueue <- p:
	default:
		log("network queue is full\n")
	}
}

func (c *srtConn) getTimestamp() uint64 {
	return uint64(time.Since(c.start).Microseconds())
}

func (c *srtConn) getTimestampForPacket() uint32 {
	return uint32(c.getTimestamp() & uint64(MAX_TIMESTAMP))
}

// This is where packets go out to the network
func (c *srtConn) pop(p packet) {
	p.Header().addr = c.remoteAddr
	p.Header().destinationSocketId = c.peerSocketId

	if !p.Header().isControlPacket {
		if c.crypto != nil {
			p.Header().keyBaseEncryptionFlag = c.keyBaseEncryption
			c.crypto.EncryptOrDecryptPayload(p.Data(), p.Header().keyBaseEncryptionFlag, p.Header().packetSequenceNumber.Val())

			c.kmPreAnnounceCountdown--
			c.kmRefreshCountdown--

			if c.kmPreAnnounceCountdown == 0 && !c.kmConfirmed {
				c.sendKMRequest()

				// Resend the request until we get a response
				c.kmPreAnnounceCountdown = c.config.KMPreAnnounce/10 + 1
			}

			if c.kmRefreshCountdown == 0 {
				c.kmPreAnnounceCountdown = c.config.KMRefreshRate - c.config.KMPreAnnounce
				c.kmRefreshCountdown = c.config.KMRefreshRate

				// Switch the keys
				c.keyBaseEncryption = c.keyBaseEncryption.Opposite()

				c.kmConfirmed = false
			}

			if c.kmRefreshCountdown == c.config.KMRefreshRate-c.config.KMPreAnnounce {
				// Decommission the previous key, resp. create a new SEK that will
				// be used in the next switch.
				c.crypto.GenerateSEK(c.keyBaseEncryption.Opposite())
			}
		}
	}

	// Send the packet on the wire
	c.onSend(p)
}

// reads from the network queue
func (c *srtConn) networkQueueReader() {
	defer func() {
		log("conn %d: left network queue reader loop\n", c.socketId)
		c.stopNetworkQueue.Done()
	}()

	for {
		select {
		case <-c.stopNetworkQueue.Check():
			return
		case p := <-c.networkQueue:
			c.handlePacket(p)
		}
	}
}

// writes to send congestion control
func (c *srtConn) writeQueueReader() {
	defer func() {
		log("conn %d: left write queue reader loop\n", c.socketId)
		c.stopWriteQueue.Done()
	}()

	for {
		select {
		case <-c.stopWriteQueue.Check():
			return
		case p := <-c.writeQueue:
			// Put the packet into the send congestion control
			c.snd.Push(p)
		}
	}
}

// writes to the read queue
func (c *srtConn) deliver(p packet) {
	if c.isShutdown {
		return
	}

	// Non-blocking write to the read queue
	select {
	case c.readQueue <- p:
	default:
		log("readQueue was blocking, dropping packet\n")
	}
}

func (c *srtConn) handlePacket(p packet) {
	if p == nil {
		return
	}

	c.peerIdleTimeout.Reset(c.config.PeerIdleTimeout)

	header := p.Header()

	if header.isControlPacket {
		if header.controlType == CTRLTYPE_KEEPALIVE {
			c.handleKeepAlive(p)
		} else if header.controlType == CTRLTYPE_SHUTDOWN {
			c.handleShutdown(p)
		} else if header.controlType == CTRLTYPE_NAK {
			c.handleNAK(p)
		} else if header.controlType == CTRLTYPE_ACK {
			c.handleACK(p)
		} else if header.controlType == CTRLTYPE_ACKACK {
			c.handleACKACK(p)
		} else if header.controlType == CTRLTYPE_USER {
			// 3.2.2.  Key Material
			if header.subType == EXTTYPE_KMREQ {
				c.handleKMRequest(p)
			} else if header.subType == EXTTYPE_KMRSP {
				c.handleKMResponse(p)
			}
		}
	} else {
		/*
			if p.packetSequenceNumber.Gt(c.debug.expectedRcvPacketSequenceNumber) == true {
				log("recv lost packets. got: %d, expected: %d (%d)\n", p.packetSequenceNumber.Val(), c.debug.expectedRcvPacketSequenceNumber.Val(), c.debug.expectedRcvPacketSequenceNumber.Distance(p.packetSequenceNumber))
			}

			c.debug.expectedRcvPacketSequenceNumber = p.packetSequenceNumber.Inc()
		*/

		// Ignore FEC filter control packets
		// https://github.com/Haivision/srt/blob/master/docs/features/packet-filtering-and-fec.md
		// "An FEC control packet is distinguished from a regular data packet by having
		// its message number equal to 0. This value isn't normally used in SRT (message
		// numbers start from 1, increment to a maximum, and then roll back to 1)."
		if header.messageNumber == 0 {
			log("dropped FEC filter control packet\n")
			return
		}

		// 4.5.1.1.  TSBPD Time Base Calculation
		if !c.tsbpdWrapPeriod {
			if header.timestamp > MAX_TIMESTAMP-(30*1000000) {
				c.tsbpdWrapPeriod = true
				log("TSBPD wrapping period started\n")
			}
		} else {
			if header.timestamp >= (30*1000000) && header.timestamp <= (60*1000000) {
				c.tsbpdWrapPeriod = false
				c.tsbpdTimeBaseOffset += uint64(MAX_TIMESTAMP) + 1
				log("TSBPD wrapping period finished\n")
			}
		}

		tsbpdTimeBaseOffset := c.tsbpdTimeBaseOffset
		if c.tsbpdWrapPeriod {
			if header.timestamp < (30 * 1000000) {
				tsbpdTimeBaseOffset += uint64(MAX_TIMESTAMP) + 1
			}
		}

		header.pktTsbpdTime = c.tsbpdTimeBase + tsbpdTimeBaseOffset + uint64(header.timestamp) + c.tsbpdDelay + c.tsbpdDrift

		if header.keyBaseEncryptionFlag != 0 && c.crypto != nil {
			c.crypto.EncryptOrDecryptPayload(p.Data(), header.keyBaseEncryptionFlag, header.packetSequenceNumber.Val())
		}

		// Put the packet into receive congestion control
		c.recv.Push(p)
	}
}

func (c *srtConn) handleKeepAlive(p packet) {
	log("handle keepalive\n")

	c.statistics.receive.keepalive++
	c.statistics.send.keepalive++

	c.peerIdleTimeout.Reset(c.config.PeerIdleTimeout)

	c.pop(p)
}

func (c *srtConn) handleShutdown(p packet) {
	log("handle shutdown\n")

	c.statistics.receive.shutdown++

	go c.close()
}

func (c *srtConn) handleACK(p packet) {
	c.statistics.receive.ack++

	cif := &cifACK{}

	if err := p.UnmarshalCIF(cif); err != nil {
		c.statistics.receive.invalid++
		log("invalid ACK\n%s", p.Dump())
		return
	}

	//logIn("%s\n", cif.String())

	c.snd.ACK(cif.lastACKPacketSequenceNumber)

	if !cif.isLite && !cif.isSmall {
		// 4.10.  Round-Trip Time Estimation
		c.recalculateRTT(time.Duration(int64(cif.rtt)) * time.Microsecond)

		c.sendACKACK(p.Header().typeSpecific)
	}
}

func (c *srtConn) handleNAK(p packet) {
	c.statistics.receive.nak++

	cif := &cifNAK{}

	if err := p.UnmarshalCIF(cif); err != nil {
		c.statistics.receive.invalid++
		log("invalid NAK\n%s", p.Dump())
		return
	}

	//logIn("%s\n", cif.String())

	// Inform congestion control about lost packets
	c.snd.NAK(cif.lostPacketSequenceNumber)
}

func (c *srtConn) handleACKACK(p packet) {
	c.ackLock.RLock()

	//log("ACKACK:\n%s\n", p.String())

	c.statistics.receive.ackack++

	// p.typeSpecific is the ACKNumber
	if ts, ok := c.ackNumbers[p.Header().typeSpecific]; ok {
		// 4.10.  Round-Trip Time Estimation
		c.recalculateRTT(time.Since(ts))
		delete(c.ackNumbers, p.Header().typeSpecific)
	} else {
		log("got unknown ACKACK (%d)\n", p.Header().typeSpecific)
		c.statistics.receive.invalid++
	}

	for i := range c.ackNumbers {
		if i < p.Header().typeSpecific {
			delete(c.ackNumbers, i)
		}
	}

	nakInterval := uint64(c.nakInterval)

	c.ackLock.RUnlock()

	c.recv.SetNAKInterval(nakInterval)
}

func (c *srtConn) recalculateRTT(rtt time.Duration) {
	// 4.10.  Round-Trip Time Estimation
	lastRTT := float64(rtt.Microseconds())

	c.rtt = c.rtt*0.875 + lastRTT*0.125
	c.rttVar = c.rttVar*0.75 + math.Abs(c.rtt-lastRTT)*0.25

	// 4.8.2.  Packet Retransmission (NAKs)
	nakInterval := (c.rtt + 4*c.rttVar) / 2
	if nakInterval < 20000 {
		c.nakInterval = 20000 // 20ms
	} else {
		c.nakInterval = nakInterval
	}

	//log("# RTT=%.0fms RTTVar=%.0fms NAKInterval=%.0fms\n", c.rtt / 1000, c.rttVar / 1000, c.nakInterval / 1000)
}

func (c *srtConn) handleKMRequest(p packet) {
	log("handle KM request\n")

	c.statistics.receive.km++

	if c.crypto == nil {
		return
	}

	cif := &cifKM{}

	if err := p.UnmarshalCIF(cif); err != nil {
		c.statistics.receive.invalid++
		//log("invalid KM\n%s", p.Dump())
		return
	}
	/*
		if cif.keyBasedEncryption == c.keyBaseEncryption {
			c.statistics.receive.invalid++
			log("invalid KM. wants to reset the key that is already in use\n")
			return
		}
	*/
	if err := c.crypto.UnmarshalKM(cif, c.config.Passphrase); err != nil {
		c.statistics.receive.invalid++
		//log("invalid KM. can't decode key with passphrase\n")
		return
	}

	p.Header().subType = EXTTYPE_KMRSP

	c.statistics.send.km++

	//log("sending out KM response\n")

	c.pop(p)
}

func (c *srtConn) handleKMResponse(p packet) {
	log("handle KM response\n")

	c.statistics.receive.km++

	if c.crypto == nil {
		//log("not encrypted\n")
		return
	}

	if c.kmPreAnnounceCountdown >= c.config.KMPreAnnounce {
		//log("not in pre-announce period\n")
		// Ignore the response, we're not in the pre-announce period
		return
	}

	c.kmConfirmed = true
}

func (c *srtConn) sendShutdown() {
	p := newPacket(c.remoteAddr, nil)

	p.Header().isControlPacket = true

	p.Header().controlType = CTRLTYPE_SHUTDOWN
	p.Header().timestamp = c.getTimestampForPacket()

	cif := cifShutdown{}

	p.MarshalCIF(&cif)

	c.statistics.send.shutdown++

	c.pop(p)
}

func (c *srtConn) sendNAK(from, to circular) {
	p := newPacket(c.remoteAddr, nil)

	p.Header().isControlPacket = true

	p.Header().controlType = CTRLTYPE_NAK
	p.Header().timestamp = c.getTimestampForPacket()

	cif := cifNAK{}

	cif.lostPacketSequenceNumber = append(cif.lostPacketSequenceNumber, from)
	cif.lostPacketSequenceNumber = append(cif.lostPacketSequenceNumber, to)

	p.MarshalCIF(&cif)

	c.statistics.send.nak++

	c.pop(p)
}

func (c *srtConn) sendACK(seq circular, lite bool) {
	p := newPacket(c.remoteAddr, nil)

	p.Header().isControlPacket = true

	p.Header().controlType = CTRLTYPE_ACK
	p.Header().timestamp = c.getTimestampForPacket()

	cif := cifACK{
		lastACKPacketSequenceNumber: seq,
	}

	c.ackLock.Lock()
	defer c.ackLock.Unlock()

	if lite {
		cif.isLite = true

		p.Header().typeSpecific = 0
	} else {
		pps, _ := c.recv.PacketRate()

		//log("pps: %d, bps: %d\n", pps, bps)

		cif.rtt = uint32(c.rtt)
		cif.rttVar = uint32(c.rttVar)
		cif.availableBufferSize = 1000 // TODO: available buffer size (packets)
		cif.packetsReceivingRate = pps // packets receiving rate (packets/s)
		cif.estimatedLinkCapacity = 0  // estimated link capacity (packets/s), not relevant for live mode
		cif.receivingRate = 0          // receiving rate (bytes/s), not relevant for live mode

		p.Header().typeSpecific = c.nextACKNumber.Val()

		c.ackNumbers[p.Header().typeSpecific] = time.Now()
		c.nextACKNumber = c.nextACKNumber.Inc()
		if c.nextACKNumber.Val() == 0 {
			c.nextACKNumber = c.nextACKNumber.Inc()
		}
	}

	p.MarshalCIF(&cif)

	c.statistics.send.ack++

	//log("ACK:\n%s\n", p.String())

	c.pop(p)
}

func (c *srtConn) sendACKACK(ackSequence uint32) {
	p := newPacket(c.remoteAddr, nil)

	p.Header().isControlPacket = true

	p.Header().controlType = CTRLTYPE_ACKACK
	p.Header().timestamp = c.getTimestampForPacket()

	p.Header().typeSpecific = ackSequence

	c.statistics.send.ackack++

	c.pop(p)
}

func (c *srtConn) sendKMRequest() {
	log("send KM request\n")

	if c.crypto == nil {
		return
	}

	cif := &cifKM{}

	c.crypto.MarshalKM(cif, c.config.Passphrase, c.keyBaseEncryption.Opposite())

	p := newPacket(c.remoteAddr, nil)

	p.Header().isControlPacket = true

	p.Header().controlType = CTRLTYPE_USER
	p.Header().subType = EXTTYPE_KMREQ
	p.Header().timestamp = c.getTimestampForPacket()

	p.MarshalCIF(cif)

	c.statistics.send.km++

	c.pop(p)
}

func (c *srtConn) Close() error {
	c.close()

	return nil
}

func (c *srtConn) close() {
	c.isShutdown = true

	c.closeOnce.Do(func() {
		log("conn %d: stopping peer idle timeout\n", c.socketId)

		c.peerIdleTimeout.Stop()

		log("conn %d: sending shutdown message to peer\n", c.socketId)

		c.sendShutdown()

		log("conn %d: stopping reader\n", c.socketId)

		// send nil to the readQueue in order to abort any pending ReadPacket call
		c.readQueue <- nil

		log("conn %d: stopping network reader\n", c.socketId)

		c.stopNetworkQueue.Stop()

		log("conn %d: stopping writer\n", c.socketId)

		c.stopWriteQueue.Stop()

		log("conn %d: stopping ticker\n", c.socketId)

		c.stopTicker.Stop()

		log("conn %d: closing queues\n", c.socketId)

		close(c.networkQueue)
		close(c.readQueue)
		close(c.writeQueue)

		log("conn %d: flushing congestion\n", c.socketId)

		c.snd.Flush()
		c.recv.Flush()

		log("conn %d: shutdown\n", c.socketId)

		go func() {
			c.onShutdown(c.socketId)
		}()
	})
}

func (c *srtConn) SetDeadline(t time.Time) error      { return nil }
func (c *srtConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *srtConn) SetWriteDeadline(t time.Time) error { return nil }

type CongestionStatsCounter struct {
	Pushed                  uint64
	Delivered               uint64
	Buffer                  uint64
	Retransmitted           uint64
	RetransmittedAndDropped uint64
	Dropped                 uint64
	DroppedTooLate          uint64
}

func (c *CongestionStatsCounter) From(l liveStatsCounter) {
	c.Pushed = l.pushed
	c.Delivered = l.delivered
	c.Buffer = l.buffer
	c.Retransmitted = l.retransmitted
	c.RetransmittedAndDropped = l.retransmittedAndDropped
	c.Dropped = l.dropped
	c.DroppedTooLate = l.droppedTooLate
}

type CongestionStats struct {
	Packets CongestionStatsCounter
	Bytes   CongestionStatsCounter
}

func (c *CongestionStats) From(l liveStats) {
	c.Packets.From(l.packets)
	c.Bytes.From(l.bytes)
}

type ConnStatsCounter struct {
	Keepalive uint64
	Shutdown  uint64
	NAK       uint64
	ACK       uint64
	ACKACK    uint64
	KM        uint64
	Invalid   uint64

	Congestion CongestionStats
}

func (c *ConnStatsCounter) From(l srtConnStatsCounter) {
	c.Keepalive = l.keepalive
	c.Shutdown = l.shutdown
	c.NAK = l.nak
	c.ACK = l.ack
	c.ACKACK = l.ackack
	c.KM = l.km
	c.Invalid = l.invalid
}

type ConnStats struct {
	Send    ConnStatsCounter
	Receive ConnStatsCounter
}

func (c *ConnStats) From(l srtConnStats) {
	c.Send.From(l.send)
	c.Receive.From(l.receive)
}

func (c *srtConn) Stats() ConnStats {
	s := ConnStats{}

	s.From(c.statistics)
	s.Send.Congestion.From(c.snd.Stats())
	s.Receive.Congestion.From(c.recv.Stats())

	return s
}
