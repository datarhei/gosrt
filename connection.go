// Copyright 2020 FOSS GmbH. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package srt

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"net"
	"strings"
	gosync "sync"
	"time"

	//"os"

	"github.com/datarhei/gosrt/sync"
)

// Conn is a SRT network connection.
type Conn interface {
	// Read reads data from the connection.
	// Read can be made to time out and return an error after a fixed
	// time limit; see SetDeadline and SetReadDeadline.
	Read(p []byte) (int, error)

	// Write writes data to the connection.
	// Write can be made to time out and return an error after a fixed
	// time limit; see SetDeadline and SetWriteDeadline.
	Write(p []byte) (int, error)

	// Close closes the connection.
	// Any blocked Read or Write operations will be unblocked and return errors.
	Close() error

	// LocalAddr returns the local network address.
	LocalAddr() net.Addr

	// RemoteAddr returns the remote network address.
	RemoteAddr() net.Addr

	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error

	// SocketId return the socketid of the connection.
	SocketId() uint32

	// PeerSocketId returns the socketid of the peer of the connection.
	PeerSocketId() uint32

	// StreamId returns the streamid use for the connection.
	StreamId() string

	// Stats returns accumulated and instantaneous statistics of the connection.
	Stats() Statistics
}

type connStats struct {
	headerSize        uint64
	pktSentACK        uint64
	pktRecvACK        uint64
	pktSentACKACK     uint64
	pktRecvACKACK     uint64
	pktSentNAK        uint64
	pktRecvNAK        uint64
	pktSentKM         uint64
	pktRecvKM         uint64
	pktRecvUndecrypt  uint64
	byteRecvUndecrypt uint64
	pktRecvInvalid    uint64
	pktSentKeepalive  uint64
	pktRecvKeepalive  uint64
	pktSentShutdown   uint64
	pktRecvShutdown   uint64
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

	rtt    float64 // microseconds
	rttVar float64 // microseconds

	nakInterval float64

	ackLock       gosync.RWMutex
	ackNumbers    map[uint32]time.Time
	nextACKNumber circular

	initialPacketSequenceNumber circular

	tsbpdTimeBase       uint64 // microseconds
	tsbpdWrapPeriod     bool
	tsbpdTimeBaseOffset uint64 // microseconds
	tsbpdDelay          uint64 // microseconds
	tsbpdDrift          uint64 // microseconds

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

	statistics connStats

	logger Logger

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
	tsbpdTimeBase               uint64 // microseconds
	tsbpdDelay                  uint64
	initialPacketSequenceNumber circular
	crypto                      *crypto
	keyBaseEncryption           packetEncryption
	onSend                      func(p packet)
	onShutdown                  func(socketId uint32)
	logger                      Logger
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
		logger:                      config.logger,
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
		c.log("connection:close", func() string {
			return fmt.Sprintf("no more data received from peer for %s. shutting down", c.config.PeerIdleTimeout)
		})
		go c.close()
	})

	c.tick = 10 * time.Millisecond

	// 4.8.1.  Packet Acknowledgement (ACKs, ACKACKs) -> periodicACK = 10 milliseconds
	// 4.8.2.  Packet Retransmission (NAKs) -> periodicNAK at least 20 milliseconds
	c.recv = newLiveRecv(liveRecvConfig{
		initialSequenceNumber: c.initialPacketSequenceNumber,
		periodicACKInterval:   10_000,
		periodicNAKInterval:   20_000,
		onSendACK:             c.sendACK,
		onSendNAK:             c.sendNAK,
		onDeliver:             c.deliver,
	})

	// 4.6.  Too-Late Packet Drop -> 125% of SRT latency, at least 1 second
	c.snd = newLiveSend(liveSendConfig{
		initialSequenceNumber: c.initialPacketSequenceNumber,
		dropInterval:          uint64(c.config.SendDropDelay.Microseconds()),
		maxBW:                 c.config.MaxBW,
		inputBW:               c.config.InputBW,
		minInputBW:            c.config.MinInputBW,
		overheadBW:            c.config.OverheadBW,
		onDeliver:             c.pop,
	})

	go c.networkQueueReader()
	go c.writeQueueReader()
	go c.ticker()

	c.debug.expectedRcvPacketSequenceNumber = c.initialPacketSequenceNumber
	c.debug.expectedReadPacketSequenceNumber = c.initialPacketSequenceNumber

	c.statistics.headerSize = 8 + 16 // 8 bytes UDP + 16 bytes SRT
	if strings.Count(c.localAddr.String(), ":") < 2 {
		c.statistics.headerSize += 20 // 20 bytes IPv4 header
	} else {
		c.statistics.headerSize += 40 // 40 bytes IPv6 header
	}

	return c
}

// LocalAddr returns the local network address. The Addr returned is not shared by other invocations of LocalAddr.
func (c *srtConn) LocalAddr() net.Addr {
	addr, _ := net.ResolveUDPAddr("udp", c.localAddr.String())
	return addr
}

// RemoteAddr returns the remote network address. The Addr returned is not shared by other invocations of RemoteAddr.
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

// ticker invokes the congestion control in regular intervals with
// the current connection time.
func (c *srtConn) ticker() {
	ticker := time.NewTicker(c.tick)
	defer ticker.Stop()
	defer func() {
		c.log("connection:close", func() string { return "left ticker loop" })
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

// readPacket reads a packet from the queue of received packets. It blocks
// if the queue is empty. Only data packets are returned.
func (c *srtConn) readPacket() (packet, error) {
	if c.isShutdown {
		return nil, io.EOF
	}

	p := <-c.readQueue
	if p == nil {
		return nil, io.EOF
	}

	if p.Header().packetSequenceNumber.Gt(c.debug.expectedReadPacketSequenceNumber) {
		c.log("connection:error", func() string {
			return fmt.Sprintf("lost packets. got: %d, expected: %d (%d)", p.Header().packetSequenceNumber.Val(), c.debug.expectedReadPacketSequenceNumber.Val(), c.debug.expectedReadPacketSequenceNumber.Distance(p.Header().packetSequenceNumber))
		})
	} else if p.Header().packetSequenceNumber.Lt(c.debug.expectedReadPacketSequenceNumber) {
		c.log("connection:error", func() string {
			return fmt.Sprintf("packet out of order. got: %d, expected: %d (%d)", p.Header().packetSequenceNumber.Val(), c.debug.expectedReadPacketSequenceNumber.Val(), c.debug.expectedReadPacketSequenceNumber.Distance(p.Header().packetSequenceNumber))
		})
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

	p, err := c.readPacket()
	if err != nil {
		return 0, err
	}

	c.readBuffer.Write(p.Data())

	// The packet is out of congestion control and written to the read buffer
	p.Decommission()

	return c.readBuffer.Read(b)
}

// writePacket writes a packet to the write queue. Packets on the write queue
// will be sent to the peer of the connection. Only data packets will be sent.
func (c *srtConn) writePacket(p packet) error {
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

		// Non-blocking write to the write queue
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

// push puts a packet on the network queue. This is where packets come in from the network.
func (c *srtConn) push(p packet) {
	if c.isShutdown {
		return
	}

	// Non-blocking write to the network queue
	select {
	case c.networkQueue <- p:
	default:
		c.log("connection:error", func() string { return "network queue is full" })
	}
}

// getTimestamp returns the elapsed time since the start of the connection in microseconds.
func (c *srtConn) getTimestamp() uint64 {
	return uint64(time.Since(c.start).Microseconds())
}

// getTimestampForPacket returns the elapsed time since the start of the connection in
// microseconds clamped a 32bit value.
func (c *srtConn) getTimestampForPacket() uint32 {
	return uint32(c.getTimestamp() & uint64(MAX_TIMESTAMP))
}

// pop adds the destination address and socketid to the packet and sends it out to the network.
// The packet will be encrypted if required.
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

		c.log("data:send:dump", func() string { return p.Dump() })
	}

	// Send the packet on the wire
	c.onSend(p)
}

// networkQueueReader reads the packets from the network queue in order to process them.
func (c *srtConn) networkQueueReader() {
	defer func() {
		c.log("connection:close", func() string { return "left network queue reader loop" })
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

// writeQueueReader reads the packets from the write queue and puts them into congestion
// control for sending.
func (c *srtConn) writeQueueReader() {
	defer func() {
		c.log("connection:close", func() string { return "left write queue reader loop" })
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

// deliver writes the packets to the read queue in order to be consumed by the Read function.
func (c *srtConn) deliver(p packet) {
	if c.isShutdown {
		return
	}

	// Non-blocking write to the read queue
	select {
	case c.readQueue <- p:
	default:
		c.log("connection:error", func() string { return "readQueue was blocking, dropping packet" })
	}
}

// handlePacket checks the packet header. If it is a control packet it will forwarded to the
// respective handler. If it is a data packet it will be put into congestion control for
// receiving. The packet will be decrypted if required.
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
			c.log("connection:filter", func() string { return "dropped FEC filter control packet" })
			return
		}

		// 4.5.1.1.  TSBPD Time Base Calculation
		if !c.tsbpdWrapPeriod {
			if header.timestamp > MAX_TIMESTAMP-(30*1000000) {
				c.tsbpdWrapPeriod = true
				c.log("connection:tsbpd", func() string { return "TSBPD wrapping period started" })
			}
		} else {
			if header.timestamp >= (30*1000000) && header.timestamp <= (60*1000000) {
				c.tsbpdWrapPeriod = false
				c.tsbpdTimeBaseOffset += uint64(MAX_TIMESTAMP) + 1
				c.log("connection:tsbpd", func() string { return "TSBPD wrapping period finished" })
			}
		}

		tsbpdTimeBaseOffset := c.tsbpdTimeBaseOffset
		if c.tsbpdWrapPeriod {
			if header.timestamp < (30 * 1000000) {
				tsbpdTimeBaseOffset += uint64(MAX_TIMESTAMP) + 1
			}
		}

		header.pktTsbpdTime = c.tsbpdTimeBase + tsbpdTimeBaseOffset + uint64(header.timestamp) + c.tsbpdDelay + c.tsbpdDrift

		c.log("data:recv:dump", func() string { return p.Dump() })

		if c.crypto != nil {
			if header.keyBaseEncryptionFlag != 0 {
				if err := c.crypto.EncryptOrDecryptPayload(p.Data(), header.keyBaseEncryptionFlag, header.packetSequenceNumber.Val()); err != nil {
					c.statistics.pktRecvUndecrypt++
					c.statistics.byteRecvUndecrypt += p.Len()
				}
			} else {
				c.statistics.pktRecvUndecrypt++
				c.statistics.byteRecvUndecrypt += p.Len()
			}
		}

		// Put the packet into receive congestion control
		c.recv.Push(p)
	}
}

// handleKeepAlive resets the idle timeout and sends a keepalive to the peer.
func (c *srtConn) handleKeepAlive(p packet) {
	c.log("control:recv:keepalive:dump", func() string { return p.Dump() })

	c.statistics.pktRecvKeepalive++
	c.statistics.pktSentKeepalive++

	c.peerIdleTimeout.Reset(c.config.PeerIdleTimeout)

	c.log("control:send:keepalive:dump", func() string { return p.Dump() })

	c.pop(p)
}

// handleShutdown closes the connection
func (c *srtConn) handleShutdown(p packet) {
	c.log("control:recv:shutdown:dump", func() string { return p.Dump() })

	c.statistics.pktRecvShutdown++

	go c.close()
}

// handleACK forwards the acknowledge sequence number to the congestion control and
// returns a ACKACK (on a full ACK). The RTT is also updated in case of a full ACK.
func (c *srtConn) handleACK(p packet) {
	c.log("control:recv:ACK:dump", func() string { return p.Dump() })

	c.statistics.pktRecvACK++

	cif := &cifACK{}

	if err := p.UnmarshalCIF(cif); err != nil {
		c.statistics.pktRecvInvalid++
		c.log("control:recv:ACK:error", func() string { return fmt.Sprintf("invalid ACK: %s", err) })
		return
	}

	c.log("control:recv:ACK:cif", func() string { return cif.String() })

	c.snd.ACK(cif.lastACKPacketSequenceNumber)

	if !cif.isLite && !cif.isSmall {
		// 4.10.  Round-Trip Time Estimation
		c.recalculateRTT(time.Duration(int64(cif.rtt)) * time.Microsecond)

		c.sendACKACK(p.Header().typeSpecific)
	}
}

// handleNAK forwards the lost sequence number to the congestion control.
func (c *srtConn) handleNAK(p packet) {
	c.log("control:recv:NAK:dump", func() string { return p.Dump() })

	c.statistics.pktRecvNAK++

	cif := &cifNAK{}

	if err := p.UnmarshalCIF(cif); err != nil {
		c.statistics.pktRecvInvalid++
		c.log("control:recv:NAK:error", func() string { return fmt.Sprintf("invalid NAK: %s", err) })
		return
	}

	c.log("control:recv:NAK:cif", func() string { return cif.String() })

	// Inform congestion control about lost packets
	c.snd.NAK(cif.lostPacketSequenceNumber)
}

// handleACKACK updates the RTT and NAK interval for the congestion control.
func (c *srtConn) handleACKACK(p packet) {
	c.ackLock.RLock()

	c.statistics.pktRecvACKACK++

	c.log("control:recv:ACKACK:dump", func() string { return p.Dump() })

	// p.typeSpecific is the ACKNumber
	if ts, ok := c.ackNumbers[p.Header().typeSpecific]; ok {
		// 4.10.  Round-Trip Time Estimation
		c.recalculateRTT(time.Since(ts))
		delete(c.ackNumbers, p.Header().typeSpecific)
	} else {
		c.log("control:recv:ACKACK:error", func() string { return fmt.Sprintf("got unknown ACKACK (%d)", p.Header().typeSpecific) })
		c.statistics.pktRecvInvalid++
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

// recalculateRTT recalculates the RTT based on a full ACK exchange
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

	c.log("connection:rtt", func() string {
		return fmt.Sprintf("RTT=%.0fus RTTVar=%.0fus NAKInterval=%.0fms", c.rtt, c.rttVar, c.nakInterval/1000)
	})
}

// handleKMRequest checks if the key material is valid and responds with a KM response.
func (c *srtConn) handleKMRequest(p packet) {
	c.log("control:recv:KM:dump", func() string { return p.Dump() })

	c.statistics.pktRecvKM++

	if c.crypto == nil {
		c.log("control:recv:KM:error", func() string { return "connection is not encrypted" })
		return
	}

	cif := &cifKM{}

	if err := p.UnmarshalCIF(cif); err != nil {
		c.statistics.pktRecvInvalid++
		c.log("control:recv:KM:error", func() string { return fmt.Sprintf("invalid KM: %s", err) })
		return
	}

	c.log("control:recv:KM:cif", func() string { return cif.String() })
	/*
		if cif.keyBasedEncryption == c.keyBaseEncryption {
			c.statistics.receive.invalid++
			log("invalid KM. wants to reset the key that is already in use\n")
			return
		}
	*/
	if err := c.crypto.UnmarshalKM(cif, c.config.Passphrase); err != nil {
		c.statistics.pktRecvInvalid++
		c.log("control:recv:KM:error", func() string { return fmt.Sprintf("invalid KM: %s", err) })
		return
	}

	p.Header().subType = EXTTYPE_KMRSP

	c.statistics.pktSentKM++

	c.pop(p)
}

// handleKMResponse confirms the change of encryption keys.
func (c *srtConn) handleKMResponse(p packet) {
	c.log("control:recv:KM:dump", func() string { return p.Dump() })

	c.statistics.pktRecvKM++

	if c.crypto == nil {
		c.log("control:recv:KM:error", func() string { return "connection is not encrypted" })
		return
	}

	if c.kmPreAnnounceCountdown >= c.config.KMPreAnnounce {
		c.log("control:recv:KM:error", func() string { return "not in pre-announce period" })
		// Ignore the response, we're not in the pre-announce period
		return
	}

	c.kmConfirmed = true
}

// sendShutdown sends a shutdown packet to the peer.
func (c *srtConn) sendShutdown() {
	p := newPacket(c.remoteAddr, nil)

	p.Header().isControlPacket = true

	p.Header().controlType = CTRLTYPE_SHUTDOWN
	p.Header().timestamp = c.getTimestampForPacket()

	cif := cifShutdown{}

	p.MarshalCIF(&cif)

	c.log("control:send:shutdown:dump", func() string { return p.Dump() })
	c.log("control:send:shutdown:cif", func() string { return cif.String() })

	c.statistics.pktSentShutdown++

	c.pop(p)
}

// sendNAK sends a NAK to the peer with the given range of sequence numbers.
func (c *srtConn) sendNAK(from, to circular) {
	p := newPacket(c.remoteAddr, nil)

	p.Header().isControlPacket = true

	p.Header().controlType = CTRLTYPE_NAK
	p.Header().timestamp = c.getTimestampForPacket()

	cif := cifNAK{}

	cif.lostPacketSequenceNumber = append(cif.lostPacketSequenceNumber, from)
	cif.lostPacketSequenceNumber = append(cif.lostPacketSequenceNumber, to)

	p.MarshalCIF(&cif)

	c.log("control:send:NAK:dump", func() string { return p.Dump() })
	c.log("control:send:NAK:cif", func() string { return cif.String() })

	c.statistics.pktSentNAK++

	c.pop(p)
}

// sendACK sends an ACK to the peer with the given sequence number.
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

		cif.rtt = uint32(c.rtt)
		cif.rttVar = uint32(c.rttVar)
		cif.availableBufferSize = c.config.FC // TODO: available buffer size (packets)
		cif.packetsReceivingRate = pps        // packets receiving rate (packets/s)
		cif.estimatedLinkCapacity = 0         // estimated link capacity (packets/s), not relevant for live mode
		cif.receivingRate = 0                 // receiving rate (bytes/s), not relevant for live mode

		p.Header().typeSpecific = c.nextACKNumber.Val()

		c.ackNumbers[p.Header().typeSpecific] = time.Now()
		c.nextACKNumber = c.nextACKNumber.Inc()
		if c.nextACKNumber.Val() == 0 {
			c.nextACKNumber = c.nextACKNumber.Inc()
		}
	}

	p.MarshalCIF(&cif)

	c.log("control:send:ACK:dump", func() string { return p.Dump() })
	c.log("control:send:ACK:cif", func() string { return cif.String() })

	c.statistics.pktSentACK++

	c.pop(p)
}

// sendACKACK sends an ACKACK to the peer with the given ACK sequence.
func (c *srtConn) sendACKACK(ackSequence uint32) {
	p := newPacket(c.remoteAddr, nil)

	p.Header().isControlPacket = true

	p.Header().controlType = CTRLTYPE_ACKACK
	p.Header().timestamp = c.getTimestampForPacket()

	p.Header().typeSpecific = ackSequence

	c.log("control:send:ACKACK:dump", func() string { return p.Dump() })

	c.statistics.pktSentACKACK++

	c.pop(p)
}

// sendKMRequest sends a KM request to the peer.
func (c *srtConn) sendKMRequest() {
	if c.crypto == nil {
		c.log("control:send:KM:error", func() string { return "connection is not encrypted" })
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

	c.log("control:send:KM:dump", func() string { return p.Dump() })
	c.log("control:send:KM:cif", func() string { return cif.String() })

	c.statistics.pktSentKM++

	c.pop(p)
}

// Close closes the connection.
func (c *srtConn) Close() error {
	c.close()

	return nil
}

// close closes the connection.
func (c *srtConn) close() {
	c.isShutdown = true

	c.closeOnce.Do(func() {
		c.log("connection:close", func() string { return "stopping peer idle timeout" })

		c.peerIdleTimeout.Stop()

		c.log("connection:close", func() string { return "sending shutdown message to peer" })

		c.sendShutdown()

		c.log("connection:close", func() string { return "stopping reader" })

		// send nil to the readQueue in order to abort any pending ReadPacket call
		c.readQueue <- nil

		c.log("connection:close", func() string { return "stopping network reader" })

		c.stopNetworkQueue.Stop()

		c.log("connection:close", func() string { return "stopping writer" })

		c.stopWriteQueue.Stop()

		c.log("connection:close", func() string { return "stopping ticker" })

		c.stopTicker.Stop()

		c.log("connection:close", func() string { return "closing queues" })

		close(c.networkQueue)
		close(c.readQueue)
		close(c.writeQueue)

		c.log("connection:close", func() string { return "flushing congestion" })

		c.snd.Flush()
		c.recv.Flush()

		c.log("connection:close", func() string { return "shutdown" })

		go func() {
			c.onShutdown(c.socketId)
		}()
	})
}

func (c *srtConn) log(topic string, message func() string) {
	c.logger.Print(topic, c.socketId, 2, message)
}

func (c *srtConn) SetDeadline(t time.Time) error      { return nil }
func (c *srtConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *srtConn) SetWriteDeadline(t time.Time) error { return nil }

func (c *srtConn) Stats() Statistics {
	send := c.snd.Stats()
	recv := c.recv.Stats()

	s := Statistics{
		MsTimeStamp: uint64(time.Since(c.start).Milliseconds()),

		// Accumulated
		PktSent:          send.pktSent,
		PktRecv:          recv.pktRecv,
		PktSentUnique:    send.pktSentUnique,
		PktRecvUnique:    recv.pktRecvUnique,
		PktSndLoss:       send.pktSndLoss,
		PktRcvLoss:       recv.pktRcvLoss,
		PktRetrans:       send.pktRetrans,
		PktRcvRetrans:    recv.pktRcvRetrans,
		PktSentACK:       c.statistics.pktSentACK,
		PktRecvACK:       c.statistics.pktRecvACK,
		PktSentNAK:       c.statistics.pktSentNAK,
		PktRecvNAK:       c.statistics.pktRecvNAK,
		PktSentKM:        c.statistics.pktSentKM,
		PktRecvKM:        c.statistics.pktRecvKM,
		UsSndDuration:    send.usSndDuration,
		PktSndDrop:       send.pktSndDrop,
		PktRcvDrop:       recv.pktRcvDrop,
		PktRcvUndecrypt:  c.statistics.pktRecvUndecrypt,
		ByteSent:         send.byteSent + (send.pktSent * c.statistics.headerSize),
		ByteRecv:         recv.byteRecv + (recv.pktRecv * c.statistics.headerSize),
		ByteSentUnique:   send.byteSentUnique + (send.pktSentUnique * c.statistics.headerSize),
		ByteRecvUnique:   recv.byteRecvUnique + (recv.pktRecvUnique * c.statistics.headerSize),
		ByteRcvLoss:      recv.byteRcvLoss + (recv.pktRcvLoss * c.statistics.headerSize),
		ByteRetrans:      send.byteRetrans + (send.pktRetrans * c.statistics.headerSize),
		ByteSndDrop:      send.byteSndDrop + (send.pktSndDrop * c.statistics.headerSize),
		ByteRcvDrop:      recv.byteRcvDrop + (recv.pktRcvDrop * c.statistics.headerSize),
		ByteRcvUndecrypt: c.statistics.byteRecvUndecrypt + (c.statistics.pktRecvUndecrypt * c.statistics.headerSize),

		// Instantaneous
		UsPktSndPeriod:       send.usPktSndPeriod,
		PktFlowWindow:        uint64(c.config.FC),
		PktFlightSize:        send.pktFlightSize,
		MsRTT:                c.rtt / 1_000,
		MbpsBandwidth:        0,
		ByteAvailSndBuf:      0,
		ByteAvailRcvBuf:      0,
		MbpsMaxBW:            float64(c.config.MaxBW / 1024 / 1024),
		ByteMSS:              uint64(c.config.MSS),
		PktSndBuf:            send.pktSndBuf,
		ByteSndBuf:           send.byteSndBuf,
		MsSndBuf:             send.msSndBuf,
		MsSndTsbPdDelay:      uint64(c.config.PeerLatency),
		PktRcvBuf:            recv.pktRcvBuf,
		ByteRcvBuf:           recv.byteRcvBuf,
		MsRcvBuf:             recv.msRcvBuf,
		MsRcvTsbPdDelay:      uint64(c.config.ReceiverLatency),
		PktReorderTolerance:  0,
		PktRcvAvgBelatedTime: 0,
	}

	return s
}
