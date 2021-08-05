// Copyright 2020 FOSS GmbH. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package srt

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	gosync "sync"
	"syscall"
	"time"

	"github.com/datarhei/gosrt/sync"
)

type ConnType int

func (c ConnType) String() string {
	switch c {
	case REJECT:
		return "REJECT"
	case PUBLISH:
		return "PUBLISH"
	case SUBSCRIBE:
		return "SUBSCRIBE"
	default:
		return ""
	}
}

const (
	REJECT ConnType = ConnType(1 << iota)
	PUBLISH
	SUBSCRIBE
)

var ErrServerClosed = errors.New("srt: server closed")

type Listener interface {
	Accept(func(req ConnRequest) ConnType) (Conn, ConnType, error)
	Close()
	Addr() net.Addr
}

type listener struct {
	pc   *net.UDPConn
	addr net.Addr

	config Config

	backlog chan connRequest
	conns   map[uint32]*srtConn
	lock    gosync.RWMutex

	start time.Time

	rcvQueue chan packet
	sndQueue chan packet

	syncookie synCookie

	isShutdown bool

	stopReader sync.Stopper
	stopWriter sync.Stopper

	doneChan chan error
}

func Listen(protocol, address string, config Config) (Listener, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("listen: invalid config: %w", err)
	}

	if config.Logger == nil {
		config.Logger = NewLogger(nil)
	}

	ln := &listener{
		config: config,
	}

	raddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, fmt.Errorf("listen: unable to resolve address: %w", err)
	}

	pc, err := net.ListenUDP("udp", raddr)
	if err != nil {
		return nil, fmt.Errorf("listen: failed listening: %w", err)
	}

	file, err := pc.File()
	if err != nil {
		return nil, err
	}

	// Set TOS
	if config.IPTOS > 0 {
		err = syscall.SetsockoptInt(int(file.Fd()), syscall.IPPROTO_IP, syscall.IP_TOS, config.IPTOS)
		if err != nil {
			return nil, fmt.Errorf("listen: failed setting socket option TOS: %w", err)
		}
	}

	// Set TTL
	if config.IPTTL > 0 {
		err = syscall.SetsockoptInt(int(file.Fd()), syscall.IPPROTO_IP, syscall.IP_TTL, config.IPTTL)
		if err != nil {
			return nil, fmt.Errorf("listen: failed setting socket option TTL: %w", err)
		}
	}

	ln.pc = pc
	ln.addr = pc.LocalAddr()

	ln.conns = make(map[uint32]*srtConn)

	ln.backlog = make(chan connRequest, 128)

	ln.rcvQueue = make(chan packet, 1024)
	ln.sndQueue = make(chan packet, 1024)

	ln.syncookie = newSYNCookie(ln.addr.String())

	ln.stopReader = sync.NewStopper()
	ln.stopWriter = sync.NewStopper()

	ln.doneChan = make(chan error)

	ln.start = time.Now()

	go ln.reader()
	go ln.writer()

	go func() {
		buffer := make([]byte, config.MSS) // MTU size

		for {
			if ln.isShutdown {
				ln.doneChan <- ErrServerClosed
				return
			}

			ln.pc.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, addr, err := ln.pc.ReadFrom(buffer)
			if err != nil {
				if errors.Is(err, os.ErrDeadlineExceeded) {
					continue
				}

				if ln.isShutdown {
					ln.doneChan <- ErrServerClosed
					return
				}

				ln.doneChan <- err
				return
			}

			p := newPacket(addr, buffer[:n])
			if p == nil {
				continue
			}

			ln.rcvQueue <- p
		}
	}()

	return ln, nil
}

type ConnRequest interface {
	RemoteAddr() net.Addr
	StreamId() string
	IsEncrypted() bool
	SetPassphrase(p string) error
}

type connRequest struct {
	addr      net.Addr
	start     time.Time
	socketId  uint32
	timestamp uint32

	handshake  *cifHandshake
	crypto     *crypto
	passphrase string
}

func (req *connRequest) RemoteAddr() net.Addr {
	addr, _ := net.ResolveUDPAddr("udp", req.addr.String())
	return addr
}

func (req *connRequest) StreamId() string {
	return req.handshake.streamId
}

func (req *connRequest) IsEncrypted() bool {
	return req.crypto != nil
}

func (req *connRequest) SetPassphrase(passphrase string) error {
	if req.crypto == nil {
		return fmt.Errorf("listen: request without encryption")
	}

	if err := req.crypto.UnmarshalKM(req.handshake.srtKM, passphrase); err != nil {
		return err
	}

	req.passphrase = passphrase

	return nil
}

func (ln *listener) Accept(acceptFn func(req ConnRequest) ConnType) (Conn, ConnType, error) {
	if ln.isShutdown {
		return nil, REJECT, ErrServerClosed
	}

	select {
	case err := <-ln.doneChan:
		return nil, REJECT, err
	case request := <-ln.backlog:
		if acceptFn == nil {
			ln.reject(request, REJ_PEER)
			break
		}

		mode := acceptFn(&request)
		if mode != PUBLISH && mode != SUBSCRIBE {
			ln.reject(request, REJ_PEER)
			break
		}

		if request.crypto != nil && len(request.passphrase) == 0 {
			ln.reject(request, REJ_BADSECRET)
			break
		}

		// Create a new socket ID
		socketId := uint32(time.Since(ln.start).Microseconds())

		// Select the largest TSBPD delay advertised by the caller, but at
		// least 120ms
		tsbpdDelay := uint16(120)
		if request.handshake.recvTSBPDDelay > tsbpdDelay {
			tsbpdDelay = request.handshake.recvTSBPDDelay
		}

		if request.handshake.sendTSBPDDelay > tsbpdDelay {
			tsbpdDelay = request.handshake.sendTSBPDDelay
		}

		ln.config.StreamId = request.handshake.streamId
		ln.config.Passphrase = request.passphrase

		// Create a new connection
		conn := newSRTConn(srtConnConfig{
			localAddr:                   ln.addr,
			remoteAddr:                  request.addr,
			config:                      ln.config,
			start:                       request.start,
			socketId:                    socketId,
			peerSocketId:                request.handshake.srtSocketId,
			tsbpdTimeBase:               uint64(request.timestamp),
			tsbpdDelay:                  uint64(tsbpdDelay) * 1000,
			initialPacketSequenceNumber: request.handshake.initialPacketSequenceNumber,
			crypto:                      request.crypto,
			keyBaseEncryption:           evenKeyEncrypted,
			onSend:                      ln.send,
			onShutdown:                  ln.handleShutdown,
			logger:                      ln.config.Logger,
		})

		ln.log("connection:new", func() string { return fmt.Sprintf("%#08x (%s) %s", conn.SocketId(), conn.StreamId(), mode) })

		request.handshake.srtSocketId = socketId
		request.handshake.synCookie = 0

		//  3.2.1.1.1.  Handshake Extension Message Flags
		request.handshake.srtVersion = 0x00010402
		request.handshake.srtFlags.TSBPDSND = true
		request.handshake.srtFlags.TSBPDRCV = true
		request.handshake.srtFlags.CRYPT = true
		request.handshake.srtFlags.TLPKTDROP = true
		request.handshake.srtFlags.PERIODICNAK = true
		request.handshake.srtFlags.REXMITFLG = true
		request.handshake.srtFlags.STREAM = false
		request.handshake.srtFlags.PACKET_FILTER = false

		ln.accept(request)

		// Add the connection to the list of known connections
		ln.lock.Lock()
		ln.conns[conn.socketId] = conn
		ln.lock.Unlock()

		return conn, mode, nil
	}

	return nil, REJECT, nil
}

func (ln *listener) handleShutdown(socketId uint32) {
	ln.lock.Lock()
	delete(ln.conns, socketId)
	ln.lock.Unlock()
}

func (ln *listener) reject(request connRequest, reason handshakeType) {
	p := newPacket(request.addr, nil)
	p.Header().isControlPacket = true

	p.Header().controlType = CTRLTYPE_HANDSHAKE
	p.Header().subType = 0
	p.Header().typeSpecific = 0

	p.Header().timestamp = uint32(time.Since(ln.start).Microseconds())
	p.Header().destinationSocketId = request.socketId

	request.handshake.handshakeType = reason

	p.MarshalCIF(request.handshake)

	ln.log("handshake:send:dump", func() string { return p.Dump() })
	ln.log("handshake:send:cif", func() string { return request.handshake.String() })

	ln.send(p)
}

func (ln *listener) accept(request connRequest) {
	p := newPacket(request.addr, nil)

	p.Header().isControlPacket = true

	p.Header().controlType = CTRLTYPE_HANDSHAKE
	p.Header().subType = 0
	p.Header().typeSpecific = 0

	p.Header().timestamp = uint32(time.Since(request.start).Microseconds())
	p.Header().destinationSocketId = request.socketId

	p.MarshalCIF(request.handshake)

	ln.log("handshake:send:dump", func() string { return p.Dump() })
	ln.log("handshake:send:cif", func() string { return request.handshake.String() })

	ln.send(p)
}

func (ln *listener) Close() {
	if ln.isShutdown {
		return
	}

	ln.isShutdown = true

	ln.lock.RLock()
	for _, conn := range ln.conns {
		conn.close()
	}
	ln.lock.RUnlock()

	ln.stopReader.Stop()
	ln.stopWriter.Stop()

	ln.log("listen", func() string { return "closing socket" })

	ln.pc.Close()
}

func (ln *listener) Addr() net.Addr {
	return ln.addr
}

func (ln *listener) reader() {
	defer func() {
		ln.log("listen", func() string { return "left reader loop" })
		ln.stopReader.Done()
	}()

	for {
		select {
		case <-ln.stopReader.Check():
			return
		case p := <-ln.rcvQueue:
			if ln.isShutdown {
				break
			}

			ln.log("packet:recv:dump", func() string { return p.Dump() })

			if p.Header().destinationSocketId == 0 {
				if p.Header().isControlPacket && p.Header().controlType == CTRLTYPE_HANDSHAKE {
					ln.handleHandshake(p)
				}

				break
			}

			ln.lock.RLock()
			conn, ok := ln.conns[p.Header().destinationSocketId]
			ln.lock.RUnlock()

			if !ok {
				// ignore the packet, we don't know the destination
				break
			}

			conn.push(p)
		}
	}
}

func (ln *listener) send(p packet) {
	// non-blocking
	select {
	case ln.sndQueue <- p:
	default:
		ln.log("listen", func() string { return "send queue is full" })
	}
}

func (ln *listener) writer() {
	defer func() {
		ln.log("listen", func() string { return "left writer loop" })
		ln.stopWriter.Done()
	}()

	var data bytes.Buffer

	for {
		select {
		case <-ln.stopWriter.Check():
			return
		case p := <-ln.sndQueue:
			data.Reset()

			p.Marshal(&data)

			buffer := data.Bytes()

			ln.log("packet:send:dump", func() string { return p.Dump() })

			// Write the packet's contents to the wire
			ln.pc.WriteTo(buffer, p.Header().addr)

			if p.Header().isControlPacket {
				// Control packets can be decommissioned because they will not be sent again (data packets might be retransferred)
				p.Decommission()
			}
		}
	}
}

func (ln *listener) handleHandshake(p packet) {
	cif := &cifHandshake{}

	err := p.UnmarshalCIF(cif)

	ln.log("handshake:recv:dump", func() string { return p.Dump() })
	ln.log("handshake:recv:cif", func() string { return cif.String() })

	if err != nil {
		ln.log("handshake:recv:error", func() string { return err.Error() })
		return
	}

	// Assemble the response (4.3.1.  Caller-Listener Handshake)

	p.Header().controlType = CTRLTYPE_HANDSHAKE
	p.Header().subType = 0
	p.Header().typeSpecific = 0
	p.Header().timestamp = uint32(time.Since(ln.start).Microseconds())
	p.Header().destinationSocketId = cif.srtSocketId

	cif.peerIP.FromNetAddr(ln.addr)

	if cif.handshakeType == HSTYPE_INDUCTION {
		// cif
		cif.version = 5
		cif.encryptionField = 0 // Don't advertise any specific encryption method
		cif.extensionField = 0x4A17
		//cif.initialPacketSequenceNumber = newCircular(0, MAX_SEQUENCENUMBER)
		//cif.maxTransmissionUnitSize = 0
		//cif.maxFlowWindowSize = 0
		cif.srtSocketId = 0
		cif.synCookie = ln.syncookie.Get(p.Header().addr.String())

		p.MarshalCIF(cif)

		ln.log("handshake:send:dump", func() string { return p.Dump() })
		ln.log("handshake:send:cif", func() string { return cif.String() })

		ln.send(p)
	} else if cif.handshakeType == HSTYPE_CONCLUSION {
		// Verify the SYN cookie
		if !ln.syncookie.Verify(cif.synCookie, p.Header().addr.String()) {
			cif.handshakeType = REJ_ROGUE
			ln.log("handshake:recv:error", func() string { return "invalid SYN cookie" })
			p.MarshalCIF(cif)
			ln.log("handshake:send:dump", func() string { return p.Dump() })
			ln.log("handshake:send:cif", func() string { return cif.String() })
			ln.send(p)

			return
		}

		// We only support HSv5
		if cif.version != 5 {
			cif.handshakeType = REJ_ROGUE
			ln.log("handshake:recv:error", func() string { return "only HSv5 is supported" })
			p.MarshalCIF(cif)
			ln.log("handshake:send:dump", func() string { return p.Dump() })
			ln.log("handshake:send:cif", func() string { return cif.String() })
			ln.send(p)

			return
		}

		// Check if the peer version is sufficient
		if cif.srtVersion < ln.config.MinVersion {
			cif.handshakeType = REJ_VERSION
			ln.log("handshake:recv:error", func() string { return fmt.Sprintf("peer version insufficient (%#08x)", cif.srtVersion) })
			p.MarshalCIF(cif)
			ln.log("handshake:send:dump", func() string { return p.Dump() })
			ln.log("handshake:send:cif", func() string { return cif.String() })
			ln.send(p)

			return
		}

		// Check the required SRT flags
		if !cif.srtFlags.TSBPDSND || !cif.srtFlags.TSBPDRCV || !cif.srtFlags.TLPKTDROP || !cif.srtFlags.PERIODICNAK || !cif.srtFlags.REXMITFLG {
			cif.handshakeType = REJ_ROGUE
			ln.log("handshake:recv:error", func() string { return "not all required flags are set" })
			p.MarshalCIF(cif)
			ln.log("handshake:send:dump", func() string { return p.Dump() })
			ln.log("handshake:send:cif", func() string { return cif.String() })
			ln.send(p)

			return
		}

		// We only support live streaming
		if cif.srtFlags.STREAM {
			cif.handshakeType = REJ_MESSAGEAPI
			ln.log("handshake:recv:error", func() string { return "only live streaming is supported" })
			p.MarshalCIF(cif)
			ln.log("handshake:send:dump", func() string { return p.Dump() })
			ln.log("handshake:send:cif", func() string { return cif.String() })
			ln.send(p)

			return
		}

		// Peer is advertising a too big MSS
		if cif.maxTransmissionUnitSize > MAX_MSS_SIZE {
			cif.handshakeType = REJ_ROGUE
			ln.log("handshake:recv:error", func() string { return fmt.Sprintf("MTU is too big (%d bytes)", cif.maxTransmissionUnitSize) })
			p.MarshalCIF(cif)
			ln.log("handshake:send:dump", func() string { return p.Dump() })
			ln.log("handshake:send:cif", func() string { return cif.String() })
			ln.send(p)

			return
		}

		// If the peer has a smaller MTU size, adjust to it
		if cif.maxTransmissionUnitSize < ln.config.MSS {
			ln.config.MSS = cif.maxTransmissionUnitSize
			ln.config.PayloadSize = ln.config.MSS - SRT_HEADER_SIZE - UDP_HEADER_SIZE

			if ln.config.PayloadSize < MIN_PAYLOAD_SIZE {
				cif.handshakeType = REJ_ROGUE
				ln.log("handshake:recv:error", func() string { return fmt.Sprintf("payload size is too small (%d bytes)", ln.config.PayloadSize) })
				p.MarshalCIF(cif)
				ln.log("handshake:send:dump", func() string { return p.Dump() })
				ln.log("handshake:send:cif", func() string { return cif.String() })
				ln.send(p)
			}
		}

		// Fill up a connection request with all relevant data and put it into the backlog

		c := connRequest{
			addr:      p.Header().addr,
			start:     time.Now(),
			socketId:  cif.srtSocketId,
			timestamp: p.Header().timestamp,

			handshake: cif,
		}

		if cif.srtKM != nil {
			cr, err := newCrypto(int(cif.srtKM.kLen))
			if err != nil {
				cif.handshakeType = REJ_ROGUE
				ln.log("handshake:recv:error", func() string { return fmt.Sprintf("crypto: %s", err) })
				p.MarshalCIF(cif)
				ln.log("handshake:send:dump", func() string { return p.Dump() })
				ln.log("handshake:send:cif", func() string { return cif.String() })
				ln.send(p)

				return
			}

			c.crypto = cr
		}

		// If the backlog is full, reject the connection
		select {
		case ln.backlog <- c:
		default:
			cif.handshakeType = REJ_BACKLOG
			ln.log("handshake:recv:error", func() string { return "backlog is full" })
			p.MarshalCIF(cif)
			ln.log("handshake:send:dump", func() string { return p.Dump() })
			ln.log("handshake:send:cif", func() string { return cif.String() })
			ln.send(p)
		}
	} else {
		if cif.handshakeType.IsRejection() {
			ln.log("handshake:recv:error", func() string { return fmt.Sprintf("connection rejected: %s", cif.handshakeType.String()) })
		} else {
			ln.log("handshake:recv:error", func() string { return fmt.Sprintf("unsupported handshake: %s", cif.handshakeType.String()) })
		}
	}
}

func (ln *listener) log(topic string, message func() string) {
	ln.config.Logger.Print(topic, 0, 2, message)
}
