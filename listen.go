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

const (
	REJECT ConnType = ConnType(1 << iota)
	PUBLISH
	SUBSCRIBE
)

var ErrServerClosed = errors.New("srt: Server closed")

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

	start      time.Time
	nbReceiver int

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
	ln.nbReceiver = 1 // runtime.NumCPU()

	go ln.reader()
	go ln.writer()

	// net.inet.udp.recvspace: 786896 -> 1573792

	go func() {
		buffer := make([]byte, config.MSS) // MTU size

		for {
			if ln.isShutdown == true {
				ln.doneChan <- ErrServerClosed
				return
			}

			ln.pc.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, addr, err := ln.pc.ReadFrom(buffer)
			if err != nil {
				if errors.Is(err, os.ErrDeadlineExceeded) == true {
					continue
				}

				if ln.isShutdown == true {
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
		return fmt.Errorf("request without encryption")
	}

	if err := req.crypto.UnmarshalKM(req.handshake.srtKM, passphrase); err != nil {
		return err
	}

	req.passphrase = passphrase

	return nil
}

func (ln *listener) Accept(acceptFn func(req ConnRequest) ConnType) (Conn, ConnType, error) {
	if ln.isShutdown == true {
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

		config := ln.config

		config.StreamId = request.handshake.streamId
		config.Passphrase = request.passphrase

		// Create a new connection
		conn := newSRTConn(srtConnConfig{
			localAddr:                   ln.addr,
			remoteAddr:                  request.addr,
			config:                      config,
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
		})

		log("new connection: %#08x (%s)\n", conn.SocketId(), conn.StreamId())

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

		log("outgoing: %s\n", request.handshake.String())

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

	ln.send(p)
}

func (ln *listener) Close() {
	if ln.isShutdown == true {
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

	log("server: closing socket\n")
	ln.pc.Close()
}

func (ln *listener) Addr() net.Addr {
	return ln.addr
}

func (ln *listener) reader() {
	defer func() {
		log("server: left reader loop\n")
		ln.stopReader.Done()
	}()

	for {
		select {
		case <-ln.stopReader.Check():
			return
		case p := <-ln.rcvQueue:
			if ln.isShutdown == true {
				break
			}

			//logIn("packet-received: bytes=%d from=%s\n", len(buffer), addr.String())
			//logIn("%s", hex.Dump(buffer[:16]))

			if p.Header().isControlPacket == true {
				//logIn("%s", p.String())
			}

			if p.Header().destinationSocketId == 0 {
				if p.Header().isControlPacket == true && p.Header().controlType == CTRLTYPE_HANDSHAKE {
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
		log("server: send queue is full")
	}
}

func (ln *listener) writer() {
	defer func() {
		log("server: left writer loop\n")
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

			//logOut("packet-send: bytes=%d to=%s\n", len(buffer), b.addr.String())
			//logOut("%s", hex.Dump(buffer))

			// Write the packet's contents to the wire
			ln.pc.WriteTo(buffer, p.Header().addr)

			if p.Header().isControlPacket == true {
				// Control packets can be decommissioned because they will be not sent again
				p.Decommission()
			}
		}
	}
}

func (ln *listener) handleHandshake(p packet) {
	cif := &cifHandshake{}

	err := p.UnmarshalCIF(cif)

	log("incoming: %s\n", cif.String())

	if err != nil {
		log("cif error: %s\n", err)
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

		log("outgoing: %s\n", cif.String())

		ln.send(p)
	} else if cif.handshakeType == HSTYPE_CONCLUSION {
		// Verify the SYN cookie
		if ln.syncookie.Verify(cif.synCookie, p.Header().addr.String()) == false {
			cif.handshakeType = REJ_ROGUE
			p.MarshalCIF(cif)
			ln.send(p)

			return
		}

		// We only support HSv5
		if cif.version != 5 {
			cif.handshakeType = REJ_ROGUE
			p.MarshalCIF(cif)
			ln.send(p)

			return
		}

		// Check if the peer version is sufficient
		if cif.srtVersion < ln.config.MinVersion {
			cif.handshakeType = REJ_VERSION
			p.MarshalCIF(cif)
			ln.send(p)

			return
		}

		// Check the required SRT flags
		if cif.srtFlags.TSBPDSND == false || cif.srtFlags.TSBPDRCV == false || cif.srtFlags.TLPKTDROP == false || cif.srtFlags.PERIODICNAK == false || cif.srtFlags.REXMITFLG == false {
			cif.handshakeType = REJ_ROGUE
			p.MarshalCIF(cif)
			ln.send(p)

			return
		}

		// We only support live streaming
		if cif.srtFlags.STREAM == true {
			cif.handshakeType = REJ_MESSAGEAPI
			p.MarshalCIF(cif)
			ln.send(p)

			return
		}

		// Peer is advertising a too big MSS
		if cif.maxTransmissionUnitSize > MAX_MSS_SIZE {
			cif.handshakeType = REJ_ROGUE
			p.MarshalCIF(cif)
			ln.send(p)

			return
		}

		// If the peer has a smaller MTU size, adjust to it
		if cif.maxTransmissionUnitSize < ln.config.MSS {
			ln.config.MSS = cif.maxTransmissionUnitSize
			ln.config.PayloadSize = ln.config.MSS - SRT_HEADER_SIZE - UDP_HEADER_SIZE

			if ln.config.PayloadSize < MIN_PAYLOAD_SIZE {
				cif.handshakeType = REJ_ROGUE
				p.MarshalCIF(cif)
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
				p.MarshalCIF(cif)
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
			p.MarshalCIF(cif)
			ln.send(p)
		}
	} else {
		if cif.handshakeType.IsRejection() == true {
			log("Connection rejected: %s", cif.handshakeType.String())
		} else {
			log("Unsupported handshake: %s", cif.handshakeType.String())
		}
	}
}
