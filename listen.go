// Copyright 2020 FOSS GmbH. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package srt

import (
	"bytes"
	"errors"
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

	backlog chan connRequest
	conns   map[uint32]*srtConn
	lock    gosync.RWMutex

	start time.Time

	rcvQueue chan *packet
	sndQueue chan *packet

	syncookie synCookie

	isShutdown bool

	stopReader sync.Stopper
	stopWriter sync.Stopper

	doneChan chan error
}

func Listen(protocol, address string, config Config) (Listener, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	ln := &listener{}

	raddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}

	pc, err := net.ListenUDP("udp", raddr)
	if err != nil {
		return nil, err
	}

	file, err := pc.File()
	if err != nil {
		return nil, err
	}

	// Set TOS
	err = syscall.SetsockoptInt(int(file.Fd()), syscall.IPPROTO_IP, syscall.IP_TOS, config.IPTOS)
	if err != nil {
		return nil, err
	}

	// Set TTL
	err = syscall.SetsockoptInt(int(file.Fd()), syscall.IPPROTO_IP, syscall.IP_TTL, config.IPTTL)
	if err != nil {
		return nil, err
	}

	ln.pc = pc
	ln.addr = pc.LocalAddr()

	ln.conns = make(map[uint32]*srtConn)

	ln.backlog = make(chan connRequest, 128)

	ln.rcvQueue = make(chan *packet, 1024)
	ln.sndQueue = make(chan *packet, 1024)

	ln.syncookie = newSYNCookie(ln.addr.String())

	ln.stopReader = sync.NewStopper()
	ln.stopWriter = sync.NewStopper()

	ln.doneChan = make(chan error)

	ln.start = time.Now()

	go ln.reader()
	go ln.writer()

	go func() {
		buffer := make([]byte, 1500) // MTU size
		index := 0

		for {
			if ln.isShutdown == true {
				ln.doneChan <- ErrServerClosed
				return
			}

			pc.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, addr, err := pc.ReadFrom(buffer)
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

			index++
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
		return nil
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

		// create a new socket ID
		socketId := uint32(time.Now().Sub(ln.start).Microseconds())

		// new connection
		conn := &srtConn{
			localAddr:                   ln.addr,
			remoteAddr:                  request.addr,
			start:                       request.start,
			socketId:                    socketId,
			peerSocketId:                request.handshake.srtSocketId,
			streamId:                    request.handshake.streamId,
			tsbpdTimeBase:               request.timestamp,
			tsbpdDelay:                  uint32(request.handshake.recvTSBPDDelay) * 1000,
			drift:                       0,
			initialPacketSequenceNumber: request.handshake.initialPacketSequenceNumber,
			crypto:                      request.crypto,
			passphrase:                  request.passphrase,
			keyBaseEncryption:           evenKeyEncrypted,
			send:                        ln.send,
			onShutdown:                  ln.handleShutdown,
		}

		// kick off the connection
		conn.listenAndServe()

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
		request.handshake.srtFlags.PACKET_FILTER = true

		log("outgoing: %s\n", request.handshake.String())

		ln.accept(request)

		// add the connection to the list of known connections
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

func (ln *listener) reject(request connRequest, reason uint32) {
	p := &packet{
		addr:            request.addr,
		isControlPacket: true,

		controlType:  CTRLTYPE_HANDSHAKE,
		subType:      0,
		typeSpecific: 0,

		timestamp:           uint32(time.Now().Sub(ln.start).Microseconds()),
		destinationSocketId: request.socketId,
	}

	request.handshake.handshakeType = reason

	p.SetCIF(request.handshake)

	ln.send(p)
}

func (ln *listener) accept(request connRequest) {
	p := &packet{
		addr:            request.addr,
		isControlPacket: true,

		controlType:  CTRLTYPE_HANDSHAKE,
		subType:      0,
		typeSpecific: 0,

		timestamp:           uint32(time.Now().Sub(request.start).Microseconds()),
		destinationSocketId: request.socketId,
	}

	p.SetCIF(request.handshake)

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

			if p.isControlPacket == true {
				//logIn("%s", p.String())
			}

			if p.destinationSocketId == 0 {
				if p.isControlPacket == true && p.controlType == CTRLTYPE_HANDSHAKE {
					ln.handleHandshake(p)
				}

				break
			}

			ln.lock.RLock()
			conn, ok := ln.conns[p.destinationSocketId]
			ln.lock.RUnlock()

			if !ok {
				// ignore the packet, we don't know the destination
				break
			}

			conn.push(p)
		}
	}
}

func (ln *listener) send(p *packet) {
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

			//addr, _ := net.ResolveUDPAddr("udp", b.addr)

			// Write the packet's contents back to the client.
			ln.pc.WriteTo(buffer, p.addr)
		}
	}
}

func (ln *listener) handleHandshake(p *packet) {
	cif := &cifHandshake{}

	err := cif.Unmarshal(p.data)

	log("incoming: %s\n", cif.String())

	if err != nil {
		log("cif error: %s\n", err)
		return
	}

	// assemble the response (4.3.1.  Caller-Listener Handshake)

	p.controlType = CTRLTYPE_HANDSHAKE
	p.subType = 0
	p.typeSpecific = 0
	p.timestamp = uint32(time.Now().Sub(ln.start).Microseconds())
	p.destinationSocketId = cif.srtSocketId

	if cif.handshakeType == HSTYPE_INDUCTION {
		// cif
		cif.version = 5
		cif.encryptionField = 0
		cif.extensionField = 0x4A17
		cif.initialPacketSequenceNumber = 0
		cif.maxTransmissionUnitSize = 0
		cif.maxFlowWindowSize = 0
		cif.srtSocketId = 0
		cif.synCookie = ln.syncookie.Get(p.addr.String())

		// leave the IP as is

		p.SetCIF(cif)

		log("outgoing: %s\n", cif.String())

		ln.send(p)
	} else if cif.handshakeType == HSTYPE_CONCLUSION {
		// Verify the SYN cookie
		if ln.syncookie.Verify(cif.synCookie, p.addr.String()) == false {
			cif.handshakeType = REJ_ROGUE
			p.SetCIF(cif)
			ln.send(p)

			return
		}

		// We only support HSv5
		if cif.version != 5 {
			cif.handshakeType = REJ_ROGUE
			p.SetCIF(cif)
			ln.send(p)

			return
		}

		// Check the required SRT flags
		if cif.srtFlags.TSBPDSND == false || cif.srtFlags.TSBPDRCV == false || cif.srtFlags.TLPKTDROP == false || cif.srtFlags.PERIODICNAK == false || cif.srtFlags.REXMITFLG == false {
			cif.handshakeType = REJ_ROGUE
			p.SetCIF(cif)
			ln.send(p)

			return
		}

		// We only support live streaming
		if cif.srtFlags.STREAM == true {
			cif.handshakeType = REJ_MESSAGEAPI
			p.SetCIF(cif)
			ln.send(p)

			return
		}

		// fill up a struct with all relevant data and put it into the backlog

		c := connRequest{
			addr:      p.addr,
			start:     time.Now(),
			socketId:  cif.srtSocketId,
			timestamp: p.timestamp,

			handshake: cif,
		}

		if cif.srtKM != nil {
			cr, err := newCrypto(int(cif.srtKM.kLen))
			if err != nil {
				cif.handshakeType = REJ_ROGUE
				p.SetCIF(cif)
				ln.send(p)

				return
			}

			c.crypto = cr
		}

		// non-blocking
		select {
		case ln.backlog <- c:
		default:
			cif.handshakeType = REJ_BACKLOG
			p.SetCIF(cif)
			ln.send(p)
		}
	} else {
		log("   unknown handshakeType\n")
	}
}
