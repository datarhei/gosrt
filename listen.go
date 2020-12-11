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
	Accept(func(addr net.Addr, streamId string) ConnType) (Conn, ConnType, error)
	Close()
	Addr() net.Addr
}

type listener struct {
	pc   net.PacketConn
	addr net.Addr

	backlog chan connRequest
	conns   map[uint32]*srtConn
	lock    gosync.RWMutex

	start time.Time

	rcvQueue chan *packet
	sndQueue chan *packet

	syncookie SYNCookie

	isShutdown bool

	stopReader sync.Stopper
	stopWriter sync.Stopper

	doneChan chan error
}

func Listen(protocol, address string) (Listener, error) {
	ln := &listener{}

	pc, err := net.ListenPacket("udp", address)
	if err != nil {
		return nil, err
	}

	ln.pc = pc
	ln.addr = pc.LocalAddr()

	ln.conns = make(map[uint32]*srtConn)

	ln.backlog = make(chan connRequest, 128)

	ln.rcvQueue = make(chan *packet, 1024)
	ln.sndQueue = make(chan *packet, 1024)

	ln.syncookie = NewSYNCookie(ln.addr.String())

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

// if the backlog is full, just ignore any handshake attempts

func (ln *listener) Accept(accept func(addr net.Addr, streamId string) ConnType) (Conn, ConnType, error) {
	if ln.isShutdown == true {
		return nil, REJECT, ErrServerClosed
	}

	select {
	case err := <-ln.doneChan:
		return nil, REJECT, err
	case request := <-ln.backlog:
		if accept == nil {
			ln.reject(request, REJ_PEER)
			return nil, REJECT, nil
		}

		mode := accept(request.addr, request.handshake.streamId)
		if mode == REJECT {
			ln.reject(request, REJ_PEER)

			return nil, REJECT, nil
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

type connRequest struct {
	addr      net.Addr
	start     time.Time
	socketId  uint32
	timestamp uint32

	handshake *cifHandshake
}

func (ln *listener) handleHandshake(p *packet) {
	cif := &cifHandshake{}

	if err := cif.Unmarshal(p.data); err != nil {
		log("cif error: %s\n", err)
		return
	}

	log("incoming: %s\n", cif.String())

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
