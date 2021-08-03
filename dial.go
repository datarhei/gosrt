// Copyright 2020 FOSS GmbH. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package srt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/datarhei/gosrt/sync"
)

var ErrClientClosed = errors.New("srt: client closed")

// dial will implement the Conn interface
type dialer struct {
	pc *net.UDPConn

	localAddr  net.Addr
	remoteAddr net.Addr

	config Config

	socketId                    uint32
	initialPacketSequenceNumber circular

	crypto *crypto

	conn     *srtConn
	connChan chan connResponse

	start time.Time

	rcvQueue chan packet
	sndQueue chan packet

	isShutdown bool

	stopReader sync.Stopper
	stopWriter sync.Stopper

	doneChan chan error
}

type connResponse struct {
	conn *srtConn
	err  error
}

func Dial(protocol, address string, config Config) (Conn, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("dial: invalid config: %w", err)
	}

	dl := &dialer{
		config: config,
	}

	raddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, fmt.Errorf("dial: unable to resolve address: %w", err)
	}

	pc, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, fmt.Errorf("dial: failed dialing: %w", err)
	}

	file, err := pc.File()
	if err != nil {
		return nil, err
	}

	// Set TOS
	if config.IPTOS > 0 {
		err = syscall.SetsockoptInt(int(file.Fd()), syscall.IPPROTO_IP, syscall.IP_TOS, config.IPTOS)
		if err != nil {
			return nil, fmt.Errorf("dial: failed setting socket option TOS: %w", err)
		}
	}

	// Set TTL
	if config.IPTTL > 0 {
		err = syscall.SetsockoptInt(int(file.Fd()), syscall.IPPROTO_IP, syscall.IP_TTL, config.IPTTL)
		if err != nil {
			return nil, fmt.Errorf("dial: failed setting socket option TTL: %w", err)
		}
	}

	dl.pc = pc

	dl.localAddr = pc.LocalAddr()
	dl.remoteAddr = pc.RemoteAddr()

	dl.conn = nil
	dl.connChan = make(chan connResponse)

	dl.rcvQueue = make(chan packet, 2048)
	dl.sndQueue = make(chan packet, 2048)

	dl.stopReader = sync.NewStopper()
	dl.stopWriter = sync.NewStopper()

	dl.doneChan = make(chan error)

	dl.start = time.Now()

	// create a new socket ID
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	dl.socketId = r.Uint32()
	dl.initialPacketSequenceNumber = newCircular(r.Uint32()&MAX_SEQUENCENUMBER, MAX_SEQUENCENUMBER)

	go func() {
		buffer := make([]byte, MAX_MSS_SIZE) // MTU size
		index := 0

		for {
			if dl.isShutdown {
				dl.doneChan <- ErrClientClosed
				return
			}

			pc.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, _, err := pc.ReadFrom(buffer)
			if err != nil {
				if errors.Is(err, os.ErrDeadlineExceeded) {
					continue
				}

				if dl.isShutdown {
					dl.doneChan <- ErrClientClosed
					return
				}

				dl.doneChan <- err
				return
			}

			p := newPacket(dl.remoteAddr, buffer[:n])
			if p == nil {
				continue
			}

			//log("incoming: %s\n", p.String())

			dl.rcvQueue <- p

			index++
		}
	}()

	go dl.reader()
	go dl.writer()

	// Send the initial handshake request
	dl.sendInduction()

	log("waiting for response\n")

	timer := time.AfterFunc(dl.config.ConnectionTimeout, func() {
		dl.connChan <- connResponse{
			conn: nil,
			err:  fmt.Errorf("dial: connection timeout. server didn't respond"),
		}
	})

	// Wait for handshake to conclude
	response := <-dl.connChan
	if response.err != nil {
		dl.Close()
		return nil, response.err
	}

	timer.Stop()

	dl.conn = response.conn

	return dl, nil
}

func (dl *dialer) checkConnection() error {
	select {
	case err := <-dl.doneChan:
		dl.Close()
		return err
	default:
	}

	return nil
}

func (dl *dialer) reader() {
	defer func() {
		log("client: left reader loop\n")
		dl.stopReader.Done()
	}()

	for {
		select {
		case <-dl.stopReader.Check():
			return
		case p := <-dl.rcvQueue:
			if dl.isShutdown {
				break
			}

			//log("packet-received: bytes=%d from=%s\n", len(p.data), p.addr.String())
			//log("%s", hex.Dump(buffer[:16]))

			//if p.isControlPacket == true {
			//log("%s", p.String())
			//}

			if p.Header().destinationSocketId != dl.socketId {
				break
			}

			if p.Header().isControlPacket && p.Header().controlType == CTRLTYPE_HANDSHAKE {
				dl.handleHandshake(p)
				break
			}

			dl.conn.push(p)
		}
	}
}

func (dl *dialer) send(p packet) {
	// non-blocking
	select {
	case dl.sndQueue <- p:
	default:
		log("client: send queue is full\n")
	}
}

// send packets to the wire
func (dl *dialer) writer() {
	defer func() {
		log("client: left writer loop\n")
		dl.stopWriter.Done()
	}()

	var data bytes.Buffer

	for {
		select {
		case <-dl.stopWriter.Check():
			return
		case p := <-dl.sndQueue:
			data.Reset()

			p.Marshal(&data)

			buffer := data.Bytes()

			//log("packet-send: bytes=%d to=%s\n", len(buffer), p.addr.String())

			// Write the packet's contents to the wire.
			dl.pc.Write(buffer)

			if p.Header().isControlPacket {
				// Control packets can be decommissioned because they will be sent again
				p.Decommission()
			}
		}
	}
}

func (dl *dialer) handleHandshake(p packet) {
	cif := &cifHandshake{}

	if err := p.UnmarshalCIF(cif); err != nil {
		log("cif error: %s\n", err)
		return
	}

	log("incoming: %s\n", cif.String())

	// assemble the response (4.3.1.  Caller-Listener Handshake)

	p.Header().controlType = CTRLTYPE_HANDSHAKE
	p.Header().subType = 0
	p.Header().typeSpecific = 0
	p.Header().timestamp = uint32(time.Since(dl.start).Microseconds())
	p.Header().destinationSocketId = cif.srtSocketId

	if cif.handshakeType == HSTYPE_INDUCTION {
		// Verify version
		if cif.version != 5 {
			dl.connChan <- connResponse{
				conn: nil,
				err:  fmt.Errorf("dial: peer doesn't support handshake v5"),
			}

			return
		}

		// Verify magic number
		if cif.extensionField != 0x4A17 {
			dl.connChan <- connResponse{
				conn: nil,
				err:  fmt.Errorf("dial: peer sent the wrong magic number"),
			}

			return
		}

		// Setup crypto context
		if len(dl.config.Passphrase) != 0 {
			keylen := dl.config.PBKeylen

			// If the server advertises a specific block cipher family and key size,
			// use this one, otherwise, use the configured one
			if cif.encryptionField != 0 {
				switch cif.encryptionField {
				case 2:
					keylen = 16
				case 3:
					keylen = 24
				case 4:
					keylen = 32
				}
			}

			cr, err := newCrypto(keylen)
			if err != nil {
				dl.connChan <- connResponse{
					conn: nil,
					err:  fmt.Errorf("dial: failed creating crypto context: %w", err),
				}
			}

			dl.crypto = cr
		}

		cif.isRequest = true
		cif.handshakeType = HSTYPE_CONCLUSION
		cif.initialPacketSequenceNumber = dl.initialPacketSequenceNumber
		cif.maxTransmissionUnitSize = dl.config.MSS // MTU size
		cif.maxFlowWindowSize = dl.config.FC
		cif.srtSocketId = dl.socketId
		cif.peerIP.FromNetAddr(dl.localAddr)

		cif.hasHS = true
		cif.srtVersion = SRT_VERSION
		cif.srtFlags.TSBPDSND = true
		cif.srtFlags.TSBPDRCV = true
		cif.srtFlags.CRYPT = true // must always set to true
		cif.srtFlags.TLPKTDROP = true
		cif.srtFlags.PERIODICNAK = true
		cif.srtFlags.REXMITFLG = true
		cif.srtFlags.STREAM = false
		cif.srtFlags.PACKET_FILTER = false
		cif.recvTSBPDDelay = uint16(dl.config.ReceiverLatency.Milliseconds())
		cif.sendTSBPDDelay = uint16(dl.config.PeerLatency.Milliseconds())

		cif.hasSID = true
		cif.streamId = dl.config.StreamId

		if dl.crypto != nil {
			cif.hasKM = true
			cif.srtKM = &cifKM{}

			if err := dl.crypto.MarshalKM(cif.srtKM, dl.config.Passphrase, evenKeyEncrypted); err != nil {
				dl.connChan <- connResponse{
					conn: nil,
					err:  err,
				}

				return
			}
		}

		p.MarshalCIF(cif)

		log("outgoing: %s\n", cif.String())

		dl.send(p)
	} else if cif.handshakeType == HSTYPE_CONCLUSION {
		// We only support HSv5
		if cif.version != 5 {
			dl.sendShutdown(cif.srtSocketId)

			dl.connChan <- connResponse{
				conn: nil,
				err:  fmt.Errorf("dial: peer doesn't support handshake v5"),
			}

			return
		}

		// Check if the peer version is sufficient
		if cif.srtVersion < dl.config.MinVersion {
			dl.sendShutdown(cif.srtSocketId)

			dl.connChan <- connResponse{
				conn: nil,
				err:  fmt.Errorf("dial: peer SRT version is not sufficient"),
			}

			return
		}

		// Check the required SRT flags
		if !cif.srtFlags.TSBPDSND || !cif.srtFlags.TSBPDRCV || !cif.srtFlags.TLPKTDROP || !cif.srtFlags.PERIODICNAK || !cif.srtFlags.REXMITFLG {
			dl.sendShutdown(cif.srtSocketId)

			dl.connChan <- connResponse{
				conn: nil,
				err:  fmt.Errorf("dial: peer doesn't agree on SRT flags"),
			}

			return
		}

		// We only support live streaming
		if cif.srtFlags.STREAM {
			dl.sendShutdown(cif.srtSocketId)

			dl.connChan <- connResponse{
				conn: nil,
				err:  fmt.Errorf("dial: peer doesn't support live streaming"),
			}

			return
		}

		// Use the largest TSBPD delay as advertised by the listener, but
		// at least 120ms
		tsbpdDelay := uint16(120)
		if cif.recvTSBPDDelay > tsbpdDelay {
			tsbpdDelay = cif.recvTSBPDDelay
		}

		if cif.sendTSBPDDelay > tsbpdDelay {
			tsbpdDelay = cif.sendTSBPDDelay
		}

		// If the peer has a smaller MTU size, adjust to it
		if cif.maxTransmissionUnitSize < dl.config.MSS {
			dl.config.MSS = cif.maxTransmissionUnitSize
			dl.config.PayloadSize = dl.config.MSS - SRT_HEADER_SIZE - UDP_HEADER_SIZE

			if dl.config.PayloadSize < MIN_PAYLOAD_SIZE {
				dl.sendShutdown(cif.srtSocketId)

				dl.connChan <- connResponse{
					conn: nil,
					err:  fmt.Errorf("dial: effective MSS too small (%d bytes) to fit the minimal payload size (%d bytes)", dl.config.MSS, MIN_PAYLOAD_SIZE),
				}

				return
			}
		}

		// Create a new connection
		conn := newSRTConn(srtConnConfig{
			localAddr:                   dl.localAddr,
			remoteAddr:                  dl.remoteAddr,
			config:                      dl.config,
			start:                       dl.start,
			socketId:                    dl.socketId,
			peerSocketId:                cif.srtSocketId,
			tsbpdTimeBase:               uint64(time.Since(dl.start).Microseconds()),
			tsbpdDelay:                  uint64(tsbpdDelay) * 1000,
			initialPacketSequenceNumber: cif.initialPacketSequenceNumber,
			crypto:                      dl.crypto,
			keyBaseEncryption:           evenKeyEncrypted,
			onSend:                      dl.send,
			onShutdown: func(socketId uint32) {
				dl.Close()
			},
		})

		log("new connection: %#08x (%s)\n", conn.SocketId(), conn.StreamId())

		dl.connChan <- connResponse{
			conn: conn,
			err:  nil,
		}
	} else {
		var err error

		if cif.handshakeType.IsRejection() {
			err = fmt.Errorf("dial: connection rejected: %s", cif.handshakeType.String())
		} else {
			err = fmt.Errorf("dial: unsupported handshake: %s", cif.handshakeType.String())
		}

		dl.connChan <- connResponse{
			conn: nil,
			err:  err,
		}
	}
}

func (dl *dialer) sendInduction() {
	p := newPacket(dl.remoteAddr, nil)

	p.Header().isControlPacket = true

	p.Header().controlType = CTRLTYPE_HANDSHAKE
	p.Header().subType = 0
	p.Header().typeSpecific = 0

	p.Header().timestamp = uint32(time.Since(dl.start).Microseconds())
	p.Header().destinationSocketId = 0

	cif := &cifHandshake{
		isRequest:                   true,
		version:                     4,
		encryptionField:             0,
		extensionField:              2,
		initialPacketSequenceNumber: newCircular(0, MAX_SEQUENCENUMBER),
		maxTransmissionUnitSize:     dl.config.MSS, // MTU size
		maxFlowWindowSize:           dl.config.FC,
		handshakeType:               HSTYPE_INDUCTION,
		srtSocketId:                 dl.socketId,
		synCookie:                   0,
	}

	cif.peerIP.FromNetAddr(dl.localAddr)

	log("outgoing: %s\n", cif.String())

	p.MarshalCIF(cif)

	dl.send(p)
}

func (dl *dialer) sendShutdown(peerSocketId uint32) {
	p := newPacket(dl.remoteAddr, nil)

	data := [4]byte{}
	binary.BigEndian.PutUint32(data[0:], 0)

	p.SetData(data[0:4])

	p.Header().isControlPacket = true

	p.Header().controlType = CTRLTYPE_SHUTDOWN
	p.Header().typeSpecific = 0

	p.Header().timestamp = uint32(time.Since(dl.start).Microseconds())
	p.Header().destinationSocketId = peerSocketId

	dl.send(p)
}

// Implementation of the Conn interface
func (dl *dialer) LocalAddr() net.Addr {
	return dl.conn.LocalAddr()
}

func (dl *dialer) RemoteAddr() net.Addr {
	return dl.conn.RemoteAddr()
}

func (dl *dialer) SocketId() uint32 {
	return dl.conn.SocketId()
}

func (dl *dialer) PeerSocketId() uint32 {
	return dl.conn.PeerSocketId()
}

func (dl *dialer) StreamId() string {
	return dl.conn.StreamId()
}

func (dl *dialer) Close() error {
	if dl.isShutdown {
		return nil
	}

	dl.isShutdown = true

	if dl.conn != nil {
		dl.conn.Close()
	}

	dl.stopReader.Stop()
	dl.stopWriter.Stop()

	log("client: closing socket\n")
	dl.pc.Close()

	select {
	case <-dl.doneChan:
	default:
	}

	return nil
}

func (dl *dialer) Read(p []byte) (n int, err error) {
	if err := dl.checkConnection(); err != nil {
		return 0, err
	}

	return dl.conn.Read(p)
}

func (dl *dialer) Write(p []byte) (n int, err error) {
	if err := dl.checkConnection(); err != nil {
		return 0, err
	}

	return dl.conn.Write(p)
}

func (dl *dialer) SetDeadline(t time.Time) error      { return dl.conn.SetDeadline(t) }
func (dl *dialer) SetReadDeadline(t time.Time) error  { return dl.conn.SetReadDeadline(t) }
func (dl *dialer) SetWriteDeadline(t time.Time) error { return dl.conn.SetWriteDeadline(t) }
func (dl *dialer) Stats() Statistics                  { return dl.conn.Stats() }
