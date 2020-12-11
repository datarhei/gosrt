package srt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"time"

	"github.com/datarhei/gosrt/sync"
)

var ErrClientClosed = errors.New("srt: Client closed")

type DialConfig struct {
	StreamId string
}

// dial will implement the Conn interface
type dialer struct {
	pc *net.UDPConn

	localAddr  net.Addr
	remoteAddr net.Addr

	streamId string
	socketId uint32

	conn     *srtConn
	connChan chan connResponse

	start time.Time

	rcvQueue chan *packet
	sndQueue chan *packet

	isShutdown bool

	stopReader sync.Stopper
	stopWriter sync.Stopper

	doneChan chan error
}

type connResponse struct {
	conn *srtConn
	err  error
}

func Dial(protocol, address string, config DialConfig) (Conn, error) {
	dl := &dialer{
		streamId: config.StreamId,
	}

	raddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}

	pc, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, err
	}

	dl.pc = pc

	dl.localAddr = pc.LocalAddr()
	dl.remoteAddr = pc.RemoteAddr()

	dl.conn = nil
	dl.connChan = make(chan connResponse)

	dl.rcvQueue = make(chan *packet, 1024)
	dl.sndQueue = make(chan *packet, 1024)

	dl.stopReader = sync.NewStopper()
	dl.stopWriter = sync.NewStopper()

	dl.doneChan = make(chan error)

	dl.start = time.Now()

	// create a new socket ID
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	dl.socketId = r.Uint32()

	go func() {
		buffer := make([]byte, 1500) // MTU size
		index := 0

		for {
			if dl.isShutdown == true {
				dl.doneChan <- ErrClientClosed
				return
			}

			pc.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, _, err := pc.ReadFrom(buffer)
			if err != nil {
				if errors.Is(err, os.ErrDeadlineExceeded) == true {
					continue
				}

				if dl.isShutdown == true {
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

			dl.rcvQueue <- p

			index++
		}
	}()

	go dl.reader()
	go dl.writer()

	// Send the initial handshake request
	dl.sendInduction()

	log("waiting for response\n")

	timer := time.AfterFunc(3*time.Second, func() {
		dl.connChan <- connResponse{
			conn: nil,
			err:  fmt.Errorf("connection timeout. server didn't respond"),
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
		return nil
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
			if dl.isShutdown == true {
				break
			}

			//log("packet-received: bytes=%d from=%s\n", len(p.data), p.addr.String())
			//log("%s", hex.Dump(buffer[:16]))

			//if p.isControlPacket == true {
			//log("%s", p.String())
			//}

			if p.destinationSocketId != dl.socketId {
				break
			}

			if p.isControlPacket == true && p.controlType == CTRLTYPE_HANDSHAKE {
				dl.handleHandshake(p)
				break
			}

			dl.conn.push(p)
		}
	}
}

func (dl *dialer) send(p *packet) {
	// non-blocking
	select {
	case dl.sndQueue <- p:
	default:
		log("client: send queue is full")
	}
}

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

			// Write the packet's contents back to the server.
			dl.pc.Write(buffer)
		}
	}
}

func (dl *dialer) handleHandshake(p *packet) {
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
	p.timestamp = uint32(time.Now().Sub(dl.start).Microseconds())
	p.destinationSocketId = cif.srtSocketId

	if cif.handshakeType == HSTYPE_INDUCTION {
		// Verify version
		if cif.version != 5 {
			dl.connChan <- connResponse{
				conn: nil,
				err:  fmt.Errorf("Peer doesn't support handshake v5"),
			}

			return
		}

		// Verify magic number
		if cif.extensionField != 0x4A17 {
			dl.connChan <- connResponse{
				conn: nil,
				err:  fmt.Errorf("Peer sent the wrong magic number"),
			}

			return
		}

		// leave the IP as is

		cif.isRequest = true
		cif.handshakeType = HSTYPE_CONCLUSION
		cif.initialPacketSequenceNumber = 0
		cif.maxTransmissionUnitSize = 1500 // MTU size
		cif.maxFlowWindowSize = 8192
		cif.srtSocketId = dl.socketId

		cif.hasHS = true
		cif.srtVersion = 0x00010402
		cif.srtFlags.TSBPDSND = true
		cif.srtFlags.TSBPDRCV = true
		cif.srtFlags.CRYPT = true
		cif.srtFlags.TLPKTDROP = true
		cif.srtFlags.PERIODICNAK = true
		cif.srtFlags.REXMITFLG = true
		cif.srtFlags.STREAM = false
		cif.srtFlags.PACKET_FILTER = true
		cif.recvTSBPDDelay = 0x0078
		cif.sendTSBPDDelay = 0x0000

		cif.hasSID = true
		cif.streamId = dl.streamId

		p.SetCIF(cif)

		log("outgoing: %s\n", cif.String())

		dl.send(p)
	} else if cif.handshakeType == HSTYPE_CONCLUSION {
		// We only support HSv5
		if cif.version != 5 {
			dl.sendShutdown(cif.srtSocketId)

			dl.connChan <- connResponse{
				conn: nil,
				err:  fmt.Errorf("Peer doesn't support handshake v5"),
			}

			return
		}

		// Check the required SRT flags
		if cif.srtFlags.TSBPDSND == false || cif.srtFlags.TSBPDRCV == false || cif.srtFlags.TLPKTDROP == false || cif.srtFlags.PERIODICNAK == false || cif.srtFlags.REXMITFLG == false {
			dl.sendShutdown(cif.srtSocketId)

			dl.connChan <- connResponse{
				conn: nil,
				err:  fmt.Errorf("Peer doesn't agree on SRT flags"),
			}

			return
		}

		// We only support live streaming
		if cif.srtFlags.STREAM == true {
			dl.sendShutdown(cif.srtSocketId)

			dl.connChan <- connResponse{
				conn: nil,
				err:  fmt.Errorf("Peer doesn't support live streaming"),
			}

			return
		}

		// fill up a struct with all relevant data and put it into the backlog

		conn := &srtConn{
			localAddr:                   dl.localAddr,
			remoteAddr:                  dl.remoteAddr,
			start:                       dl.start,
			socketId:                    dl.socketId,
			peerSocketId:                cif.srtSocketId,
			streamId:                    dl.streamId,
			tsbpdTimeBase:               uint32(time.Now().Sub(dl.start).Microseconds()),
			tsbpdDelay:                  uint32(cif.recvTSBPDDelay) * 1000,
			drift:                       0,
			initialPacketSequenceNumber: cif.initialPacketSequenceNumber,
			send:                        dl.send,
			onShutdown: func(socketId uint32) {
				dl.Close()
			},
		}

		// kick off the connection
		conn.listenAndServe()

		log("new connection: %#08x (%s)\n", conn.SocketId(), conn.StreamId())

		dl.connChan <- connResponse{
			conn: conn,
			err:  nil,
		}
	} else {
		var err error

		switch cif.handshakeType {
		case REJ_UNKNOWN:
			err = fmt.Errorf("Connection rejected: unknown reason (REJ_UNKNOWN)")
		case REJ_SYSTEM:
			err = fmt.Errorf("Connection rejected: system function error (REJ_SYSTEM)")
		case REJ_PEER:
			err = fmt.Errorf("Connection rejected: rejected by peer (REJ_PEER)")
		case REJ_RESOURCE:
			err = fmt.Errorf("Connection rejected: resource allocation problem (REJ_RESOURCE)")
		case REJ_ROGUE:
			err = fmt.Errorf("Connection rejected: incorrect data in handshake (REJ_ROGUE)")
		case REJ_BACKLOG:
			err = fmt.Errorf("Connection rejected: listener's backlog exceeded (REJ_BACKLOG)")
		case REJ_IPE:
			err = fmt.Errorf("Connection rejected: internal program error (REJ_IPE)")
		case REJ_CLOSE:
			err = fmt.Errorf("Connection rejected: socket is closing (REJ_CLOSE)")
		case REJ_VERSION:
			err = fmt.Errorf("Connection rejected: peer is older version than agent's min (REJ_VERSION)")
		case REJ_RDVCOOKIE:
			err = fmt.Errorf("Connection rejected: rendezvous cookie collision (REJ_RDVCOOKIE)")
		case REJ_BADSECRET:
			err = fmt.Errorf("Connection rejected: wrong password (REJ_BADSECRET)")
		case REJ_UNSECURE:
			err = fmt.Errorf("Connection rejected: password required or unexpected (REJ_UNSECURE)")
		case REJ_MESSAGEAPI:
			err = fmt.Errorf("Connection rejected: stream flag collision (REJ_MESSAGEAPI)")
		case REJ_CONGESTION:
			err = fmt.Errorf("Connection rejected: incompatible congestion-controller type (REJ_CONGESTION)")
		case REJ_FILTER:
			err = fmt.Errorf("Connection rejected: incompatible packet filter (REJ_FILTER)")
		case REJ_GROUP:
			err = fmt.Errorf("Connection rejected: incompatible group (REJ_GROUP)")
		default:
			err = fmt.Errorf("Connection rejected: Unknown reason")
		}

		dl.connChan <- connResponse{
			conn: nil,
			err:  err,
		}
	}
}

func (dl *dialer) sendInduction() {
	p := &packet{
		addr:            dl.remoteAddr,
		isControlPacket: true,

		controlType:  CTRLTYPE_HANDSHAKE,
		subType:      0,
		typeSpecific: 0,

		timestamp:           uint32(time.Now().Sub(dl.start).Microseconds()),
		destinationSocketId: 0,
	}

	cif := &cifHandshake{
		isRequest:                   true,
		version:                     4,
		encryptionField:             0,
		extensionField:              2,
		initialPacketSequenceNumber: 0,
		maxTransmissionUnitSize:     1500, // MTU size
		maxFlowWindowSize:           8192,
		handshakeType:               HSTYPE_INDUCTION,
		srtSocketId:                 dl.socketId,
		synCookie:                   0,

		peerIP0: 0x0100007f, // here we need to set our real IP
	}

	log("outgoing: %s\n", cif.String())

	p.SetCIF(cif)

	dl.send(p)
}

func (dl *dialer) sendShutdown(peerSocketId uint32) {
	p := &packet{
		addr:            dl.remoteAddr,
		isControlPacket: true,

		controlType:  CTRLTYPE_SHUTDOWN,
		typeSpecific: 0,

		timestamp:           uint32(time.Now().Sub(dl.start).Microseconds()),
		destinationSocketId: peerSocketId,

		data: make([]byte, 4),
	}

	binary.BigEndian.PutUint32(p.data[0:], 0)

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
	if dl.isShutdown == true {
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

func (dl *dialer) ReadPacket() (*packet, error) {
	if err := dl.checkConnection(); err != nil {
		return nil, err
	}

	return dl.conn.ReadPacket()
}

func (dl *dialer) Write(p []byte) (n int, err error) {
	if err := dl.checkConnection(); err != nil {
		return 0, err
	}

	return dl.conn.Write(p)
}

func (dl *dialer) WritePacket(p *packet) error {
	if err := dl.checkConnection(); err != nil {
		return err
	}

	return dl.conn.WritePacket(p)
}

func (dl *dialer) SetDeadline(t time.Time) error      { return dl.conn.SetDeadline(t) }
func (dl *dialer) SetReadDeadline(t time.Time) error  { return dl.conn.SetReadDeadline(t) }
func (dl *dialer) SetWriteDeadline(t time.Time) error { return dl.conn.SetWriteDeadline(t) }
