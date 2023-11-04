package srt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/datarhei/gosrt/internal/crypto"
	srtnet "github.com/datarhei/gosrt/internal/net"
	"github.com/datarhei/gosrt/internal/packet"
)

// ConnType represents the kind of connection as returned
// from the AcceptFunc. It is one of REJECT, PUBLISH, or SUBSCRIBE.
type ConnType int

// String returns a string representation of the ConnType.
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
	REJECT    ConnType = ConnType(1 << iota) // Reject a connection
	PUBLISH                                  // This connection is meant to write data to the server
	SUBSCRIBE                                // This connection is meant to read data from a PUBLISHed stream
)

// ConnRequest is an incoming connection request
type ConnRequest interface {
	// RemoteAddr returns the address of the peer. The returned net.Addr
	// is a copy and can be used at will.
	RemoteAddr() net.Addr

	// Version returns the handshake version of the incoming request. Currently
	// known versions are 4 and 5. With version 4 the StreamId will always be
	// empty and IsEncrypted will always return false. An incoming version 4
	// connection will always be publishing.
	Version() uint32

	// StreamId returns the streamid of the requesting connection. Use this
	// to decide what to do with the connection.
	StreamId() string

	// IsEncrypted returns whether the connection is encrypted. If it is
	// encrypted, use SetPassphrase to set the passphrase for decrypting.
	IsEncrypted() bool

	// SetPassphrase sets the passphrase in order to decrypt the incoming
	// data. Returns an error if the passphrase did not work or the connection
	// is not encrypted.
	SetPassphrase(p string) error
}

// connRequest implements the ConnRequest interface
type connRequest struct {
	addr      net.Addr
	start     time.Time
	socketId  uint32
	timestamp uint32

	handshake  *packet.CIFHandshake
	crypto     crypto.Crypto
	passphrase string
}

func (req *connRequest) RemoteAddr() net.Addr {
	addr, _ := net.ResolveUDPAddr("udp", req.addr.String())
	return addr
}

func (req *connRequest) Version() uint32 {
	return req.handshake.Version
}

func (req *connRequest) StreamId() string {
	return req.handshake.StreamId
}

func (req *connRequest) IsEncrypted() bool {
	return req.crypto != nil
}

func (req *connRequest) SetPassphrase(passphrase string) error {
	if req.handshake.Version == 5 {
		if req.crypto == nil {
			return fmt.Errorf("listen: request without encryption")
		}

		if err := req.crypto.UnmarshalKM(req.handshake.SRTKM, passphrase); err != nil {
			return err
		}
	}

	req.passphrase = passphrase

	return nil
}

// ErrListenerClosed is returned when the listener is about to shutdown.
var ErrListenerClosed = errors.New("srt: listener closed")

// AcceptFunc receives a connection request and returns the type of connection
// and is required by the Listener for each Accept of a new connection.
type AcceptFunc func(req ConnRequest) ConnType

// Listener waits for new connections
type Listener interface {
	// Accept waits for new connections. For each new connection the AcceptFunc
	// gets called. Conn is a new connection if AcceptFunc is PUBLISH or SUBSCRIBE.
	// If AcceptFunc returns REJECT, Conn is nil. In case of failure error is not
	// nil, Conn is nil and ConnType is REJECT. On closing the listener err will
	// be ErrListenerClosed and ConnType is REJECT.
	Accept(AcceptFunc) (Conn, ConnType, error)

	// Close closes the listener. It will stop accepting new connections and
	// close all currently established connections.
	Close()

	// Addr returns the address of the listener.
	Addr() net.Addr
}

// listener implements the Listener interface.
type listener struct {
	pc   *net.UDPConn
	addr net.Addr

	config Config

	backlog chan connRequest
	conns   map[uint32]*srtConn
	lock    sync.RWMutex

	start time.Time

	rcvQueue chan packet.Packet

	sendMutex sync.Mutex
	sendData  bytes.Buffer

	syncookie *srtnet.SYNCookie

	shutdown     bool
	shutdownLock sync.RWMutex
	shutdownOnce sync.Once

	stopReader context.CancelFunc

	doneChan chan error
}

// Listen returns a new listener on the SRT protocol on the address with
// the provided config. The network parameter needs to be "srt".
//
// The address has the form "host:port".
//
// Examples:
//
//	Listen("srt", "127.0.0.1:3000", DefaultConfig())
//
// In case of an error, the returned Listener is nil and the error is non-nil.
func Listen(network, address string, config Config) (Listener, error) {
	if network != "srt" {
		return nil, fmt.Errorf("listen: the network must be 'srt'")
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("listen: invalid config: %w", err)
	}

	if config.Logger == nil {
		config.Logger = NewLogger(nil)
	}

	ln := &listener{
		config: config,
	}

	lc := net.ListenConfig{
		Control: ListenControl(config),
	}

	lp, err := lc.ListenPacket(context.Background(), "udp", address)
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}

	pc := lp.(*net.UDPConn)

	ln.pc = pc
	ln.addr = pc.LocalAddr()

	ln.conns = make(map[uint32]*srtConn)

	ln.backlog = make(chan connRequest, 128)

	ln.rcvQueue = make(chan packet.Packet, 2048)

	ln.syncookie, err = srtnet.NewSYNCookie(ln.addr.String(), nil)
	if err != nil {
		ln.Close()
		return nil, err
	}

	ln.doneChan = make(chan error)

	ln.start = time.Now()

	var readerCtx context.Context
	readerCtx, ln.stopReader = context.WithCancel(context.Background())
	go ln.reader(readerCtx)

	go func() {
		buffer := make([]byte, config.MSS) // MTU size

		for {
			if ln.isShutdown() {
				ln.doneChan <- ErrListenerClosed
				return
			}

			ln.pc.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, addr, err := ln.pc.ReadFrom(buffer)
			if err != nil {
				if errors.Is(err, os.ErrDeadlineExceeded) {
					continue
				}

				if ln.isShutdown() {
					ln.doneChan <- ErrListenerClosed
					return
				}

				ln.doneChan <- err
				return
			}

			p := packet.NewPacket(addr, buffer[:n])
			if p == nil {
				continue
			}

			// non-blocking
			select {
			case ln.rcvQueue <- p:
			default:
				ln.log("listen", func() string { return "receive queue is full" })
			}
		}
	}()

	return ln, nil
}

func (ln *listener) Accept(acceptFn AcceptFunc) (Conn, ConnType, error) {
	if ln.isShutdown() {
		return nil, REJECT, ErrListenerClosed
	}

	select {
	case err := <-ln.doneChan:
		return nil, REJECT, err
	case request := <-ln.backlog:
		if acceptFn == nil {
			ln.reject(request, packet.REJ_PEER)
			break
		}

		mode := acceptFn(&request)
		if mode != PUBLISH && mode != SUBSCRIBE {
			ln.reject(request, packet.REJ_PEER)
			break
		}

		if request.crypto != nil && len(request.passphrase) == 0 {
			ln.reject(request, packet.REJ_BADSECRET)
			break
		}

		// Create a new socket ID
		socketId := uint32(time.Since(ln.start).Microseconds())

		// Select the largest TSBPD delay advertised by the caller, but at least 120ms
		recvTsbpdDelay := uint16(ln.config.ReceiverLatency.Milliseconds())
		sendTsbpdDelay := uint16(ln.config.PeerLatency.Milliseconds())

		if request.handshake.Version == 5 {
			if request.handshake.SRTHS.SendTSBPDDelay > recvTsbpdDelay {
				recvTsbpdDelay = request.handshake.SRTHS.SendTSBPDDelay
			}

			if request.handshake.SRTHS.RecvTSBPDDelay > sendTsbpdDelay {
				sendTsbpdDelay = request.handshake.SRTHS.RecvTSBPDDelay
			}

			ln.config.StreamId = request.handshake.StreamId
		}

		ln.config.Passphrase = request.passphrase

		// Create a new connection
		conn := newSRTConn(srtConnConfig{
			version:                     request.handshake.Version,
			localAddr:                   ln.addr,
			remoteAddr:                  request.addr,
			config:                      ln.config,
			start:                       request.start,
			socketId:                    socketId,
			peerSocketId:                request.handshake.SRTSocketId,
			tsbpdTimeBase:               uint64(request.timestamp),
			tsbpdDelay:                  uint64(recvTsbpdDelay) * 1000,
			peerTsbpdDelay:              uint64(sendTsbpdDelay) * 1000,
			initialPacketSequenceNumber: request.handshake.InitialPacketSequenceNumber,
			crypto:                      request.crypto,
			keyBaseEncryption:           packet.EvenKeyEncrypted,
			onSend:                      ln.send,
			onShutdown:                  ln.handleShutdown,
			logger:                      ln.config.Logger,
		})

		ln.log("connection:new", func() string { return fmt.Sprintf("%#08x (%s) %s", conn.SocketId(), conn.StreamId(), mode) })

		request.handshake.SRTSocketId = socketId
		request.handshake.SynCookie = 0

		if request.handshake.Version == 5 {
			//  3.2.1.1.1.  Handshake Extension Message Flags
			request.handshake.SRTHS.SRTVersion = SRT_VERSION
			request.handshake.SRTHS.SRTFlags.TSBPDSND = true
			request.handshake.SRTHS.SRTFlags.TSBPDRCV = true
			request.handshake.SRTHS.SRTFlags.CRYPT = true
			request.handshake.SRTHS.SRTFlags.TLPKTDROP = true
			request.handshake.SRTHS.SRTFlags.PERIODICNAK = true
			request.handshake.SRTHS.SRTFlags.REXMITFLG = true
			request.handshake.SRTHS.SRTFlags.STREAM = false
			request.handshake.SRTHS.SRTFlags.PACKET_FILTER = false
			request.handshake.SRTHS.RecvTSBPDDelay = recvTsbpdDelay
			request.handshake.SRTHS.SendTSBPDDelay = sendTsbpdDelay
		}

		ln.accept(request)

		// Add the connection to the list of known connections
		ln.lock.Lock()
		ln.conns[socketId] = conn
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

func (ln *listener) reject(request connRequest, reason packet.HandshakeType) {
	p := packet.NewPacket(request.addr, nil)
	p.Header().IsControlPacket = true

	p.Header().ControlType = packet.CTRLTYPE_HANDSHAKE
	p.Header().SubType = 0
	p.Header().TypeSpecific = 0

	p.Header().Timestamp = uint32(time.Since(ln.start).Microseconds())
	p.Header().DestinationSocketId = request.socketId

	request.handshake.HandshakeType = reason

	p.MarshalCIF(request.handshake)

	ln.log("handshake:send:dump", func() string { return p.Dump() })
	ln.log("handshake:send:cif", func() string { return request.handshake.String() })

	ln.send(p)
}

func (ln *listener) accept(request connRequest) {
	p := packet.NewPacket(request.addr, nil)

	p.Header().IsControlPacket = true

	p.Header().ControlType = packet.CTRLTYPE_HANDSHAKE
	p.Header().SubType = 0
	p.Header().TypeSpecific = 0

	p.Header().Timestamp = uint32(time.Since(request.start).Microseconds())
	p.Header().DestinationSocketId = request.socketId

	p.MarshalCIF(request.handshake)

	ln.log("handshake:send:dump", func() string { return p.Dump() })
	ln.log("handshake:send:cif", func() string { return request.handshake.String() })

	ln.send(p)
}

func (ln *listener) isShutdown() bool {
	ln.shutdownLock.RLock()
	defer ln.shutdownLock.RUnlock()

	return ln.shutdown
}

func (ln *listener) Close() {
	ln.shutdownOnce.Do(func() {
		ln.shutdownLock.Lock()
		ln.shutdown = true
		ln.shutdownLock.Unlock()

		ln.lock.RLock()
		for _, conn := range ln.conns {
			conn.close()
		}
		ln.lock.RUnlock()

		ln.stopReader()

		ln.log("listen", func() string { return "closing socket" })

		ln.pc.Close()
	})
}

func (ln *listener) Addr() net.Addr {
	addr, _ := net.ResolveUDPAddr("udp", ln.addr.String())
	return addr
}

func (ln *listener) reader(ctx context.Context) {
	defer func() {
		ln.log("listen", func() string { return "left reader loop" })
	}()

	ln.log("listen", func() string { return "reader loop started" })

	for {
		select {
		case <-ctx.Done():
			return
		case p := <-ln.rcvQueue:
			if ln.isShutdown() {
				break
			}

			ln.log("packet:recv:dump", func() string { return p.Dump() })

			if p.Header().DestinationSocketId == 0 {
				if p.Header().IsControlPacket && p.Header().ControlType == packet.CTRLTYPE_HANDSHAKE {
					ln.handleHandshake(p)
				}

				break
			}

			ln.lock.RLock()
			conn, ok := ln.conns[p.Header().DestinationSocketId]
			ln.lock.RUnlock()

			if !ok {
				// ignore the packet, we don't know the destination
				break
			}

			conn.push(p)
		}
	}
}

// this function must be synchronous in order to allow to safely call Packet.Decommission() afterward.
func (ln *listener) send(p packet.Packet) {
	ln.sendMutex.Lock()
	defer ln.sendMutex.Unlock()

	ln.sendData.Reset()

	if err := p.Marshal(&ln.sendData); err != nil {
		p.Decommission()
		ln.log("packet:send:error", func() string { return "marshalling packet failed" })
		return
	}

	buffer := ln.sendData.Bytes()

	ln.log("packet:send:dump", func() string { return p.Dump() })

	// Write the packet's contents to the wire
	ln.pc.WriteTo(buffer, p.Header().Addr)

	if p.Header().IsControlPacket {
		// Control packets can be decommissioned because they will not be sent again (data packets might be retransferred)
		p.Decommission()
	}
}

func (ln *listener) handleHandshake(p packet.Packet) {
	cif := &packet.CIFHandshake{}

	err := p.UnmarshalCIF(cif)

	ln.log("handshake:recv:dump", func() string { return p.Dump() })
	ln.log("handshake:recv:cif", func() string { return cif.String() })

	if err != nil {
		ln.log("handshake:recv:error", func() string { return err.Error() })
		return
	}

	// Assemble the response (4.3.1.  Caller-Listener Handshake)

	p.Header().ControlType = packet.CTRLTYPE_HANDSHAKE
	p.Header().SubType = 0
	p.Header().TypeSpecific = 0
	p.Header().Timestamp = uint32(time.Since(ln.start).Microseconds())
	p.Header().DestinationSocketId = cif.SRTSocketId

	cif.PeerIP.FromNetAddr(ln.addr)

	if cif.HandshakeType == packet.HSTYPE_INDUCTION {
		// cif
		cif.Version = 5
		cif.EncryptionField = 0 // Don't advertise any specific encryption method
		cif.ExtensionField = 0x4A17
		//cif.initialPacketSequenceNumber = newCircular(0, MAX_SEQUENCENUMBER)
		//cif.maxTransmissionUnitSize = 0
		//cif.maxFlowWindowSize = 0
		//cif.SRTSocketId = 0
		cif.SynCookie = ln.syncookie.Get(p.Header().Addr.String())

		p.MarshalCIF(cif)

		ln.log("handshake:send:dump", func() string { return p.Dump() })
		ln.log("handshake:send:cif", func() string { return cif.String() })

		ln.send(p)
	} else if cif.HandshakeType == packet.HSTYPE_CONCLUSION {
		// Verify the SYN cookie
		if !ln.syncookie.Verify(cif.SynCookie, p.Header().Addr.String()) {
			cif.HandshakeType = packet.REJ_ROGUE
			ln.log("handshake:recv:error", func() string { return "invalid SYN cookie" })
			p.MarshalCIF(cif)
			ln.log("handshake:send:dump", func() string { return p.Dump() })
			ln.log("handshake:send:cif", func() string { return cif.String() })
			ln.send(p)

			return
		}

		// Peer is advertising a too big MSS
		if cif.MaxTransmissionUnitSize > MAX_MSS_SIZE {
			cif.HandshakeType = packet.REJ_ROGUE
			ln.log("handshake:recv:error", func() string { return fmt.Sprintf("MTU is too big (%d bytes)", cif.MaxTransmissionUnitSize) })
			p.MarshalCIF(cif)
			ln.log("handshake:send:dump", func() string { return p.Dump() })
			ln.log("handshake:send:cif", func() string { return cif.String() })
			ln.send(p)

			return
		}

		// If the peer has a smaller MTU size, adjust to it
		if cif.MaxTransmissionUnitSize < ln.config.MSS {
			ln.config.MSS = cif.MaxTransmissionUnitSize
			ln.config.PayloadSize = ln.config.MSS - SRT_HEADER_SIZE - UDP_HEADER_SIZE

			if ln.config.PayloadSize < MIN_PAYLOAD_SIZE {
				cif.HandshakeType = packet.REJ_ROGUE
				ln.log("handshake:recv:error", func() string { return fmt.Sprintf("payload size is too small (%d bytes)", ln.config.PayloadSize) })
				p.MarshalCIF(cif)
				ln.log("handshake:send:dump", func() string { return p.Dump() })
				ln.log("handshake:send:cif", func() string { return cif.String() })
				ln.send(p)
			}
		}

		// We only support HSv4 and HSv5
		if cif.Version == 4 {
			// Check if the type (encryption field + extension field) has the value 2
			if cif.EncryptionField != 0 || cif.ExtensionField != 2 {
				cif.HandshakeType = packet.REJ_ROGUE
				ln.log("handshake:recv:error", func() string { return "invalid type, expecting a value of 2 (UDT_DGRAM)" })
				p.MarshalCIF(cif)
				ln.log("handshake:send:dump", func() string { return p.Dump() })
				ln.log("handshake:send:cif", func() string { return cif.String() })
				ln.send(p)

				return
			}
		} else if cif.Version == 5 {
			// Check if the peer version is sufficient
			if cif.SRTHS.SRTVersion < ln.config.MinVersion {
				cif.HandshakeType = packet.REJ_VERSION
				ln.log("handshake:recv:error", func() string {
					return fmt.Sprintf("peer version insufficient (%#06x), expecting at least %#06x", cif.SRTHS.SRTVersion, ln.config.MinVersion)
				})
				p.MarshalCIF(cif)
				ln.log("handshake:send:dump", func() string { return p.Dump() })
				ln.log("handshake:send:cif", func() string { return cif.String() })
				ln.send(p)

				return
			}

			// Check the required SRT flags
			if !cif.SRTHS.SRTFlags.TSBPDSND || !cif.SRTHS.SRTFlags.TSBPDRCV || !cif.SRTHS.SRTFlags.TLPKTDROP || !cif.SRTHS.SRTFlags.PERIODICNAK || !cif.SRTHS.SRTFlags.REXMITFLG {
				cif.HandshakeType = packet.REJ_ROGUE
				ln.log("handshake:recv:error", func() string { return "not all required flags are set" })
				p.MarshalCIF(cif)
				ln.log("handshake:send:dump", func() string { return p.Dump() })
				ln.log("handshake:send:cif", func() string { return cif.String() })
				ln.send(p)

				return
			}

			// We only support live streaming
			if cif.SRTHS.SRTFlags.STREAM {
				cif.HandshakeType = packet.REJ_MESSAGEAPI
				ln.log("handshake:recv:error", func() string { return "only live streaming is supported" })
				p.MarshalCIF(cif)
				ln.log("handshake:send:dump", func() string { return p.Dump() })
				ln.log("handshake:send:cif", func() string { return cif.String() })
				ln.send(p)

				return
			}
		} else {
			cif.HandshakeType = packet.REJ_ROGUE
			ln.log("handshake:recv:error", func() string { return fmt.Sprintf("only HSv4 and HSv5 are supported (got HSv%d)", cif.Version) })
			p.MarshalCIF(cif)
			ln.log("handshake:send:dump", func() string { return p.Dump() })
			ln.log("handshake:send:cif", func() string { return cif.String() })
			ln.send(p)

			return
		}

		// Fill up a connection request with all relevant data and put it into the backlog

		c := connRequest{
			addr:      p.Header().Addr,
			start:     time.Now(),
			socketId:  cif.SRTSocketId,
			timestamp: p.Header().Timestamp,

			handshake: cif,
		}

		if cif.SRTKM != nil {
			cr, err := crypto.New(int(cif.SRTKM.KLen))
			if err != nil {
				cif.HandshakeType = packet.REJ_ROGUE
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
			cif.HandshakeType = packet.REJ_BACKLOG
			ln.log("handshake:recv:error", func() string { return "backlog is full" })
			p.MarshalCIF(cif)
			ln.log("handshake:send:dump", func() string { return p.Dump() })
			ln.log("handshake:send:cif", func() string { return cif.String() })
			ln.send(p)
		}
	} else {
		if cif.HandshakeType.IsRejection() {
			ln.log("handshake:recv:error", func() string { return fmt.Sprintf("connection rejected: %s", cif.HandshakeType.String()) })
		} else {
			ln.log("handshake:recv:error", func() string { return fmt.Sprintf("unsupported handshake: %s", cif.HandshakeType.String()) })
		}
	}
}

func (ln *listener) log(topic string, message func() string) {
	ln.config.Logger.Print(topic, 0, 2, message)
}
