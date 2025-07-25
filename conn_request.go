package srt

import (
	"fmt"
	"net"
	"time"

	"github.com/datarhei/gosrt/crypto"
	"github.com/datarhei/gosrt/packet"
	"github.com/datarhei/gosrt/rand"
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

	// SocketId return the socketid of the connection.
	SocketId() uint32

	// PeerSocketId returns the socketid of the peer of the connection.
	PeerSocketId() uint32

	// IsEncrypted returns whether the connection is encrypted. If it is
	// encrypted, use SetPassphrase to set the passphrase for decrypting.
	IsEncrypted() bool

	// SetPassphrase sets the passphrase in order to decrypt the incoming
	// data. Returns an error if the passphrase did not work or the connection
	// is not encrypted.
	SetPassphrase(p string) error

	// SetRejectionReason sets the rejection reason for the connection. If
	// no set, REJ_PEER will be used.
	//
	// Deprecated: replaced by Reject().
	SetRejectionReason(r RejectionReason)

	// Accept accepts the request and returns a connection.
	Accept() (Conn, error)

	// Reject rejects the request.
	Reject(r RejectionReason)
}

// connRequest implements the ConnRequest interface
type connRequest struct {
	ln              *listener
	addr            net.Addr
	start           time.Time
	socketId        uint32
	peerSocketId    uint32
	timestamp       uint32
	config          Config
	handshake       *packet.CIFHandshake
	crypto          crypto.Crypto
	passphrase      string
	rejectionReason RejectionReason
}

func newConnRequest(ln *listener, p packet.Packet) *connRequest {
	cif := &packet.CIFHandshake{}

	err := p.UnmarshalCIF(cif)

	ln.log("handshake:recv:dump", func() string { return p.Dump() })
	ln.log("handshake:recv:cif", func() string { return cif.String() })

	if err != nil {
		ln.log("handshake:recv:error", func() string { return err.Error() })
		return nil
	}

	// Assemble the response (4.3.1.  Caller-Listener Handshake)

	p.Header().ControlType = packet.CTRLTYPE_HANDSHAKE
	p.Header().SubType = 0
	p.Header().TypeSpecific = 0
	p.Header().Timestamp = uint32(time.Since(ln.start).Microseconds())
	p.Header().DestinationSocketId = cif.SRTSocketId

	cif.PeerIP.FromNetAddr(ln.addr)

	// Create a copy of the configuration for the connection
	config := ln.config

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
			cif.HandshakeType = packet.HandshakeType(REJ_ROGUE)
			ln.log("handshake:recv:error", func() string { return "invalid SYN cookie" })
			p.MarshalCIF(cif)
			ln.log("handshake:send:dump", func() string { return p.Dump() })
			ln.log("handshake:send:cif", func() string { return cif.String() })
			ln.send(p)

			return nil
		}

		// Peer is advertising a too big MSS
		if cif.MaxTransmissionUnitSize > MAX_MSS_SIZE {
			cif.HandshakeType = packet.HandshakeType(REJ_ROGUE)
			ln.log("handshake:recv:error", func() string { return fmt.Sprintf("MTU is too big (%d bytes)", cif.MaxTransmissionUnitSize) })
			p.MarshalCIF(cif)
			ln.log("handshake:send:dump", func() string { return p.Dump() })
			ln.log("handshake:send:cif", func() string { return cif.String() })
			ln.send(p)

			return nil
		}

		// If the peer has a smaller MTU size, adjust to it
		if cif.MaxTransmissionUnitSize < config.MSS {
			config.MSS = cif.MaxTransmissionUnitSize
			config.PayloadSize = config.MSS - SRT_HEADER_SIZE - UDP_HEADER_SIZE

			if config.PayloadSize < MIN_PAYLOAD_SIZE {
				cif.HandshakeType = packet.HandshakeType(REJ_ROGUE)
				ln.log("handshake:recv:error", func() string { return fmt.Sprintf("payload size is too small (%d bytes)", config.PayloadSize) })
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
				cif.HandshakeType = packet.HandshakeType(REJ_ROGUE)
				ln.log("handshake:recv:error", func() string { return "invalid type, expecting a value of 2 (UDT_DGRAM)" })
				p.MarshalCIF(cif)
				ln.log("handshake:send:dump", func() string { return p.Dump() })
				ln.log("handshake:send:cif", func() string { return cif.String() })
				ln.send(p)

				return nil
			}
		} else if cif.Version == 5 {
			if cif.SRTHS == nil {
				cif.HandshakeType = packet.HandshakeType(REJ_ROGUE)
				ln.log("handshake:recv:error", func() string { return "missing handshake extension" })
				p.MarshalCIF(cif)
				ln.log("handshake:send:dump", func() string { return p.Dump() })
				ln.log("handshake:send:cif", func() string { return cif.String() })
				ln.send(p)

				return nil
			}

			// Check if the peer version is sufficient
			if cif.SRTHS.SRTVersion < config.MinVersion {
				cif.HandshakeType = packet.HandshakeType(REJ_VERSION)
				ln.log("handshake:recv:error", func() string {
					return fmt.Sprintf("peer version insufficient (%#06x), expecting at least %#06x", cif.SRTHS.SRTVersion, config.MinVersion)
				})
				p.MarshalCIF(cif)
				ln.log("handshake:send:dump", func() string { return p.Dump() })
				ln.log("handshake:send:cif", func() string { return cif.String() })
				ln.send(p)

				return nil
			}

			// Check the required SRT flags
			if !cif.SRTHS.SRTFlags.TSBPDSND || !cif.SRTHS.SRTFlags.TSBPDRCV || !cif.SRTHS.SRTFlags.TLPKTDROP || !cif.SRTHS.SRTFlags.PERIODICNAK || !cif.SRTHS.SRTFlags.REXMITFLG {
				cif.HandshakeType = packet.HandshakeType(REJ_ROGUE)
				ln.log("handshake:recv:error", func() string { return "not all required flags are set" })
				p.MarshalCIF(cif)
				ln.log("handshake:send:dump", func() string { return p.Dump() })
				ln.log("handshake:send:cif", func() string { return cif.String() })
				ln.send(p)

				return nil
			}

			// We only support live streaming
			if cif.SRTHS.SRTFlags.STREAM {
				cif.HandshakeType = packet.HandshakeType(REJ_MESSAGEAPI)
				ln.log("handshake:recv:error", func() string { return "only live streaming is supported" })
				p.MarshalCIF(cif)
				ln.log("handshake:send:dump", func() string { return p.Dump() })
				ln.log("handshake:send:cif", func() string { return cif.String() })
				ln.send(p)

				return nil
			}

			// We only support live congestion control
			if cif.HasCongestionCtl && cif.CongestionCtl != "live" {
				cif.HandshakeType = packet.HandshakeType(REJ_CONGESTION)
				ln.log("handshake:recv:error", func() string { return "only live congestion control is supported" })
				p.MarshalCIF(cif)
				ln.log("handshake:send:dump", func() string { return p.Dump() })
				ln.log("handshake:send:cif", func() string { return cif.String() })
				ln.send(p)

				return nil
			}
		} else {
			cif.HandshakeType = packet.HandshakeType(REJ_ROGUE)
			ln.log("handshake:recv:error", func() string { return fmt.Sprintf("only HSv4 and HSv5 are supported (got HSv%d)", cif.Version) })
			p.MarshalCIF(cif)
			ln.log("handshake:send:dump", func() string { return p.Dump() })
			ln.log("handshake:send:cif", func() string { return cif.String() })
			ln.send(p)

			return nil
		}

		req := &connRequest{
			ln:           ln,
			addr:         p.Header().Addr,
			start:        time.Now(),
			peerSocketId: cif.SRTSocketId,
			timestamp:    p.Header().Timestamp,
			config:       config,
			handshake:    cif,
		}

		if cif.SRTKM != nil {
			cr, err := crypto.New(int(cif.SRTKM.KLen))
			if err != nil {
				cif.HandshakeType = packet.HandshakeType(REJ_ROGUE)
				ln.log("handshake:recv:error", func() string { return fmt.Sprintf("crypto: %s", err) })
				p.MarshalCIF(cif)
				ln.log("handshake:send:dump", func() string { return p.Dump() })
				ln.log("handshake:send:cif", func() string { return cif.String() })
				ln.send(p)

				return nil
			}

			req.crypto = cr
		}

		ln.lock.Lock()
		_, exists := ln.connReqs[cif.SRTSocketId]
		if !exists {
			ln.connReqs[cif.SRTSocketId] = req
		}
		ln.lock.Unlock()

		// We received a duplicate request: reject silently
		if exists {
			return nil
		}

		// Already reserve a socketId for this connection
		ln.lock.Lock()
		socketId, err := req.generateSocketId()
		if err == nil {
			ln.conns[socketId] = nil
			req.socketId = socketId
		}
		ln.lock.Unlock()

		// We couldn't create a socketId: reject silently
		if err != nil {
			return nil
		}

		return req
	} else {
		if cif.HandshakeType.IsRejection() {
			ln.log("handshake:recv:error", func() string { return fmt.Sprintf("connection rejected: %s", cif.HandshakeType.String()) })
		} else {
			ln.log("handshake:recv:error", func() string { return fmt.Sprintf("unsupported handshake: %s", cif.HandshakeType.String()) })
		}
	}

	return nil
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

func (req *connRequest) SocketId() uint32 {
	return req.socketId
}

func (req *connRequest) PeerSocketId() uint32 {
	return req.peerSocketId
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

func (req *connRequest) SetRejectionReason(reason RejectionReason) {
	req.rejectionReason = reason
}

func (req *connRequest) Reject(reason RejectionReason) {
	req.ln.lock.Lock()
	defer req.ln.lock.Unlock()

	if _, hasReq := req.ln.connReqs[req.peerSocketId]; !hasReq {
		return
	}

	p := packet.NewPacket(req.addr)
	p.Header().IsControlPacket = true
	p.Header().ControlType = packet.CTRLTYPE_HANDSHAKE
	p.Header().SubType = 0
	p.Header().TypeSpecific = 0
	p.Header().Timestamp = uint32(time.Since(req.ln.start).Microseconds())
	p.Header().DestinationSocketId = req.peerSocketId
	req.handshake.HandshakeType = packet.HandshakeType(reason)
	p.MarshalCIF(req.handshake)
	req.ln.log("handshake:send:dump", func() string { return p.Dump() })
	req.ln.log("handshake:send:cif", func() string { return req.handshake.String() })
	req.ln.send(p)

	delete(req.ln.connReqs, req.peerSocketId)
	delete(req.ln.conns, req.socketId)
}

// generateSocketId generates an SRT SocketID that can be used for this connection
func (req *connRequest) generateSocketId() (uint32, error) {
	for i := 0; i < 10; i++ {
		socketId, err := rand.Uint32()
		if err != nil {
			return 0, fmt.Errorf("could not generate random socket id")
		}

		// check that the socket id is not already in use
		if _, found := req.ln.conns[socketId]; !found {
			return socketId, nil
		}
	}

	return 0, fmt.Errorf("could not generate unused socketid")
}

func (req *connRequest) Accept() (Conn, error) {
	if req.crypto != nil && len(req.passphrase) == 0 {
		req.Reject(REJ_BADSECRET)
		return nil, fmt.Errorf("passphrase is missing")
	}

	req.ln.lock.Lock()
	defer req.ln.lock.Unlock()

	if _, hasReq := req.ln.connReqs[req.peerSocketId]; !hasReq {
		return nil, fmt.Errorf("connection already accepted")
	}

	// Select the largest TSBPD delay advertised by the caller, but at least 120ms
	recvTsbpdDelay := uint16(req.config.ReceiverLatency.Milliseconds())
	sendTsbpdDelay := uint16(req.config.PeerLatency.Milliseconds())

	if req.handshake.Version == 5 {
		if req.handshake.SRTHS.SendTSBPDDelay > recvTsbpdDelay {
			recvTsbpdDelay = req.handshake.SRTHS.SendTSBPDDelay
		}

		if req.handshake.SRTHS.RecvTSBPDDelay > sendTsbpdDelay {
			sendTsbpdDelay = req.handshake.SRTHS.RecvTSBPDDelay
		}

		req.config.StreamId = req.handshake.StreamId
	}

	req.config.Passphrase = req.passphrase

	// Create a new connection
	conn := newSRTConn(srtConnConfig{
		version:                     req.handshake.Version,
		localAddr:                   req.ln.addr,
		remoteAddr:                  req.addr,
		config:                      req.config,
		start:                       req.start,
		socketId:                    req.socketId,
		peerSocketId:                req.peerSocketId,
		tsbpdTimeBase:               uint64(req.timestamp),
		tsbpdDelay:                  uint64(recvTsbpdDelay) * 1000,
		peerTsbpdDelay:              uint64(sendTsbpdDelay) * 1000,
		initialPacketSequenceNumber: req.handshake.InitialPacketSequenceNumber,
		crypto:                      req.crypto,
		keyBaseEncryption:           packet.EvenKeyEncrypted,
		onSend:                      req.ln.send,
		onShutdown:                  req.ln.handleShutdown,
		logger:                      req.config.Logger,
	})

	req.ln.log("connection:new", func() string { return fmt.Sprintf("%#08x (%s)", conn.SocketId(), conn.StreamId()) })

	req.handshake.SRTSocketId = req.socketId
	req.handshake.SynCookie = 0

	if req.handshake.Version == 5 {
		//  3.2.1.1.1.  Handshake Extension Message Flags
		req.handshake.SRTHS.SRTVersion = SRT_VERSION
		req.handshake.SRTHS.SRTFlags.TSBPDSND = true
		req.handshake.SRTHS.SRTFlags.TSBPDRCV = true
		req.handshake.SRTHS.SRTFlags.CRYPT = true
		req.handshake.SRTHS.SRTFlags.TLPKTDROP = true
		req.handshake.SRTHS.SRTFlags.PERIODICNAK = true
		req.handshake.SRTHS.SRTFlags.REXMITFLG = true
		req.handshake.SRTHS.SRTFlags.STREAM = false
		req.handshake.SRTHS.SRTFlags.PACKET_FILTER = false
		req.handshake.SRTHS.RecvTSBPDDelay = recvTsbpdDelay
		req.handshake.SRTHS.SendTSBPDDelay = sendTsbpdDelay
	}

	p := packet.NewPacket(req.addr)
	p.Header().IsControlPacket = true
	p.Header().ControlType = packet.CTRLTYPE_HANDSHAKE
	p.Header().SubType = 0
	p.Header().TypeSpecific = 0
	p.Header().Timestamp = uint32(time.Since(req.start).Microseconds())
	p.Header().DestinationSocketId = req.peerSocketId
	p.MarshalCIF(req.handshake)
	req.ln.log("handshake:send:dump", func() string { return p.Dump() })
	req.ln.log("handshake:send:cif", func() string { return req.handshake.String() })
	req.ln.send(p)

	req.ln.conns[req.socketId] = conn
	delete(req.ln.connReqs, req.peerSocketId)

	return conn, nil
}
