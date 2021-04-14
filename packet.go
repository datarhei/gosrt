// Copyright 2020 FOSS GmbH. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package srt

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
)

const MAX_SEQUENCENUMBER uint32 = 0b01111111_11111111_11111111_11111111
const MAX_TIMESTAMP uint32 = 0b11111111_11111111_11111111_11111111

// Table 1: SRT Control Packet Types
const (
	CTRLTYPE_HANDSHAKE uint16 = 0x0000
	CTRLTYPE_KEEPALIVE uint16 = 0x0001
	CTRLTYPE_ACK       uint16 = 0x0002
	CTRLTYPE_NAK       uint16 = 0x0003
	CTRLTYPE_WARN      uint16 = 0x0004 // unimplemented, receiver->sender
	CTRLTYPE_SHUTDOWN  uint16 = 0x0005
	CTRLTYPE_ACKACK    uint16 = 0x0006
	CRTLTYPE_DROPREQ   uint16 = 0x0007 // unimplemented, sender->receiver
	CRTLTYPE_PEERERROR uint16 = 0x0008 // unimplemented, receiver->sender
	CTRLTYPE_USER      uint16 = 0x7FFF
)

type handshakeType uint32

// Table 4: Handshake Type
const (
	HSTYPE_DONE       handshakeType = 0xFFFFFFFD
	HSTYPE_AGREEMENT  handshakeType = 0xFFFFFFFE
	HSTYPE_CONCLUSION handshakeType = 0xFFFFFFFF
	HSTYPE_WAVEHAND   handshakeType = 0x00000000
	HSTYPE_INDUCTION  handshakeType = 0x00000001
)

// Table 7: Handshake Rejection Reason Codes
const (
	REJ_UNKNOWN    handshakeType = 1000
	REJ_SYSTEM     handshakeType = 1001
	REJ_PEER       handshakeType = 1002
	REJ_RESOURCE   handshakeType = 1003
	REJ_ROGUE      handshakeType = 1004
	REJ_BACKLOG    handshakeType = 1005
	REJ_IPE        handshakeType = 1006
	REJ_CLOSE      handshakeType = 1007
	REJ_VERSION    handshakeType = 1008
	REJ_RDVCOOKIE  handshakeType = 1009
	REJ_BADSECRET  handshakeType = 1010
	REJ_UNSECURE   handshakeType = 1011
	REJ_MESSAGEAPI handshakeType = 1012
	REJ_CONGESTION handshakeType = 1013
	REJ_FILTER     handshakeType = 1014
	REJ_GROUP      handshakeType = 1015
)

func (h handshakeType) String() string {
	switch h {
	case HSTYPE_DONE:
		return "DONE"
	case HSTYPE_AGREEMENT:
		return "AGREEMENT"
	case HSTYPE_CONCLUSION:
		return "CONCLUSION"
	case HSTYPE_WAVEHAND:
		return "WAVEHAND"
	case HSTYPE_INDUCTION:
		return "INDUCTION"
	case REJ_UNKNOWN:
		return "REJ_UNKNOWN (unknown reason)"
	case REJ_SYSTEM:
		return "REJ_SYSTEM (system function error)"
	case REJ_PEER:
		return "REJ_PEER (rejected by peer)"
	case REJ_RESOURCE:
		return "REJ_RESOURCE (resource allocation problem)"
	case REJ_ROGUE:
		return "REJ_ROGUE (incorrect data in handshake)"
	case REJ_BACKLOG:
		return "REJ_BACKLOG (listener's backlog exceeded)"
	case REJ_IPE:
		return "REJ_IPE (internal program error)"
	case REJ_CLOSE:
		return "REJ_CLOSE (socket is closing)"
	case REJ_VERSION:
		return "REJ_VERSION (peer is older version than agent's min)"
	case REJ_RDVCOOKIE:
		return "REJ_RDVCOOKIE (rendezvous cookie collision)"
	case REJ_BADSECRET:
		return "REJ_BADSECRET (wrong password)"
	case REJ_UNSECURE:
		return "REJ_UNSECURE (password required or unexpected)"
	case REJ_MESSAGEAPI:
		return "REJ_MESSAGEAPI (stream flag collision)"
	case REJ_CONGESTION:
		return "REJ_CONGESTION (incompatible congestion-controller type)"
	case REJ_FILTER:
		return "REJ_FILTER (incompatible packet filter)"
	case REJ_GROUP:
		return "REJ_GROUP (incompatible group)"
	}

	return "unknown"
}

func (h handshakeType) IsUnknown() bool {
	return h.String() == "unkonwn"
}

func (h handshakeType) IsHandshake() bool {
	switch h {
	case HSTYPE_DONE:
	case HSTYPE_AGREEMENT:
	case HSTYPE_CONCLUSION:
	case HSTYPE_WAVEHAND:
	case HSTYPE_INDUCTION:
	default:
		return false
	}

	return true
}

func (h handshakeType) IsRejection() bool {
	if h.IsUnknown() {
		return false
	} else if h.IsHandshake() {
		return false
	}

	return true
}

func (h handshakeType) Val() uint32 {
	return uint32(h)
}

// Table 6: Handshake Extension Message Flags
const (
	SRTFLAG_TSBPDSND      uint32 = 1 << 0
	SRTFLAG_TSBPDRCV      uint32 = 1 << 1
	SRTFLAG_CRYPT         uint32 = 1 << 2
	SRTFLAG_TLPKTDROP     uint32 = 1 << 3
	SRTFLAG_PERIODICNAK   uint32 = 1 << 4
	SRTFLAG_REXMITFLG     uint32 = 1 << 5
	SRTFLAG_STREAM        uint32 = 1 << 6
	SRTFLAG_PACKET_FILTER uint32 = 1 << 7
)

// Table 5: Handshake Extension Type values
const (
	EXTTYPE_HSREQ      uint16 = 1
	EXTTYPE_HSRSP      uint16 = 2
	EXTTYPE_KMREQ      uint16 = 3
	EXTTYPE_KMRSP      uint16 = 4
	EXTTYPE_SID        uint16 = 5
	EXTTYPE_CONGESTION uint16 = 6
	EXTTYPE_FILTER     uint16 = 7
	EXTTYPE_GROUP      uint16 = 8
)

type packet interface {
	String() string
	Clone() packet
	Header() *pktHeader
	Data() []byte
	SetData([]byte)
	Len() uint64
	Unmarshal(data []byte) error
	Marshal(w io.Writer)
	Dump() string
	MarshalCIF(c cifInterface)
	UnmarshalCIF(c cifInterface) error
	Decommission()
}

type pktHeader struct {
	addr            net.Addr
	isControlPacket bool
	pktTsbpdTime    uint64

	// control packet fields
	controlType  uint16
	subType      uint16
	typeSpecific uint32

	// data packet fields
	packetSequenceNumber    circular
	packetPositionFlag      packetPosition
	orderFlag               bool
	keyBaseEncryptionFlag   packetEncryption
	retransmittedPacketFlag bool
	messageNumber           uint32

	// common fields
	timestamp           uint32
	destinationSocketId uint32
}

type pkt struct {
	header pktHeader

	payload *bytes.Buffer
}

type pool struct {
	pool sync.Pool
}

func newPool() *pool {
	return &pool{
		pool: sync.Pool{
			New: func() interface{} {
				return new(bytes.Buffer)
			},
		},
	}
}

func (p *pool) Get() *bytes.Buffer {
	b := p.pool.Get().(*bytes.Buffer)
	b.Reset()

	return b
}

func (p *pool) Put(b *bytes.Buffer) {
	p.pool.Put(b)
}

var payloadPool *pool = newPool()

func newPacket(addr net.Addr, rawdata []byte) packet {
	p := &pkt{
		header: pktHeader{
			addr:                  addr,
			packetSequenceNumber:  newCircular(0, 0b01111111_11111111_11111111_11111111),
			packetPositionFlag:    singlePacket,
			keyBaseEncryptionFlag: unencryptedPacket,
			messageNumber:         1,
		},
		payload: payloadPool.Get(),
	}

	if len(rawdata) != 0 {
		if err := p.Unmarshal(rawdata); err != nil {
			return nil
		}
	}

	return p
}

func (p *pkt) Decommission() {
	payloadPool.Put(p.payload)
	p.payload = nil
}

func (p pkt) String() string {
	var b strings.Builder

	fmt.Fprintf(&b, "timestamp=%#08x, destId=%#08x\n", p.header.timestamp, p.header.destinationSocketId)

	if p.header.isControlPacket {
		fmt.Fprintf(&b, "control packet:\n")
		fmt.Fprintf(&b, "   controlType=%#04x\n", p.header.controlType)
		fmt.Fprintf(&b, "   subType=%#04x\n", p.header.subType)
		fmt.Fprintf(&b, "   typeSpecific=%#08x\n", p.header.typeSpecific)
	} else {
		fmt.Fprintf(&b, "data packet:\n")
		fmt.Fprintf(&b, "   packetSequenceNumber=%#08x (%d)\n", p.header.packetSequenceNumber.Val(), p.header.packetSequenceNumber.Val())
		fmt.Fprintf(&b, "   packetPositionFlag=%s\n", p.header.packetPositionFlag)
		fmt.Fprintf(&b, "   orderFlag=%v\n", p.header.orderFlag)
		fmt.Fprintf(&b, "   keyBaseEncryptionFlag=%s\n", p.header.keyBaseEncryptionFlag)
		fmt.Fprintf(&b, "   retransmittedPacketFlag=%v\n", p.header.retransmittedPacketFlag)
		fmt.Fprintf(&b, "   messageNumber=%#08x (%d)\n", p.header.messageNumber, p.header.messageNumber)
	}

	fmt.Fprintf(&b, "data (%d bytes)\n%s", p.Len(), p.Dump())

	return b.String()
}

func (p *pkt) Clone() packet {
	clone := *p

	clone.payload = payloadPool.Get()
	clone.payload.Write(p.payload.Bytes())

	return &clone
}

func (p *pkt) Header() *pktHeader {
	return &p.header
}

func (p *pkt) SetData(data []byte) {
	p.payload.Reset()
	p.payload.Write(data)
}

func (p *pkt) Data() []byte {
	return p.payload.Bytes()
}

func (p *pkt) Len() uint64 {
	return uint64(p.payload.Len())
}

func (p *pkt) Unmarshal(data []byte) error {
	if len(data) < 16 {
		return fmt.Errorf("data too short to unmarshal")
	}

	p.header.isControlPacket = (data[0] & 0x80) != 0

	if p.header.isControlPacket {
		p.header.controlType = binary.BigEndian.Uint16(data[0:]) & ^uint16(1<<15) // clear the first bit
		p.header.subType = binary.BigEndian.Uint16(data[2:])
		p.header.typeSpecific = binary.BigEndian.Uint32(data[4:])
	} else {
		p.header.packetSequenceNumber = newCircular(binary.BigEndian.Uint32(data[0:]), MAX_SEQUENCENUMBER)
		p.header.packetPositionFlag = packetPosition((data[4] & 0b11000000) >> 6)
		p.header.orderFlag = (data[4] & 0b00100000) != 0
		p.header.keyBaseEncryptionFlag = packetEncryption((data[4] & 0b00011000) >> 3)
		p.header.retransmittedPacketFlag = (data[4] & 0b00000100) != 0
		p.header.messageNumber = binary.BigEndian.Uint32(data[4:]) & ^uint32(0b11111000<<24)
	}

	p.header.timestamp = binary.BigEndian.Uint32(data[8:])
	p.header.destinationSocketId = binary.BigEndian.Uint32(data[12:])

	p.payload.Reset()
	p.payload.Write(data[16:])

	return nil
}

func (p *pkt) Marshal(w io.Writer) {
	var buffer [16]byte

	if p.header.isControlPacket {
		binary.BigEndian.PutUint16(buffer[0:], p.header.controlType)  // control type
		binary.BigEndian.PutUint16(buffer[2:], p.header.subType)      // sub type
		binary.BigEndian.PutUint32(buffer[4:], p.header.typeSpecific) // type specific

		buffer[0] |= 0x80
	} else {
		binary.BigEndian.PutUint32(buffer[0:], p.header.packetSequenceNumber.Val()) // sequence number

		p.header.typeSpecific = 0

		p.header.typeSpecific |= (uint32(p.header.packetPositionFlag) << 6)
		if p.header.orderFlag {
			p.header.typeSpecific |= (1 << 5)
		}
		p.header.typeSpecific |= (uint32(p.header.keyBaseEncryptionFlag) << 3)
		if p.header.retransmittedPacketFlag {
			p.header.typeSpecific |= (1 << 2)
		}
		p.header.typeSpecific = p.header.typeSpecific << 24
		p.header.typeSpecific += p.header.messageNumber

		binary.BigEndian.PutUint32(buffer[4:], p.header.typeSpecific) // sequence number
	}

	binary.BigEndian.PutUint32(buffer[8:], p.header.timestamp)            // timestamp
	binary.BigEndian.PutUint32(buffer[12:], p.header.destinationSocketId) // destination socket ID

	w.Write(buffer[0:])
	w.Write(p.payload.Bytes())
}

func (p *pkt) Dump() string {
	return hex.Dump(p.payload.Bytes())
}

func (p *pkt) MarshalCIF(c cifInterface) {
	if !p.header.isControlPacket {
		return
	}

	p.payload.Reset()
	c.Marshal(p.payload)
}

func (p *pkt) UnmarshalCIF(c cifInterface) error {
	if !p.header.isControlPacket {
		return nil
	}

	return c.Unmarshal(p.payload.Bytes())
}

type cifInterface interface {
	Marshal(w io.Writer)
	Unmarshal(data []byte) error
}

// 3.2.1.  Handshake
type cifHandshake struct {
	isRequest bool

	version                     uint32
	encryptionField             uint16
	extensionField              uint16
	initialPacketSequenceNumber circular
	maxTransmissionUnitSize     uint32
	maxFlowWindowSize           uint32
	handshakeType               handshakeType
	srtSocketId                 uint32
	synCookie                   uint32
	peerIP                      IP

	hasHS  bool
	hasKM  bool
	hasSID bool

	// 3.2.1.1.  Handshake Extension Message
	srtVersion uint32
	srtFlags   struct { // 3.2.1.1.1.  Handshake Extension Message Flags
		TSBPDSND      bool
		TSBPDRCV      bool
		CRYPT         bool
		TLPKTDROP     bool
		PERIODICNAK   bool
		REXMITFLG     bool
		STREAM        bool
		PACKET_FILTER bool
	}
	recvTSBPDDelay uint16 // milliseconds, see "4.4.  SRT Buffer Latency"
	sendTSBPDDelay uint16 // milliseconds, see "4.4.  SRT Buffer Latency"

	// 3.2.1.2.  Key Material Extension Message
	srtKM *cifKM

	// 3.2.1.3.  Stream ID Extension Message
	streamId string
}

func (c cifHandshake) String() string {
	var b strings.Builder

	fmt.Fprintf(&b, "handshake\n")

	fmt.Fprintf(&b, "   version: %#08x\n", c.version)
	fmt.Fprintf(&b, "   encryptionField: %#04x\n", c.encryptionField)
	fmt.Fprintf(&b, "   extensionField: %#04x\n", c.extensionField)
	fmt.Fprintf(&b, "   initialPacketSequenceNumber: %#08x\n", c.initialPacketSequenceNumber.Val())
	fmt.Fprintf(&b, "   maxTransmissionUnitSize: %#08x (%d)\n", c.maxTransmissionUnitSize, c.maxTransmissionUnitSize)
	fmt.Fprintf(&b, "   maxFlowWindowSize: %#08x (%d)\n", c.maxFlowWindowSize, c.maxFlowWindowSize)
	fmt.Fprintf(&b, "   handshakeType: %#08x (%s)\n", c.handshakeType.Val(), c.handshakeType.String())
	fmt.Fprintf(&b, "   srtSocketId: %#08x\n", c.srtSocketId)
	fmt.Fprintf(&b, "   synCookie: %#08x\n", c.synCookie)
	fmt.Fprintf(&b, "   peerIP: %s\n", c.peerIP)

	if c.hasHS {
		fmt.Fprintf(&b, "   SRT_CMD_HS(REQ/RSP)\n")
		fmt.Fprintf(&b, "      srtVersion: %#08x\n", c.srtVersion)
		fmt.Fprintf(&b, "      srtFlags:\n")
		fmt.Fprintf(&b, "         TSBPDSND     : %v\n", c.srtFlags.TSBPDSND)
		fmt.Fprintf(&b, "         TSBPDRCV     : %v\n", c.srtFlags.TSBPDRCV)
		fmt.Fprintf(&b, "         CRYPT        : %v\n", c.srtFlags.CRYPT)
		fmt.Fprintf(&b, "         TLPKTDROP    : %v\n", c.srtFlags.TLPKTDROP)
		fmt.Fprintf(&b, "         PERIODICNAK  : %v\n", c.srtFlags.PERIODICNAK)
		fmt.Fprintf(&b, "         REXMITFLG    : %v\n", c.srtFlags.REXMITFLG)
		fmt.Fprintf(&b, "         STREAM       : %v\n", c.srtFlags.STREAM)
		fmt.Fprintf(&b, "         PACKET_FILTER: %v\n", c.srtFlags.PACKET_FILTER)
		fmt.Fprintf(&b, "      recvTSBPDDelay: %#04x (%dms)\n", c.recvTSBPDDelay, c.recvTSBPDDelay)
		fmt.Fprintf(&b, "      sendTSBPDDelay: %#04x (%dms)\n", c.sendTSBPDDelay, c.sendTSBPDDelay)
	}

	if c.hasKM {
		fmt.Fprintf(&b, "   SRT_CMD_KM(REQ/RSP)\n")
		fmt.Fprintf(&b, "      s: %d\n", c.srtKM.s)
		fmt.Fprintf(&b, "      version: %d\n", c.srtKM.version)
		fmt.Fprintf(&b, "      packetType: %d\n", c.srtKM.packetType)
		fmt.Fprintf(&b, "      sign: %#08x\n", c.srtKM.sign)
		fmt.Fprintf(&b, "      resv1: %d\n", c.srtKM.resv1)
		fmt.Fprintf(&b, "      keyBasedEncryption: %s\n", c.srtKM.keyBasedEncryption.String())
		fmt.Fprintf(&b, "      keyEncryptionKeyIndex: %d\n", c.srtKM.keyEncryptionKeyIndex)
		fmt.Fprintf(&b, "      cipher: %d\n", c.srtKM.cipher)
		fmt.Fprintf(&b, "      authentication: %d\n", c.srtKM.authentication)
		fmt.Fprintf(&b, "      streamEncapsulation: %d\n", c.srtKM.streamEncapsulation)
		fmt.Fprintf(&b, "      resv2: %d\n", c.srtKM.resv2)
		fmt.Fprintf(&b, "      resv3: %d\n", c.srtKM.resv3)
		fmt.Fprintf(&b, "      sLen: %d (%d)\n", c.srtKM.sLen, c.srtKM.sLen/4)
		fmt.Fprintf(&b, "      kLen: %d (%d)\n", c.srtKM.kLen, c.srtKM.kLen/4)
		fmt.Fprintf(&b, "      salt: %#08x\n", c.srtKM.salt)
		fmt.Fprintf(&b, "      wrap: %#08x\n", c.srtKM.wrap)
	}

	if c.hasSID {
		fmt.Fprintf(&b, "   SRT_CMD_SID\n")
		fmt.Fprintf(&b, "      streamId : %s\n", c.streamId)
	}

	return b.String()
}

func (c *cifHandshake) Unmarshal(data []byte) error {
	if len(data) < 48 {
		return fmt.Errorf("data too short to unmarshal")
	}

	c.version = binary.BigEndian.Uint32(data[0:])
	c.encryptionField = binary.BigEndian.Uint16(data[4:])
	c.extensionField = binary.BigEndian.Uint16(data[6:])
	c.initialPacketSequenceNumber = newCircular(binary.BigEndian.Uint32(data[8:])&MAX_SEQUENCENUMBER, MAX_SEQUENCENUMBER)
	c.maxTransmissionUnitSize = binary.BigEndian.Uint32(data[12:])
	c.maxFlowWindowSize = binary.BigEndian.Uint32(data[16:])
	c.handshakeType = handshakeType(binary.BigEndian.Uint32(data[20:]))
	c.srtSocketId = binary.BigEndian.Uint32(data[24:])
	c.synCookie = binary.BigEndian.Uint32(data[28:])
	c.peerIP.Unmarshal(data[32:48])

	//if c.handshakeType != HSTYPE_INDUCTION && c.handshakeType != HSTYPE_CONCLUSION {
	//	return fmt.Errorf("unimplemented handshake type")
	//}

	if c.handshakeType == HSTYPE_INDUCTION {
		// Nothing more to unmarshal
		return nil
	}

	if c.handshakeType != HSTYPE_CONCLUSION {
		// Everything else is currently not supported
		return nil
	}

	if c.extensionField == 0 {
		return nil
	}

	if len(data) <= 48 {
		return fmt.Errorf("data too short to unmarshal")
	}

	switch c.encryptionField {
	case 0:
	case 2:
	case 3:
	case 4:
	default:
		return fmt.Errorf("invalid encryption field value (%d)", c.encryptionField)
	}

	pivot := data[48:]

	for {
		extensionType := binary.BigEndian.Uint16(pivot[0:])
		extensionLength := int(binary.BigEndian.Uint16(pivot[2:])) * 4

		pivot = pivot[4:]

		if extensionType == EXTTYPE_HSREQ || extensionType == EXTTYPE_HSRSP {
			// 3.2.1.1.  Handshake Extension Message
			if extensionLength != 12 || len(pivot) < extensionLength {
				return fmt.Errorf("invalid extension length")
			}

			c.hasHS = true

			c.srtVersion = binary.BigEndian.Uint32(pivot[0:])
			srtFlags := binary.BigEndian.Uint32(pivot[4:])

			c.srtFlags.TSBPDSND = (srtFlags&SRTFLAG_TSBPDSND != 0)
			c.srtFlags.TSBPDRCV = (srtFlags&SRTFLAG_TSBPDRCV != 0)
			c.srtFlags.CRYPT = (srtFlags&SRTFLAG_CRYPT != 0)
			c.srtFlags.TLPKTDROP = (srtFlags&SRTFLAG_TLPKTDROP != 0)
			c.srtFlags.PERIODICNAK = (srtFlags&SRTFLAG_PERIODICNAK != 0)
			c.srtFlags.REXMITFLG = (srtFlags&SRTFLAG_REXMITFLG != 0)
			c.srtFlags.STREAM = (srtFlags&SRTFLAG_STREAM != 0)
			c.srtFlags.PACKET_FILTER = (srtFlags&SRTFLAG_PACKET_FILTER != 0)

			c.recvTSBPDDelay = binary.BigEndian.Uint16(pivot[8:])
			c.sendTSBPDDelay = binary.BigEndian.Uint16(pivot[10:])
		} else if extensionType == EXTTYPE_KMREQ || extensionType == EXTTYPE_KMRSP {
			// 3.2.1.2.  Key Material Extension Message
			if len(pivot) < extensionLength {
				return fmt.Errorf("invalid extension length")
			}

			c.hasKM = true

			c.srtKM = &cifKM{}

			if err := c.srtKM.Unmarshal(pivot); err != nil {
				return err
			}

			if c.encryptionField == 0 {
				// using default cipher family and key size (AES-128)
				c.encryptionField = 2
			}

			if c.encryptionField == 2 && c.srtKM.kLen != 16 {
				return fmt.Errorf("invalid key length for AES-128 (%d bit)", c.srtKM.kLen*8)
			} else if c.encryptionField == 3 && c.srtKM.kLen != 24 {
				return fmt.Errorf("invalid key length for AES-192 (%d bit)", c.srtKM.kLen*8)
			} else if c.encryptionField == 4 && c.srtKM.kLen != 32 {
				return fmt.Errorf("invalid key length for AES-256 (%d bit)", c.srtKM.kLen*8)
			}
		} else if extensionType == EXTTYPE_SID {
			// 3.2.1.3.  Stream ID Extension Message
			if extensionLength > 512 || len(pivot) < extensionLength {
				return fmt.Errorf("invalid extension length")
			}

			c.hasSID = true

			var b strings.Builder

			for i := 0; i < extensionLength; i += 4 {
				b.WriteByte(pivot[i+3])
				b.WriteByte(pivot[i+2])
				b.WriteByte(pivot[i+1])
				b.WriteByte(pivot[i+0])
			}

			c.streamId = strings.TrimRight(b.String(), "\x00")
		} else {
			return fmt.Errorf("unimplemented extension (%d)", extensionType)
		}

		if len(pivot) > extensionLength {
			pivot = pivot[extensionLength:]
		} else {
			break
		}
	}

	return nil
}

func (c *cifHandshake) Marshal(w io.Writer) {
	var buffer [128]byte

	if len(c.streamId) == 0 {
		c.hasSID = false
	}

	if c.handshakeType == HSTYPE_CONCLUSION {
		c.extensionField = 0
	}

	if c.hasHS {
		c.extensionField = c.extensionField | 1
	}

	if c.hasKM {
		c.extensionField = c.extensionField | 2
	}

	if c.hasSID {
		c.extensionField = c.extensionField | 4
	}

	binary.BigEndian.PutUint32(buffer[0:], c.version)                           // version
	binary.BigEndian.PutUint16(buffer[4:], c.encryptionField)                   // encryption field
	binary.BigEndian.PutUint16(buffer[6:], c.extensionField)                    // extension field
	binary.BigEndian.PutUint32(buffer[8:], c.initialPacketSequenceNumber.Val()) // initialPacketSequenceNumber
	binary.BigEndian.PutUint32(buffer[12:], c.maxTransmissionUnitSize)          // maxTransmissionUnitSize
	binary.BigEndian.PutUint32(buffer[16:], c.maxFlowWindowSize)                // maxFlowWindowSize
	binary.BigEndian.PutUint32(buffer[20:], c.handshakeType.Val())              // handshakeType
	binary.BigEndian.PutUint32(buffer[24:], c.srtSocketId)                      // Socket ID of the Listener, should be some own generated ID
	binary.BigEndian.PutUint32(buffer[28:], c.synCookie)                        // SYN cookie
	c.peerIP.Marshal(buffer[32:])                                               // peerIP

	w.Write(buffer[:48])

	if c.hasHS {
		if c.isRequest {
			binary.BigEndian.PutUint16(buffer[0:], EXTTYPE_HSREQ)
		} else {
			binary.BigEndian.PutUint16(buffer[0:], EXTTYPE_HSRSP)
		}

		binary.BigEndian.PutUint16(buffer[2:], 3)

		binary.BigEndian.PutUint32(buffer[4:], c.srtVersion)
		var srtFlags uint32 = 0

		if c.srtFlags.TSBPDSND {
			srtFlags |= SRTFLAG_TSBPDSND
		}

		if c.srtFlags.TSBPDRCV {
			srtFlags |= SRTFLAG_TSBPDRCV
		}

		if c.srtFlags.CRYPT {
			srtFlags |= SRTFLAG_CRYPT
		}

		if c.srtFlags.TLPKTDROP {
			srtFlags |= SRTFLAG_TLPKTDROP
		}

		if c.srtFlags.PERIODICNAK {
			srtFlags |= SRTFLAG_PERIODICNAK
		}

		if c.srtFlags.REXMITFLG {
			srtFlags |= SRTFLAG_REXMITFLG
		}

		if c.srtFlags.STREAM {
			srtFlags |= SRTFLAG_STREAM
		}

		if c.srtFlags.PACKET_FILTER {
			srtFlags |= SRTFLAG_PACKET_FILTER
		}

		binary.BigEndian.PutUint32(buffer[8:], srtFlags)
		binary.BigEndian.PutUint16(buffer[12:], c.recvTSBPDDelay)
		binary.BigEndian.PutUint16(buffer[14:], c.sendTSBPDDelay)

		w.Write(buffer[:16])
	}

	if c.hasKM {
		var data bytes.Buffer

		c.srtKM.Marshal(&data)

		if c.isRequest {
			binary.BigEndian.PutUint16(buffer[0:], EXTTYPE_KMREQ)
		} else {
			binary.BigEndian.PutUint16(buffer[0:], EXTTYPE_KMRSP)
		}

		binary.BigEndian.PutUint16(buffer[2:], uint16(data.Len()/4))

		w.Write(buffer[:4])
		w.Write(data.Bytes())
	}

	if c.hasSID {
		streamId := bytes.NewBufferString(c.streamId)

		missing := (4 - streamId.Len()%4)
		if missing < 4 {
			for i := 0; i < missing; i++ {
				streamId.WriteByte(0)
			}
		}

		binary.BigEndian.PutUint16(buffer[0:], EXTTYPE_SID)
		binary.BigEndian.PutUint16(buffer[2:], uint16(streamId.Len()/4))

		w.Write(buffer[:4])

		b := streamId.Bytes()

		for i := 0; i < len(b); i += 4 {
			buffer[0] = b[i+3]
			buffer[1] = b[i+2]
			buffer[2] = b[i+1]
			buffer[3] = b[i+0]

			w.Write(buffer[:4])
		}
	}
}

// 3.2.2.  Key Material
type cifKM struct {
	s                     uint8
	version               uint8
	packetType            uint8
	sign                  uint16
	resv1                 uint8
	keyBasedEncryption    packetEncryption
	keyEncryptionKeyIndex uint32
	cipher                uint8
	authentication        uint8
	streamEncapsulation   uint8
	resv2                 uint8
	resv3                 uint16
	sLen                  uint16
	kLen                  uint16
	salt                  []byte
	wrap                  []byte
}

func (c cifKM) String() string {
	var b strings.Builder

	fmt.Fprintf(&b, "KM\n")

	fmt.Fprintf(&b, "   s: %d\n", c.s)
	fmt.Fprintf(&b, "   version: %d\n", c.version)
	fmt.Fprintf(&b, "   packetType: %d\n", c.packetType)
	fmt.Fprintf(&b, "   sign: %#08x\n", c.sign)
	fmt.Fprintf(&b, "   resv1: %d\n", c.resv1)
	fmt.Fprintf(&b, "   keyBasedEncryption: %s\n", c.keyBasedEncryption.String())
	fmt.Fprintf(&b, "   keyEncryptionKeyIndex: %d\n", c.keyEncryptionKeyIndex)
	fmt.Fprintf(&b, "   cipher: %d\n", c.cipher)
	fmt.Fprintf(&b, "   authentication: %d\n", c.authentication)
	fmt.Fprintf(&b, "   streamEncapsulation: %d\n", c.streamEncapsulation)
	fmt.Fprintf(&b, "   resv2: %d\n", c.resv2)
	fmt.Fprintf(&b, "   resv3: %d\n", c.resv3)
	fmt.Fprintf(&b, "   sLen: %d (%d)\n", c.sLen, c.sLen/4)
	fmt.Fprintf(&b, "   kLen: %d (%d)\n", c.kLen, c.kLen/4)
	fmt.Fprintf(&b, "   salt: %#08x\n", c.salt)
	fmt.Fprintf(&b, "   wrap: %#08x\n", c.wrap)

	return b.String()
}

func (c *cifKM) Unmarshal(data []byte) error {
	if len(data) < 16 {
		return fmt.Errorf("data too short to unmarshal")
	}

	c.s = uint8(data[0] & 0b1000_0000 >> 7)
	if c.s != 0 {
		return fmt.Errorf("invalid value for S")
	}

	c.version = uint8(data[0] & 0b0111_0000 >> 4)
	if c.version != 1 {
		return fmt.Errorf("invalid version")
	}

	c.packetType = uint8(data[0] & 0b0000_1111)
	if c.packetType != 2 {
		return fmt.Errorf("invalid packet type (%d)", c.packetType)
	}

	c.sign = binary.BigEndian.Uint16(data[1:])
	if c.sign != 0x2029 {
		return fmt.Errorf("invalid signature (%#08x)", c.sign)
	}

	c.resv1 = uint8(data[3] & 0b1111_1100 >> 2)
	c.keyBasedEncryption = packetEncryption(data[3] & 0b0000_0011)
	if !c.keyBasedEncryption.IsValid() || c.keyBasedEncryption == unencryptedPacket {
		return fmt.Errorf("invalid extension format (KK must not be 0)")
	}

	c.keyEncryptionKeyIndex = binary.BigEndian.Uint32(data[4:])
	if c.keyEncryptionKeyIndex != 0 {
		return fmt.Errorf("invalid key encryption key index (%d)", c.keyEncryptionKeyIndex)
	}

	c.cipher = uint8(data[8])
	c.authentication = uint8(data[9])
	c.streamEncapsulation = uint8(data[10])
	if c.streamEncapsulation != 2 {
		return fmt.Errorf("invalid stream encapsulation (%d)", c.streamEncapsulation)
	}

	c.resv2 = uint8(data[11])
	c.resv3 = binary.BigEndian.Uint16(data[12:])
	c.sLen = uint16(data[14]) * 4
	c.kLen = uint16(data[15]) * 4

	switch c.kLen {
	case 16:
	case 24:
	case 32:
	default:
		return fmt.Errorf("invalid key length")
	}

	offset := 16

	if c.sLen != 0 {
		if c.sLen != 16 {
			return fmt.Errorf("invalid salt length")
		}

		if len(data[offset:]) < 16 {
			return fmt.Errorf("data too short to unmarshal")
		}

		c.salt = make([]byte, 16)
		copy(c.salt, data[offset:])

		offset += 16
	}

	n := 1
	if c.keyBasedEncryption == evenAndOddKey {
		n = 2
	}

	if len(data[offset:]) < n*int(c.kLen)+8 {
		return fmt.Errorf("data too short to unmarshal")
	}

	c.wrap = make([]byte, n*int(c.kLen)+8)
	copy(c.wrap, data[offset:])

	return nil
}

func (c *cifKM) Marshal(w io.Writer) {
	var buffer [128]byte

	b := byte(0)

	b |= (c.s << 7) & 0b1000_0000
	b |= (c.version << 4) & 0b0111_0000
	b |= c.packetType & 0b0000_1111

	buffer[0] = b
	binary.BigEndian.PutUint16(buffer[1:], c.sign)

	b = 0
	b |= (c.resv1 << 2) & 0b1111_1100
	b |= uint8(c.keyBasedEncryption) & 0b0000_0011

	buffer[3] = b
	binary.BigEndian.PutUint32(buffer[4:], c.keyEncryptionKeyIndex)

	buffer[8] = byte(c.cipher)
	buffer[9] = byte(c.authentication)
	buffer[10] = byte(c.streamEncapsulation)
	buffer[11] = byte(c.resv2)

	binary.BigEndian.PutUint16(buffer[12:], c.resv3)

	buffer[14] = byte(c.sLen / 4)
	buffer[15] = byte(c.kLen / 4)

	offset := 16

	if c.sLen != 0 {
		copy(buffer[offset:], c.salt[0:])
		offset += len(c.salt)
	}

	copy(buffer[offset:], c.wrap)
	offset += len(c.wrap)

	w.Write(buffer[:offset])
}

// 3.2.4.  ACK (Acknowledgment)
type cifACK struct {
	isLite                      bool
	isSmall                     bool
	lastACKPacketSequenceNumber circular
	rtt                         uint32
	rttVar                      uint32
	availableBufferSize         uint32
	packetsReceivingRate        uint32
	estimatedLinkCapacity       uint32
	receivingRate               uint32
}

func (c cifACK) String() string {
	var b strings.Builder

	ackType := "full"
	if c.isLite {
		ackType = "lite"
	} else if c.isSmall {
		ackType = "small"
	}

	fmt.Fprintf(&b, "ACK (type: %s)\n", ackType)

	fmt.Fprintf(&b, "   lastACKPacketSequenceNumber: %#08x (%d)\n", c.lastACKPacketSequenceNumber.Val(), c.lastACKPacketSequenceNumber.Val())

	if !c.isLite {
		fmt.Fprintf(&b, "   rtt: %#08x\n", c.rtt)
		fmt.Fprintf(&b, "   rttVar: %#08x\n", c.rttVar)
		fmt.Fprintf(&b, "   availableBufferSize: %#08x\n", c.availableBufferSize)
		fmt.Fprintf(&b, "   packetsReceivingRate: %#08x\n", c.packetsReceivingRate)
		fmt.Fprintf(&b, "   estimatedLinkCapacity: %#08x\n", c.estimatedLinkCapacity)
		fmt.Fprintf(&b, "   receivingRate: %#08x\n", c.receivingRate)
	}

	return b.String()
}

func (c *cifACK) Unmarshal(data []byte) error {
	c.isLite = false
	c.isSmall = false

	if len(data) == 4 {
		c.isLite = true

		c.lastACKPacketSequenceNumber = newCircular(binary.BigEndian.Uint32(data[0:])&MAX_SEQUENCENUMBER, MAX_SEQUENCENUMBER)

		return nil
	} else if len(data) == 16 {
		c.isSmall = true

		c.lastACKPacketSequenceNumber = newCircular(binary.BigEndian.Uint32(data[0:])&MAX_SEQUENCENUMBER, MAX_SEQUENCENUMBER)
		c.rtt = binary.BigEndian.Uint32(data[4:])
		c.rttVar = binary.BigEndian.Uint32(data[8:])
		c.availableBufferSize = binary.BigEndian.Uint32(data[12:])

		return nil
	}

	if len(data) < 28 {
		return fmt.Errorf("data too short to unmarshal")
	}

	c.lastACKPacketSequenceNumber = newCircular(binary.BigEndian.Uint32(data[0:])&MAX_SEQUENCENUMBER, MAX_SEQUENCENUMBER)
	c.rtt = binary.BigEndian.Uint32(data[4:])
	c.rttVar = binary.BigEndian.Uint32(data[8:])
	c.availableBufferSize = binary.BigEndian.Uint32(data[12:])
	c.packetsReceivingRate = binary.BigEndian.Uint32(data[16:])
	c.estimatedLinkCapacity = binary.BigEndian.Uint32(data[20:])
	c.receivingRate = binary.BigEndian.Uint32(data[24:])

	return nil
}

func (c *cifACK) Marshal(w io.Writer) {
	var buffer [28]byte

	binary.BigEndian.PutUint32(buffer[0:], c.lastACKPacketSequenceNumber.Val())
	binary.BigEndian.PutUint32(buffer[4:], c.rtt)
	binary.BigEndian.PutUint32(buffer[8:], c.rttVar)
	binary.BigEndian.PutUint32(buffer[12:], c.availableBufferSize)
	binary.BigEndian.PutUint32(buffer[16:], c.packetsReceivingRate)
	binary.BigEndian.PutUint32(buffer[20:], c.estimatedLinkCapacity)
	binary.BigEndian.PutUint32(buffer[24:], c.receivingRate)

	if c.isLite {
		w.Write(buffer[0:4])
	} else if c.isSmall {
		w.Write(buffer[0:16])
	} else {
		w.Write(buffer[0:])
	}
}

// 3.2.5.  NAK (Loss Report)
type cifNAK struct {
	lostPacketSequenceNumber []circular
}

func (c cifNAK) String() string {
	var b strings.Builder

	fmt.Fprintf(&b, "NAK\n")

	if len(c.lostPacketSequenceNumber)%2 != 0 {
		fmt.Fprintf(&b, "   invalid list of sequence numbers\n")
		return b.String()
	}

	for i := 0; i < len(c.lostPacketSequenceNumber); i += 2 {
		if c.lostPacketSequenceNumber[i].Equals(c.lostPacketSequenceNumber[i+1]) {
			fmt.Fprintf(&b, "   single: %#08x\n", c.lostPacketSequenceNumber[i].Val())
		} else {
			fmt.Fprintf(&b, "      row: %#08x to %#08x\n", c.lostPacketSequenceNumber[i].Val(), c.lostPacketSequenceNumber[i+1].Val())
		}
	}

	return b.String()
}

func (c *cifNAK) Unmarshal(data []byte) error {
	if len(data)%4 != 0 {
		return fmt.Errorf("data too short to unmarshal")
	}

	// Appendix A

	c.lostPacketSequenceNumber = []circular{}

	var sequenceNumber circular
	isRange := false

	for i := 0; i < len(data); i += 4 {
		sequenceNumber = newCircular(binary.BigEndian.Uint32(data[i:])&MAX_SEQUENCENUMBER, MAX_SEQUENCENUMBER)

		if data[i]&0b10000000 == 0 {
			c.lostPacketSequenceNumber = append(c.lostPacketSequenceNumber, sequenceNumber)

			if !isRange {
				c.lostPacketSequenceNumber = append(c.lostPacketSequenceNumber, sequenceNumber)
			}

			isRange = false
		} else {
			c.lostPacketSequenceNumber = append(c.lostPacketSequenceNumber, sequenceNumber)
			isRange = true
		}
	}

	if len(c.lostPacketSequenceNumber)%2 != 0 {
		return fmt.Errorf("data too short to unmarshal")
	}

	sort.Slice(c.lostPacketSequenceNumber, func(i, j int) bool { return c.lostPacketSequenceNumber[i].Lt(c.lostPacketSequenceNumber[j]) })

	return nil
}

func (c *cifNAK) Marshal(w io.Writer) {
	if len(c.lostPacketSequenceNumber)%2 != 0 {
		return
	}

	// Appendix A

	var buffer [8]byte

	for i := 0; i < len(c.lostPacketSequenceNumber); i += 2 {
		if c.lostPacketSequenceNumber[i] == c.lostPacketSequenceNumber[i+1] {
			binary.BigEndian.PutUint32(buffer[0:], c.lostPacketSequenceNumber[i].Val())
			w.Write(buffer[0:4])
		} else {
			binary.BigEndian.PutUint32(buffer[0:], c.lostPacketSequenceNumber[i].Val()|0b10000000_00000000_00000000_00000000)
			binary.BigEndian.PutUint32(buffer[4:], c.lostPacketSequenceNumber[i+1].Val())
			w.Write(buffer[0:])
		}
	}
}

type cifShutdown struct{}

func (c cifShutdown) String() string {
	return "Shutdown\n"
}

func (c *cifShutdown) Unmarshal(data []byte) error {
	if len(data) != 0 && len(data) != 4 {
		return fmt.Errorf("invalid length")
	}

	return nil
}

func (c *cifShutdown) Marshal(w io.Writer) {
	var buffer [4]byte

	binary.BigEndian.PutUint32(buffer[0:], 0)

	w.Write(buffer[0:])
}

type packetPosition uint

const (
	firstPacket  packetPosition = 2
	middlePacket packetPosition = 0
	lastPacket   packetPosition = 1
	singlePacket packetPosition = 3
)

func (p packetPosition) String() string {
	switch int(p) {
	case 0:
		return "middle"
	case 1:
		return "last"
	case 2:
		return "first"
	case 3:
		return "single"
	}

	return `¯\_(ツ)_/¯`
}

func (p packetPosition) IsValid() bool {
	return p < 4
}

type packetEncryption uint

const (
	unencryptedPacket packetEncryption = 0
	evenKeyEncrypted  packetEncryption = 1
	oddKeyEncrypted   packetEncryption = 2
	evenAndOddKey     packetEncryption = 3
)

func (p packetEncryption) String() string {
	switch int(p) {
	case 0:
		return "unencrypted"
	case 1:
		return "even key"
	case 2:
		return "odd key"
	case 3:
		return "even and odd key"
	}

	return `¯\_(ツ)_/¯`
}

func (p packetEncryption) IsValid() bool {
	return p < 4
}

func (p packetEncryption) Opposite() packetEncryption {
	if p == evenKeyEncrypted {
		return oddKeyEncrypted
	}

	if p == oddKeyEncrypted {
		return evenKeyEncrypted
	}

	return p
}
