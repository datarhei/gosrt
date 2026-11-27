package fec

import (
	"sync"

	"github.com/datarhei/gosrt/packet"
)

// Generator is responsible for generating row FEC control packets.
type Generator struct {
	config Config

	mu sync.Mutex

	base  uint32 // sequence number of the first packet of the current row
	count int    // number of packets collected for the current row

	timestampRecov uint32
	flagsRecov     uint8
	lengthRecov    uint16
	payloadRecov   []byte
}

func NewGenerator(cfg Config, isn uint32) *Generator {
	return &Generator{
		config:       cfg,
		base:         isn & packet.MAX_SEQUENCENUMBER,
		payloadRecov: make([]byte, 0, packet.MAX_PAYLOAD_SIZE),
	}
}

// AddPacket processes an outgoing data packet and potentially generates an FEC control packet.
// Returns a slice of FEC control packets that are ready to be sent.
func (g *Generator) AddPacket(p packet.Packet) []packet.Packet {
	header := p.Header()

	if header.IsControlPacket || header.RetransmittedPacketFlag {
		return nil
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	cols := uint32(g.config.Cols)
	seq := header.PacketSequenceNumber.Val()

	offset := (seq - g.base) & packet.MAX_SEQUENCENUMBER
	if offset > packet.MAX_SEQUENCENUMBER/2 {
		return nil // Belongs to a row that has already been finished.
	}

	if offset >= cols {
		// Skipped ahead, the current row can't be completed anymore.
		g.base = (g.base + offset/cols*cols) & packet.MAX_SEQUENCENUMBER
		offset %= cols
		g.reset()
	}

	g.timestampRecov ^= header.Timestamp
	g.flagsRecov ^= uint8(header.KeyBaseEncryptionFlag.Val() & 0x03)
	data := p.Data()
	g.lengthRecov ^= uint16(len(data))

	if len(data) > len(g.payloadRecov) {
		g.payloadRecov = append(g.payloadRecov, make([]byte, len(data)-len(g.payloadRecov))...)
	}
	for i, b := range data {
		g.payloadRecov[i] ^= b
	}

	g.count++

	if offset != cols-1 {
		return nil
	}

	// This was the last packet of the row.
	var fecPkts []packet.Packet

	if g.count == int(cols) {
		ctrl := &ControlPacket{
			SNBase:         seq,
			GroupIndex:     RowGroupIndex,
			TimestampRecov: g.timestampRecov,
			FlagsRecov:     g.flagsRecov,
			LengthRecov:    g.lengthRecov,
			PayloadRecov:   g.payloadRecov,
		}

		fecPkts = append(fecPkts, WriteControlPacket(header.DestinationSocketId, ctrl))
	}

	g.base = (g.base + cols) & packet.MAX_SEQUENCENUMBER
	g.reset()

	return fecPkts
}

func (g *Generator) reset() {
	g.count = 0
	g.timestampRecov = 0
	g.flagsRecov = 0
	g.lengthRecov = 0
	g.payloadRecov = g.payloadRecov[:0]
}
