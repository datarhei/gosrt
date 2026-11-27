package fec

import (
	"net"
	"sync"

	"github.com/datarhei/gosrt/circular"
	"github.com/datarhei/gosrt/packet"
)

// Reconstructor is responsible for rebuilding lost packets using row FEC control packets.
type Reconstructor struct {
	config Config

	mu sync.Mutex

	packets  map[uint32]packet.Packet  // received and reconstructed data packets, by sequence number
	controls map[uint32]*ControlPacket // FEC packets, by the sequence number of the first packet of their row

	history uint32 // number of sequence numbers to keep behind the highest one

	highest     circular.Number
	haveHighest bool

	alignBase uint32 // first sequence number of the row of the most recent FEC packet
	haveAlign bool
}

// NewReconstructor creates a new FEC Reconstructor.
func NewReconstructor(cfg Config) *Reconstructor {
	return &Reconstructor{
		config:   cfg,
		packets:  make(map[uint32]packet.Packet),
		controls: make(map[uint32]*ControlPacket),
		history:  uint32(4*cfg.Cols + 64),
	}
}

// AddPacket processes an incoming data packet or FEC control packet.
// It returns a slice of recovered packets (if any).
func (r *Reconstructor) AddPacket(p packet.Packet) []packet.Packet {
	if p == nil || p.Header().IsControlPacket {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	cols := uint32(r.config.Cols)
	if cols < MinCols {
		return nil
	}

	var recovered []packet.Packet

	if IsControlPacket(p) {
		ctrl, err := ParseControlPacket(p)
		if err != nil {
			return nil
		}

		// Column FEC (2D) is not supported. Using a column packet as a row packet would rebuild wrong data, so it is ignored.
		if ctrl.GroupIndex != RowGroupIndex {
			return nil
		}

		base := (ctrl.SNBase - (cols - 1)) & packet.MAX_SEQUENCENUMBER

		r.alignBase = base
		r.haveAlign = true
		r.updateHighest(ctrl.SNBase)

		r.controls[base] = ctrl

		if pkt := r.tryReconstruct(base); pkt != nil {
			recovered = append(recovered, pkt)
		}
	} else {
		seq := p.Header().PacketSequenceNumber.Val()
		if _, ok := r.packets[seq]; ok {
			return nil // Duplicate
		}

		r.packets[seq] = p.Clone()
		r.updateHighest(seq)

		if r.haveAlign {
			base := r.rowBase(seq)
			if _, ok := r.controls[base]; ok {
				if pkt := r.tryReconstruct(base); pkt != nil {
					recovered = append(recovered, pkt)
				}
			}
		}
	}

	r.cleanup()

	return recovered
}

func (r *Reconstructor) updateHighest(seq uint32) {
	s := circular.New(seq, packet.MAX_SEQUENCENUMBER)
	if !r.haveHighest || s.Gt(r.highest) {
		r.highest = s
		r.haveHighest = true
	}
}

func (r *Reconstructor) rowBase(seq uint32) uint32 {
	cols := int64(r.config.Cols)

	offset := int64((seq - r.alignBase) & packet.MAX_SEQUENCENUMBER)
	if offset > int64(packet.MAX_SEQUENCENUMBER/2) {
		offset -= int64(packet.MAX_SEQUENCENUMBER) + 1
	}

	rows := offset / cols
	if offset%cols < 0 {
		rows--
	}

	return uint32(int64(r.alignBase)+rows*cols) & packet.MAX_SEQUENCENUMBER
}

// cleanup removes packets and FEC packets that are too far behind the highest sequence number.
func (r *Reconstructor) cleanup() {
	if !r.haveHighest || uint32(len(r.packets)+len(r.controls)) <= 2*r.history {
		return
	}

	isOld := func(seq uint32) bool {
		s := circular.New(seq, packet.MAX_SEQUENCENUMBER)
		return s.Lt(r.highest) && s.Distance(r.highest) > r.history
	}

	for seq, p := range r.packets {
		if isOld(seq) {
			p.Decommission()
			delete(r.packets, seq)
		}
	}

	for base := range r.controls {
		if isOld(base) {
			delete(r.controls, base)
		}
	}
}

func (r *Reconstructor) tryReconstruct(base uint32) packet.Packet {
	ctrl, ok := r.controls[base]
	if !ok {
		return nil
	}

	cols := uint32(r.config.Cols)

	missingCount := 0
	var missingSeq uint32

	for i := uint32(0); i < cols; i++ {
		seq := (base + i) & packet.MAX_SEQUENCENUMBER
		if _, ok := r.packets[seq]; !ok {
			missingCount++
			missingSeq = seq
		}
	}

	if missingCount == 0 {
		// All packets received, nothing to do.
		delete(r.controls, base)
		return nil
	}

	if missingCount > 1 {
		// Can't reconstruct yet.
		return nil
	}

	// Exactly one missing, reconstruct it.
	tsRecov := ctrl.TimestampRecov
	flagsRecov := ctrl.FlagsRecov
	lengthRecov := ctrl.LengthRecov

	payloadRecov := make([]byte, len(ctrl.PayloadRecov))
	copy(payloadRecov, ctrl.PayloadRecov)

	var addr, localAddr net.Addr
	var destinationSocketId uint32

	for i := uint32(0); i < cols; i++ {
		seq := (base + i) & packet.MAX_SEQUENCENUMBER
		if seq == missingSeq {
			continue
		}

		pkt := r.packets[seq]
		header := pkt.Header()

		data := pkt.Data()
		if len(data) > len(payloadRecov) {
			// The FEC payload must cover every packet of the row. If it doesn't, the FEC packet doesn't belong to these packets and would produce garbage.
			delete(r.controls, base)
			return nil
		}

		tsRecov ^= header.Timestamp
		flagsRecov ^= byte(header.KeyBaseEncryptionFlag.Val() & 0x03)
		lengthRecov ^= uint16(len(data))

		for j, b := range data {
			payloadRecov[j] ^= b
		}

		addr = header.Addr
		localAddr = header.LocalAddr
		destinationSocketId = header.DestinationSocketId
	}

	delete(r.controls, base)

	if lengthRecov == 0 || int(lengthRecov) > len(payloadRecov) {
		return nil // Inconsistent FEC packet
	}

	p := packet.NewPacket(addr)
	header := p.Header()
	header.LocalAddr = localAddr
	header.DestinationSocketId = destinationSocketId
	header.IsControlPacket = false
	header.PacketSequenceNumber = circular.New(missingSeq, packet.MAX_SEQUENCENUMBER)
	header.PacketPositionFlag = packet.SinglePacket
	header.OrderFlag = false
	header.KeyBaseEncryptionFlag = packet.PacketEncryption(flagsRecov & 0x03)
	header.RetransmittedPacketFlag = true
	header.MessageNumber = 1 // The original message number can't be recovered. It must not be 0, because that marks an FEC control packet.
	header.Timestamp = tsRecov

	p.SetData(payloadRecov[:lengthRecov])

	r.packets[missingSeq] = p.Clone() // Keep the reconstructed packet, so it isn't considered missing anymore.

	return p
}
