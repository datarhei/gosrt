package fec

import (
	"testing"

	"github.com/datarhei/gosrt/circular"
	"github.com/datarhei/gosrt/packet"
	"github.com/stretchr/testify/require"
)

func newDataPacket(seq uint32, data []byte) packet.Packet {
	p := packet.NewPacket(nil)
	h := p.Header()
	h.IsControlPacket = false
	h.PacketSequenceNumber = circular.New(seq&packet.MAX_SEQUENCENUMBER, packet.MAX_SEQUENCENUMBER)
	h.PacketPositionFlag = packet.SinglePacket
	h.MessageNumber = 1
	p.SetData(data)
	return p
}

func newFECPacket(seq uint32, lengthRecov uint16, payload []byte) packet.Packet {
	return WriteControlPacket(0, &ControlPacket{
		SNBase:       seq,
		GroupIndex:   -1,
		LengthRecov:  lengthRecov,
		PayloadRecov: payload,
	})
}

// Regression test for the crash reported in STR-2028: an FEC packet whose recovery payload
// is shorter than a data packet in its row caused an index out of range panic.
func TestReconstructorShortFECPayloadDoesNotPanic(t *testing.T) {
	cfg := Config{Cols: 2, Rows: 1}

	for _, payload := range [][]byte{nil, {1, 2, 3, 4}} {
		r := NewReconstructor(cfg)
		require.NotPanics(t, func() {
			require.Empty(t, r.AddPacket(newFECPacket(100, 0, payload)))
			require.Empty(t, r.AddPacket(newDataPacket(101, make([]byte, 1316))))
		})

		// And the other order
		r = NewReconstructor(cfg)
		require.NotPanics(t, func() {
			require.Empty(t, r.AddPacket(newDataPacket(101, make([]byte, 1316))))
			require.Empty(t, r.AddPacket(newFECPacket(100, 0, payload)))
		})
	}
}

func TestReconstructorInvalidLength(t *testing.T) {
	cfg := Config{Cols: 2, Rows: 1}

	// The recovered length is longer than the recovery payload
	r := NewReconstructor(cfg)
	require.Empty(t, r.AddPacket(newDataPacket(11, make([]byte, 4))))
	require.Empty(t, r.AddPacket(newFECPacket(10, 4^100, make([]byte, 10))))

	// The recovered length is 0
	r = NewReconstructor(cfg)
	require.Empty(t, r.AddPacket(newDataPacket(11, make([]byte, 4))))
	require.Empty(t, r.AddPacket(newFECPacket(10, 4, make([]byte, 10))))
}

func TestReconstructorRecoversPacket(t *testing.T) {
	cfg := Config{Cols: 2, Rows: 1}

	lost := []byte{1, 2, 3, 4, 5, 6}
	present := []byte{9, 8, 7}

	payload := make([]byte, len(lost))
	copy(payload, lost)
	for i, b := range present {
		payload[i] ^= b
	}

	r := NewReconstructor(cfg)
	require.Empty(t, r.AddPacket(newDataPacket(11, present)))
	recovered := r.AddPacket(newFECPacket(10, uint16(len(lost)^len(present)), payload))
	require.Len(t, recovered, 1)
	require.Equal(t, uint32(10), recovered[0].Header().PacketSequenceNumber.Val())
	require.Equal(t, lost, recovered[0].Data())
}
