package fec

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"testing"

	"github.com/datarhei/gosrt/circular"
	"github.com/datarhei/gosrt/packet"
	"github.com/stretchr/testify/require"
)

func newDataPacket(seq uint32, msgno uint32, ts uint32, data []byte) packet.Packet {
	p := packet.NewPacket(nil)
	h := p.Header()
	h.IsControlPacket = false
	h.PacketSequenceNumber = circular.New(seq&packet.MAX_SEQUENCENUMBER, packet.MAX_SEQUENCENUMBER)
	h.PacketPositionFlag = packet.SinglePacket
	h.MessageNumber = msgno
	h.Timestamp = ts
	p.SetData(data)
	return p
}

func newFECPacket(seq uint32, groupIndex int8, payload []byte) packet.Packet {
	return WriteControlPacket(0, &ControlPacket{
		SNBase:       seq,
		GroupIndex:   groupIndex,
		PayloadRecov: payload,
	})
}

func mustParse(t *testing.T, s string) Config {
	t.Helper()
	cfg, err := ParseConfig(s)
	require.NoError(t, err)
	return cfg
}

// Regression test for the crash reported in STR-2028: an FEC packet whose recovery payload
// is shorter than a data packet in its row caused an index out of range panic.
func TestReconstructorShortFECPayloadDoesNotPanic(t *testing.T) {
	// The reproduction from the report
	r := NewReconstructor(mustParse(t, "fec,cols:2"))
	require.NotPanics(t, func() {
		r.AddPacket(newFECPacket(100, RowGroupIndex, nil))
		r.AddPacket(newDataPacket(101, 1, 0, make([]byte, 1316)))
	})

	// The same, but with the data packet in the row of the FEC packet, such that
	// a reconstruction is attempted.
	for _, payload := range [][]byte{nil, {1, 2, 3, 4}} {
		r = NewReconstructor(mustParse(t, "fec,cols:2"))
		require.NotPanics(t, func() {
			require.Empty(t, r.AddPacket(newFECPacket(101, RowGroupIndex, payload)))
			require.Empty(t, r.AddPacket(newDataPacket(100, 1, 0, make([]byte, 1316))))
		})

		// And the other order
		r = NewReconstructor(mustParse(t, "fec,cols:2"))
		require.NotPanics(t, func() {
			require.Empty(t, r.AddPacket(newDataPacket(100, 1, 0, make([]byte, 1316))))
			require.Empty(t, r.AddPacket(newFECPacket(101, RowGroupIndex, payload)))
		})
	}
}

func TestReconstructorInvalidLength(t *testing.T) {
	cfg := mustParse(t, "fec,cols:2")

	// The recovered length is longer than the recovery payload
	r := NewReconstructor(cfg)
	ctrl := &ControlPacket{SNBase: 11, GroupIndex: RowGroupIndex, LengthRecov: 4 ^ 100, PayloadRecov: make([]byte, 10)}
	require.Empty(t, r.AddPacket(newDataPacket(10, 1, 0, make([]byte, 4))))
	require.Empty(t, r.AddPacket(WriteControlPacket(0, ctrl)))

	// The recovered length is 0
	r = NewReconstructor(cfg)
	ctrl = &ControlPacket{SNBase: 11, GroupIndex: RowGroupIndex, LengthRecov: 4, PayloadRecov: make([]byte, 10)}
	require.Empty(t, r.AddPacket(newDataPacket(10, 1, 0, make([]byte, 4))))
	require.Empty(t, r.AddPacket(WriteControlPacket(0, ctrl)))
}

// generate feeds the packets into a generator and returns the packets in send order,
// FEC packets included.
func generate(t *testing.T, cfg Config, isn uint32, pkts []packet.Packet) []packet.Packet {
	t.Helper()

	g := NewGenerator(cfg, isn)
	out := []packet.Packet{}

	for _, p := range pkts {
		out = append(out, p)
		out = append(out, g.AddPacket(p)...)
	}

	return out
}

func randomPackets(rnd *rand.Rand, isn uint32, n int) []packet.Packet {
	pkts := []packet.Packet{}
	for i := 0; i < n; i++ {
		data := make([]byte, 1+rnd.Intn(packet.MAX_PAYLOAD_SIZE-ExtraHeaderSize))
		rnd.Read(data)
		p := newDataPacket(isn+uint32(i), uint32(i+1), rnd.Uint32(), data)
		p.Header().KeyBaseEncryptionFlag = packet.PacketEncryption(rnd.Intn(3))
		pkts = append(pkts, p)
	}
	return pkts
}

func TestGeneratorFECPacket(t *testing.T) {
	cfg := mustParse(t, "fec,cols:4")
	isn := uint32(1000)

	rnd := rand.New(rand.NewSource(1))
	pkts := randomPackets(rnd, isn, 8)

	out := generate(t, cfg, isn, pkts)
	require.Len(t, out, 10)

	for _, i := range []int{4, 9} {
		fecPkt := out[i]
		require.True(t, IsControlPacket(fecPkt))

		ctrl, err := ParseControlPacket(fecPkt)
		require.NoError(t, err)

		// Like libsrt, the FEC packet carries the sequence number of the last packet of the row.
		require.Equal(t, out[i-1].Header().PacketSequenceNumber.Val(), ctrl.SNBase)
		require.Equal(t, RowGroupIndex, ctrl.GroupIndex)

		// The recovery payload covers the longest packet of the row
		maxLen := 0
		for _, p := range out[i-4 : i] {
			maxLen = max(maxLen, len(p.Data()))
		}
		require.Len(t, ctrl.PayloadRecov, maxLen)
	}
}

func TestGeneratorRetransmissionsAndGaps(t *testing.T) {
	cfg := mustParse(t, "fec,cols:4")
	g := NewGenerator(cfg, 0)

	require.Empty(t, g.AddPacket(newDataPacket(0, 1, 0, []byte{1})))
	require.Empty(t, g.AddPacket(newDataPacket(1, 2, 0, []byte{2})))

	// Retransmissions are not protected
	rexmit := newDataPacket(0, 1, 0, []byte{1})
	rexmit.Header().RetransmittedPacketFlag = true
	require.Empty(t, g.AddPacket(rexmit))

	require.Empty(t, g.AddPacket(newDataPacket(2, 3, 0, []byte{3})))
	require.Len(t, g.AddPacket(newDataPacket(3, 4, 0, []byte{4})), 1)

	// A row with a gap doesn't produce an FEC packet, the next row is aligned again.
	require.Empty(t, g.AddPacket(newDataPacket(4, 5, 0, []byte{5})))
	require.Empty(t, g.AddPacket(newDataPacket(6, 7, 0, []byte{7})))
	require.Empty(t, g.AddPacket(newDataPacket(7, 8, 0, []byte{8})))
	require.Empty(t, g.AddPacket(newDataPacket(9, 9, 0, []byte{9})))
	require.Empty(t, g.AddPacket(newDataPacket(10, 9, 0, []byte{9})))
	fecPkts := g.AddPacket(newDataPacket(11, 9, 0, []byte{9}))
	require.Empty(t, fecPkts)

	for seq := uint32(12); seq < 15; seq++ {
		require.Empty(t, g.AddPacket(newDataPacket(seq, 9, 0, []byte{9})))
	}
	fecPkts = g.AddPacket(newDataPacket(15, 9, 0, []byte{9}))
	require.Len(t, fecPkts, 1)
	require.Equal(t, uint32(15), fecPkts[0].Header().PacketSequenceNumber.Val())
}

func requireSamePacket(t *testing.T, want, got packet.Packet) {
	t.Helper()

	require.Equal(t, want.Header().PacketSequenceNumber.Val(), got.Header().PacketSequenceNumber.Val())
	require.Equal(t, want.Header().Timestamp, got.Header().Timestamp)
	require.Equal(t, want.Header().KeyBaseEncryptionFlag, got.Header().KeyBaseEncryptionFlag)
	require.True(t, bytes.Equal(want.Data(), got.Data()), "payload differs")

	// The message number can't be recovered, but it must not mark an FEC packet
	require.NotEqual(t, uint32(0), got.Header().MessageNumber)
	require.False(t, IsControlPacket(got))
	require.Equal(t, packet.SinglePacket, got.Header().PacketPositionFlag)
}

func TestRoundTripRecoversEveryPosition(t *testing.T) {
	for _, isn := range []uint32{0, 12345, packet.MAX_SEQUENCENUMBER - 5} {
		for _, cols := range []int{2, 5, 10} {
			cfg := Config{Cols: cols, Rows: 1}
			rnd := rand.New(rand.NewSource(int64(isn) + int64(cols)))

			pkts := randomPackets(rnd, isn, 3*cols)
			out := generate(t, cfg, isn, pkts)

			// Drop the i-th data packet of every row
			for drop := 0; drop < cols; drop++ {
				r := NewReconstructor(cfg)
				recovered := []packet.Packet{}
				dropped := []packet.Packet{}

				pos := 0
				for _, p := range out {
					if !IsControlPacket(p) {
						if pos%cols == drop {
							dropped = append(dropped, p)
							pos++
							continue
						}
						pos++
					}
					recovered = append(recovered, r.AddPacket(p)...)
				}

				require.Len(t, recovered, len(dropped), "isn=%d cols=%d drop=%d", isn, cols, drop)
				for i := range dropped {
					requireSamePacket(t, dropped[i], recovered[i])
				}
			}
		}
	}
}

func TestReconstructorFECBeforeData(t *testing.T) {
	cfg := mustParse(t, "fec,cols:4")
	rnd := rand.New(rand.NewSource(2))
	pkts := randomPackets(rnd, 100, 4)
	out := generate(t, cfg, 100, pkts)
	require.Len(t, out, 5)

	// FEC packet first (reordering), packet 101 lost
	r := NewReconstructor(cfg)
	require.Empty(t, r.AddPacket(out[4]))
	require.Empty(t, r.AddPacket(out[0]))
	require.Empty(t, r.AddPacket(out[2]))
	recovered := r.AddPacket(out[3])
	require.Len(t, recovered, 1)
	requireSamePacket(t, out[1], recovered[0])

	// The late original is a duplicate now
	require.Empty(t, r.AddPacket(out[1]))
}

func TestReconstructorTwoLostThenRetransmission(t *testing.T) {
	cfg := mustParse(t, "fec,cols:4")
	rnd := rand.New(rand.NewSource(3))
	out := generate(t, cfg, 0, randomPackets(rnd, 0, 4))

	r := NewReconstructor(cfg)
	require.Empty(t, r.AddPacket(out[0]))
	require.Empty(t, r.AddPacket(out[3]))
	require.Empty(t, r.AddPacket(out[4])) // 2 missing, nothing to do yet

	// A retransmission of packet 1 arrives, now packet 2 can be rebuilt
	recovered := r.AddPacket(out[1])
	require.Len(t, recovered, 1)
	requireSamePacket(t, out[2], recovered[0])
}

// Column FEC packets (2D FEC) must not be used as row packets, otherwise wrong data is rebuilt.
func TestReconstructorIgnoresColumnPackets(t *testing.T) {
	cfg := mustParse(t, "fec,cols:4")
	rnd := rand.New(rand.NewSource(4))
	out := generate(t, cfg, 0, randomPackets(rnd, 0, 4))

	ctrl, err := ParseControlPacket(out[4])
	require.NoError(t, err)

	r := NewReconstructor(cfg)
	require.Empty(t, r.AddPacket(out[0]))
	require.Empty(t, r.AddPacket(out[1]))
	require.Empty(t, r.AddPacket(out[2]))

	for _, index := range []int8{0, 1, 3} {
		column := *ctrl
		column.GroupIndex = index
		require.Empty(t, r.AddPacket(WriteControlPacket(0, &column)))
	}

	// The real row packet still works
	recovered := r.AddPacket(out[4])
	require.Len(t, recovered, 1)
	requireSamePacket(t, out[3], recovered[0])
}

// Packets in the format libsrt sends: the FEC packet carries the sequence number of the
// last packet of the row and a recovery payload padded to the full payload size.
func TestReconstructorLibsrtFormat(t *testing.T) {
	cols := 3
	cfg := Config{Cols: cols, Rows: 1}
	payloadSize := 1452

	data := [][]byte{bytes.Repeat([]byte{0xaa}, 1316), bytes.Repeat([]byte{0x55}, 188), bytes.Repeat([]byte{0x0f}, 1452)}
	ts := []uint32{1000, 2000, 3000}

	var tsRecov uint32
	var lengthRecov uint16
	payload := make([]byte, payloadSize)
	pkts := []packet.Packet{}
	for i := range data {
		pkts = append(pkts, newDataPacket(uint32(50+i), uint32(i+1), ts[i], data[i]))
		tsRecov ^= ts[i]
		lengthRecov ^= uint16(len(data[i]))
		for j, b := range data[i] {
			payload[j] ^= b
		}
	}

	raw := make([]byte, ExtraHeaderSize+payloadSize)
	raw[0] = 0xff // row
	raw[1] = 0
	binary.BigEndian.PutUint16(raw[2:4], lengthRecov)
	copy(raw[4:], payload)

	fecPkt := newDataPacket(52, 0, tsRecov, raw)

	for lost := 0; lost < cols; lost++ {
		r := NewReconstructor(cfg)
		recovered := []packet.Packet{}
		for i, p := range pkts {
			if i == lost {
				continue
			}
			recovered = append(recovered, r.AddPacket(p)...)
		}
		recovered = append(recovered, r.AddPacket(fecPkt)...)

		require.Len(t, recovered, 1)
		requireSamePacket(t, pkts[lost], recovered[0])
	}
}

func TestReconstructorHistoryIsBounded(t *testing.T) {
	cfg := mustParse(t, "fec,cols:10")
	r := NewReconstructor(cfg)

	for seq := uint32(0); seq < 10000; seq++ {
		r.AddPacket(newDataPacket(seq, 1, 0, []byte{1}))
		if seq%10 == 9 {
			r.AddPacket(newFECPacket(seq, RowGroupIndex, []byte{0}))
		}
	}

	require.LessOrEqual(t, uint32(len(r.packets)+len(r.controls)), 2*r.history+1)
}

func TestParseConfig(t *testing.T) {
	valid := map[string]Config{
		"fec,cols:10":                              {Cols: 10, Rows: 1, Layout: "even", ARQ: "always"},
		"FEC,cols:2,rows:1":                        {Cols: 2, Rows: 1, Layout: "even", ARQ: "always"},
		"fec,cols:1024,rows:1,layout:staircase":    {Cols: 1024, Rows: 1, Layout: "staircase", ARQ: "always"},
		"fec,cols:5,rows:1,layout:even,arq:always": {Cols: 5, Rows: 1, Layout: "even", ARQ: "always"},
		"fec, cols:5 ,rows: 1":                     {Cols: 5, Rows: 1, Layout: "even", ARQ: "always"},
	}

	for s, want := range valid {
		got, err := ParseConfig(s)
		require.NoError(t, err, s)
		require.Equal(t, want, got, s)
	}

	invalid := []string{
		"",
		"FEC",
		"fec",
		"foo,cols:10",
		"fec,cols:1",
		"fec,cols:1025",
		"fec,cols:abc",
		"fec,cols:10,rows:2",  // 2D FEC is not supported
		"fec,cols:10,rows:5",  // 2D FEC is not supported
		"fec,cols:10,rows:-5", // column-only FEC is not supported
		"fec,cols:10,arq:foo",
		"fec,cols:10,layout:foo",
		"fec,cols:10,cols:10",
		"fec,cols:10,foo:bar",
		"fec,cols:10,rows",
		"fec,cols:10,",
		"fec,cols:",
	}

	for _, s := range invalid {
		_, err := ParseConfig(s)
		require.Error(t, err, s)
	}
}

func TestNegotiate(t *testing.T) {
	tests := []struct {
		local, peer string
		want        string
		err         bool
	}{
		{"", "", "", false},
		{"fec,cols:10", "", "fec,cols:10", false},
		{"", "fec,cols:10", "", false},
		{"fec,cols:10", "fec,cols:10", "fec,cols:10", false},
		{"fec,cols:10", "fec,cols:10,rows:1,layout:even", "fec,cols:10,rows:1,layout:even", false},
		{"fec,cols:10,arq:always", "fec,rows:1", "fec,cols:10,rows:1,arq:always", false},
		{"fec,cols:10", "fec,cols:20", "", true},
		{"fec,cols:10", "fec,cols:10,rows:5", "", true},
		{"fec,cols:10", "fec,arq:onreq,cols:10,layout:staircase,rows:1", "fec,cols:10,rows:1,layout:staircase,arq:onreq", false},
		{"fec,cols:10,arq:always", "fec,cols:10,arq:onreq", "", true},
		{"fec,cols:10", "foo,cols:10", "", true},
		{"fec,cols:10", "fec,cols:10,cols:10", "", true},
		{"fec,rows:1", "fec,rows:1", "", true}, // no cols at all
	}

	for _, tc := range tests {
		got, err := Negotiate(tc.local, tc.peer)
		if tc.err {
			require.Error(t, err, "%q + %q", tc.local, tc.peer)
			continue
		}

		require.NoError(t, err, "%q + %q", tc.local, tc.peer)
		require.Equal(t, tc.want, got, "%q + %q", tc.local, tc.peer)
	}
}

// FuzzReconstructor feeds arbitrary data and FEC packets into the reconstructor. It must
// never panic.
func FuzzReconstructor(f *testing.F) {
	f.Add(uint8(2), []byte{0, 100, 4, 0, 0, 0, 0, 1, 101, 0x28, 0x05})
	f.Add(uint8(4), []byte{1, 0, 10, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 3, 4, 0xff, 0, 0, 10, 1, 2, 3})

	f.Fuzz(func(t *testing.T, cols uint8, input []byte) {
		cfg := Config{Cols: MinCols + int(cols)%32, Rows: 1}
		r := NewReconstructor(cfg)

		// Each record: msgno flag (1 byte), seq delta (1 byte), length (1 byte), payload
		for len(input) >= 3 {
			msgno := uint32(input[0] & 1)
			seq := uint32(input[1])
			length := int(input[2])
			input = input[3:]

			if length > len(input) {
				length = len(input)
			}

			data := input[:length]
			input = input[length:]

			r.AddPacket(newDataPacket(seq, msgno, 0, data))
		}
	})
}
