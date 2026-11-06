package packet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/datarhei/gosrt/circular"
	"github.com/stretchr/testify/require"
)

func TestDropReqWire(t *testing.T) {
	for _, bounds := range [][2]uint32{{42, 42}, {101, 110}, {MAX_SEQUENCENUMBER - 1, 2}} {
		c := &CIFDropReq{
			FirstPacketSequenceNumber: circular.New(bounds[0], MAX_SEQUENCENUMBER),
			LastPacketSequenceNumber:  circular.New(bounds[1], MAX_SEQUENCENUMBER),
		}
		var data bytes.Buffer
		require.NoError(t, c.Marshal(&data))
		require.Len(t, data.Bytes(), 8)
		require.Equal(t, bounds[0], binary.BigEndian.Uint32(data.Bytes()[:4]))
		require.Equal(t, bounds[1], binary.BigEndian.Uint32(data.Bytes()[4:]))
		parsed := &CIFDropReq{}
		require.NoError(t, parsed.Unmarshal(data.Bytes()))
		require.Equal(t, c, parsed)
		require.Contains(t, parsed.String(), "DROPREQ")
	}
}

func TestDropReqRejectsMalformed(t *testing.T) {
	for _, size := range []int{0, 1, 4, 7, 9, 12, 1456} {
		require.Error(t, new(CIFDropReq).Unmarshal(make([]byte, size)))
	}
	for _, bounds := range [][2]uint32{{1 << 31, 1}, {1, 1 << 31}, {100, 99}, {0, 1 << 30}, {0, MAX_SEQUENCENUMBER / 2}} {
		var data [8]byte
		binary.BigEndian.PutUint32(data[:4], bounds[0])
		binary.BigEndian.PutUint32(data[4:], bounds[1])
		require.Error(t, new(CIFDropReq).Unmarshal(data[:]), "bounds %v", bounds)
	}
	bad := &CIFDropReq{
		FirstPacketSequenceNumber: circular.New(100, MAX_SEQUENCENUMBER),
		LastPacketSequenceNumber:  circular.New(99, MAX_SEQUENCENUMBER),
	}
	require.Error(t, bad.Marshal(&bytes.Buffer{}))
	require.Error(t, new(CIFDropReq).Marshal(nil))
	require.ErrorIs(t, new(CIFDropReq).Marshal(dropReqWriter{n: 7}), io.ErrShortWrite)
	failure := errors.New("write failed")
	require.ErrorIs(t, new(CIFDropReq).Marshal(dropReqWriter{err: failure}), failure)
}

type dropReqWriter struct {
	n   int
	err error
}

func (w dropReqWriter) Write(p []byte) (int, error) { return w.n, w.err }

func FuzzDropReq(f *testing.F) {
	f.Add([]byte{0, 0, 0, 100, 0, 0, 0, 105})
	f.Add([]byte{0x7f, 0xff, 0xff, 0xff, 0, 0, 0, 1})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		c := new(CIFDropReq)
		if c.Unmarshal(data) != nil {
			return
		}
		var encoded bytes.Buffer
		require.NoError(t, c.Marshal(&encoded))
		require.Equal(t, data, encoded.Bytes())
	})
}
