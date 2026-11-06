package packet

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/datarhei/gosrt/circular"
)

// CIFDropReq is the inclusive sequence range of a Message Drop Request.
// The message number is carried in the packet header's TypeSpecific field.
type CIFDropReq struct {
	FirstPacketSequenceNumber circular.Number
	LastPacketSequenceNumber  circular.Number
}

func (c CIFDropReq) String() string {
	return fmt.Sprintf("--- DROPREQ ---\n   range: %d to %d\n--- /DROPREQ ---", c.FirstPacketSequenceNumber.Val(), c.LastPacketSequenceNumber.Val())
}

func (c *CIFDropReq) Unmarshal(data []byte) error {
	if len(data) != 8 {
		return fmt.Errorf("invalid DROPREQ length")
	}
	first := binary.BigEndian.Uint32(data[:4])
	last := binary.BigEndian.Uint32(data[4:])
	if first > MAX_SEQUENCENUMBER || last > MAX_SEQUENCENUMBER || (last-first)&MAX_SEQUENCENUMBER >= MAX_SEQUENCENUMBER/2 {
		return fmt.Errorf("invalid DROPREQ sequence range")
	}
	c.FirstPacketSequenceNumber = circular.New(first, MAX_SEQUENCENUMBER)
	c.LastPacketSequenceNumber = circular.New(last, MAX_SEQUENCENUMBER)
	return nil
}

func (c *CIFDropReq) Marshal(w io.Writer) error {
	if w == nil {
		return fmt.Errorf("invalid writer")
	}
	var data [8]byte
	binary.BigEndian.PutUint32(data[:4], c.FirstPacketSequenceNumber.Val())
	binary.BigEndian.PutUint32(data[4:], c.LastPacketSequenceNumber.Val())
	if err := new(CIFDropReq).Unmarshal(data[:]); err != nil {
		return err
	}
	n, err := w.Write(data[:])
	if err == nil && n != len(data) {
		return io.ErrShortWrite
	}
	return err
}
