// Package congestions provides congestion control implementations for SRT
package congestion

import (
	"github.com/datarhei/gosrt/internal/circular"
	"github.com/datarhei/gosrt/internal/packet"
)

// Sender is the sending part of the congestion control
type Sender interface {
	Stats() SendStats
	Flush()
	Push(p packet.Packet)
	Tick(now uint64)
	ACK(sequenceNumber circular.Number)
	NAK(sequenceNumbers []circular.Number)
	SetDropThreshold(threshold uint64)
}

// Receiver is the receiving part of the congestion control
type Receiver interface {
	Stats() ReceiveStats
	PacketRate() (pps, bps, capacity float64)
	Flush()
	Push(pkt packet.Packet)
	Tick(now uint64)
	SetNAKInterval(nakInterval uint64)
}

// SendStats are collected statistics from a sender
type SendStats struct {
	Pkt  uint64 // Sent packets in total
	Byte uint64 // Sent bytes in total

	PktUnique  uint64
	ByteUnique uint64

	PktLoss  uint64
	ByteLoss uint64

	PktRetrans  uint64
	ByteRetrans uint64

	UsSndDuration uint64 // microseconds

	PktDrop  uint64
	ByteDrop uint64

	// instantaneous
	PktBuf  uint64
	ByteBuf uint64
	MsBuf   uint64

	PktFlightSize uint64

	UsPktSndPeriod float64 // microseconds
	BytePayload    uint64

	MbpsEstimatedInputBandwidth float64
	MbpsEstimatedSentBandwidth  float64

	PktLossRate float64
}

// ReceiveStats are collected statistics from a reciever
type ReceiveStats struct {
	Pkt  uint64
	Byte uint64

	PktUnique  uint64
	ByteUnique uint64

	PktLoss  uint64
	ByteLoss uint64

	PktRetrans  uint64
	ByteRetrans uint64

	PktBelated  uint64
	ByteBelated uint64

	PktDrop  uint64
	ByteDrop uint64

	// instantaneous
	PktBuf  uint64
	ByteBuf uint64
	MsBuf   uint64

	BytePayload uint64

	MbpsEstimatedRecvBandwidth float64
	MbpsEstimatedLinkCapacity  float64

	PktLossRate float64
}
