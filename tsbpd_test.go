package srt

import (
	"net"
	"testing"
	"time"

	"github.com/datarhei/gosrt/circular"
	"github.com/datarhei/gosrt/packet"
	"github.com/stretchr/testify/require"
)

// testPeerClockOffset sends data packets from a peer whose clock started at the given offset after the local
// start and checks that they are delivered after the TSBPD delay from their arrival.
func testPeerClockOffset(t *testing.T, peerStartOffset time.Duration) {
	start := time.Now().Add(-500 * time.Millisecond)
	peerStart := start.Add(peerStartOffset)

	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:6000")

	config := DefaultConfig()
	config.DriftTracer = true

	c := newSRTConn(srtConnConfig{
		version:                     5,
		isCaller:                    true,
		localAddr:                   addr,
		remoteAddr:                  addr,
		config:                      config,
		start:                       start,
		socketId:                    1,
		peerSocketId:                2,
		tsbpdTimeBase:               uint64(time.Since(start).Microseconds()),
		tsbpdDelay:                  uint64((120 * time.Millisecond).Microseconds()),
		peerTsbpdDelay:              uint64((120 * time.Millisecond).Microseconds()),
		initialPacketSequenceNumber: circular.New(0, packet.MAX_SEQUENCENUMBER),
		onSend:                      func(p packet.Packet) {},
		onShutdown:                  func(c *srtConn) {},
		logger:                      NewLogger(nil),
	})
	defer c.Close()

	// margin returns how long a packet that arrives now will wait for its delivery
	margin := func(seq uint32) time.Duration {
		p := packet.NewPacket(addr)
		p.Header().PacketSequenceNumber = circular.New(seq, packet.MAX_SEQUENCENUMBER)
		p.Header().MessageNumber = 1
		p.Header().Timestamp = uint32(time.Since(peerStart).Microseconds())

		c.handlePacket(p)

		now := c.tsbpdTimeBase + c.getTimestamp()

		return time.Duration(int64(p.Header().PktTsbpdTime)-int64(now)) * time.Microsecond
	}

	require.InDelta(t, 120*time.Millisecond, margin(0), float64(10*time.Millisecond))

	time.Sleep(50 * time.Millisecond)

	require.InDelta(t, 120*time.Millisecond, margin(1), float64(10*time.Millisecond))

	// On a stable link the drift samples are about 0
	for range 10 {
		c.addDriftSample(uint32(time.Since(peerStart).Microseconds()), 0)
	}

	require.InDelta(t, 0, c.driftTracer.sum/int64(c.driftTracer.span), float64(5*time.Millisecond.Microseconds()))
}

// The clock of the listener starts after the caller's start.
func TestTSBPDPeerClockLater(t *testing.T) {
	testPeerClockOffset(t, 150*time.Millisecond)
}

// The clock of the caller starts before the listener's start.
func TestTSBPDPeerClockEarlier(t *testing.T) {
	testPeerClockOffset(t, -200*time.Millisecond)
}
