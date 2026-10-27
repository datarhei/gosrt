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

func TestControlBaseTimeWrap(t *testing.T) {
	c := &srtConn{}
	c.tsbpdPeerOffset = 1000
	c.havePeerOffset = true

	wrap := int64(packet.MAX_TIMESTAMP) + 1
	at := func(ts uint32, carry int64) int64 { return carry + int64(ts) + c.tsbpdPeerOffset }

	// Far from a wrap
	c.tsbpdTimeBaseOffset = 0
	c.tsbpdWrapPeriod = false
	require.Equal(t, at(100_000_000, 0), c.controlBaseTime(100_000_000, at(100_000_000, 0)+50))

	// The data packets are in the wrap period. A control packet from before the wrap.
	c.tsbpdWrapPeriod = true
	ts := uint32(packet.MAX_TIMESTAMP - 10_000)
	require.Equal(t, at(ts, 0), c.controlBaseTime(ts, at(ts, 0)+50))

	// A control packet from after the wrap, but within the first 30s
	ts = 5_000_000
	require.Equal(t, at(ts, wrap), c.controlBaseTime(ts, at(ts, wrap)+50))

	// A control packet whose timestamp is already past 30s, while the data packets are still in the wrap period
	ts = 30_005_000
	require.Equal(t, at(ts, wrap), c.controlBaseTime(ts, at(ts, wrap)+50))

	// The wrap period of the data packets ended, the offset includes the wrap
	c.tsbpdTimeBaseOffset = uint64(wrap)
	c.tsbpdWrapPeriod = false
	require.Equal(t, at(ts, wrap), c.controlBaseTime(ts, at(ts, wrap)+50))

	// A late control packet from before the wrap, after the wrap period ended
	ts = uint32(packet.MAX_TIMESTAMP - 10_000)
	require.Equal(t, at(ts, 0), c.controlBaseTime(ts, at(ts, 0)+50))
}

func TestDriftSampleAtWrap(t *testing.T) {
	c := &srtConn{}
	c.havePeerOffset = true
	c.tsbpdWrapPeriod = true

	wrap := int64(packet.MAX_TIMESTAMP) + 1
	d := newDriftTracer()

	// ACKACKs around the end of the wrap period of the data packets, without any drift
	for i := range d.maxSpan {
		ts := uint32(29_990_000 + i*20)
		arrival := wrap + int64(ts)
		d.addSample(arrival, c.controlBaseTime(ts, arrival), 20_000)
	}

	require.InDelta(t, 0, d.correction(), 10)
}
