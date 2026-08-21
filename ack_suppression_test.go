package srt

import (
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestLowRateACKOverhead measures the control traffic a slow live stream pays
// for. A 1 fps camera at 25 kbit/s puts ~2.4 packets per second on the wire;
// the periodic ACK runs on a 10 ms timer, so without suppression the sender
// receives ~100 ACKs per second regardless — and owes an ACKACK for each.
func TestLowRateACKOverhead(t *testing.T) {
	const (
		addr     = "127.0.0.1:6111"
		interval = 400 * time.Millisecond // 2.5 packets/s, as at 1 fps / 25 kbit/s
		packets  = 10                     // 4 s of stream
	)

	server := Server{
		Addr: addr,
		HandleConnect: func(req ConnRequest) ConnType {
			if req.StreamId() == "publish" {
				return PUBLISH
			}
			return REJECT
		},
		HandlePublish: func(conn Conn) {
			buf := make([]byte, 1316)
			for {
				if _, err := conn.Read(buf); err != nil {
					break
				}
			}
			conn.Close()
		},
	}

	require.NoError(t, server.Listen())
	defer server.Shutdown()

	go func() {
		if err := server.Serve(); err != ErrServerClosed {
			require.NoError(t, err)
		}
	}()

	config := DefaultConfig()
	config.StreamId = "publish"

	conn, err := Dial("srt", addr, config)
	require.NoError(t, err)

	payload := make([]byte, 1316)
	start := time.Now()
	for i := 0; i < packets; i++ {
		_, err := conn.Write(payload)
		require.True(t, err == nil || err == io.EOF)
		time.Sleep(interval)
	}
	elapsed := time.Since(start).Seconds()

	stats := &Statistics{}
	conn.Stats(stats)
	conn.Close()

	data := stats.Accumulated.PktSent
	acks := stats.Accumulated.PktRecvACK
	// 72 B per full ACK inbound, and the peer answers each with a 44 B ACKACK
	// outbound; IPv4 + UDP counted in both.
	fmt.Printf("\n%d data pkt (%.1f/s) | %d ack in (%.1f/s) "+
		"| control %.1f kbit/s down, %.1f kbit/s up\n",
		data, float64(data)/elapsed,
		acks, float64(acks)/elapsed,
		float64(acks)*72*8/1000/elapsed, float64(acks)*44*8/1000/elapsed)

	// One ACK per data packet plus a handshake handful is healthy; the 10 ms
	// timer unsuppressed would put this in the hundreds.
	require.Less(t, acks, uint64(4*packets),
		"periodic ACKs are not being suppressed on an idle link")
}
