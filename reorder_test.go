package srt

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLossMaxTTL(t *testing.T) {
	ln, err := Listen("srt", "127.0.0.1:6220", DefaultConfig())
	require.NoError(t, err)
	defer ln.Close()

	accepted := make(chan Conn, 1)
	go func() {
		req, err := ln.Accept2()
		if err != nil {
			return
		}

		conn, err := req.Accept()
		if err != nil {
			return
		}

		accepted <- conn
	}()

	config := DefaultConfig()
	config.StreamId = "subscribe:lossmaxttl"
	config.LossMaxTTL = 30

	conn, err := Dial("srt", "127.0.0.1:6220", config)
	require.NoError(t, err)
	defer conn.Close()

	select {
	case c := <-accepted:
		defer c.Close()

		s := Statistics{}
		c.Stats(&s)

		// The listener doesn't use a reorder tolerance
		require.Equal(t, uint64(0), s.Instantaneous.PktReorderTolerance)
	case <-time.After(3 * time.Second):
		t.Fatal("connection not accepted")
	}

	// The reorder tolerance of the receiver starts with LossMaxTTL
	s := Statistics{}
	conn.Stats(&s)

	require.Equal(t, uint64(30), s.Instantaneous.PktReorderTolerance)
}
