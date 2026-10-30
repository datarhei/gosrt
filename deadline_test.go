package srt

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// deadlinePair returns a connected pair of a caller and the accepted connection of a listener.
func deadlinePair(t *testing.T, addr string) (Conn, Conn) {
	ln, err := Listen("srt", addr, DefaultConfig())
	require.NoError(t, err)
	t.Cleanup(ln.Close)

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
	config.StreamId = "publish:deadline"

	caller, err := Dial("srt", addr, config)
	require.NoError(t, err)
	t.Cleanup(func() { caller.Close() })

	var listener Conn
	select {
	case listener = <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("connection not accepted")
	}
	t.Cleanup(func() { listener.Close() })

	return caller, listener
}

func requireTimeout(t *testing.T, err error) {
	t.Helper()

	require.Error(t, err)
	require.True(t, errors.Is(err, os.ErrDeadlineExceeded), "error: %v", err)

	var netErr net.Error
	require.True(t, errors.As(err, &netErr))
	require.True(t, netErr.Timeout())
}

func TestReadDeadline(t *testing.T) {
	caller, listener := deadlinePair(t, "127.0.0.1:6210")

	buf := make([]byte, 2048)

	// Read times out on a silent connection
	require.NoError(t, listener.SetReadDeadline(time.Now().Add(100*time.Millisecond)))

	start := time.Now()
	_, err := listener.Read(buf)
	requireTimeout(t, err)
	require.InDelta(t, 100*time.Millisecond, time.Since(start), float64(80*time.Millisecond))

	// A deadline in the past times out immediately
	_, err = listener.Read(buf)
	requireTimeout(t, err)

	// The connection keeps working after a timeout, with a new deadline
	require.NoError(t, listener.SetReadDeadline(time.Now().Add(3*time.Second)))

	_, err = caller.Write([]byte("hello"))
	require.NoError(t, err)

	n, err := listener.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "hello", string(buf[:n]))
}

func TestReadDeadlineClear(t *testing.T) {
	caller, listener := deadlinePair(t, "127.0.0.1:6211")

	require.NoError(t, listener.SetReadDeadline(time.Now().Add(50*time.Millisecond)))
	require.NoError(t, listener.SetReadDeadline(time.Time{}))

	go func() {
		time.Sleep(300 * time.Millisecond)
		caller.Write([]byte("hello"))
	}()

	// Without a deadline, Read waits for the data
	buf := make([]byte, 2048)
	n, err := listener.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "hello", string(buf[:n]))
}

func TestReadDeadlineChangedWhileReading(t *testing.T) {
	_, listener := deadlinePair(t, "127.0.0.1:6212")

	done := make(chan error, 1)
	start := time.Now()

	go func() {
		buf := make([]byte, 2048)
		_, err := listener.Read(buf)
		done <- err
	}()

	// Read blocks without a deadline. Setting one wakes it up.
	time.Sleep(100 * time.Millisecond)
	require.NoError(t, listener.SetReadDeadline(time.Now().Add(100*time.Millisecond)))

	select {
	case err := <-done:
		requireTimeout(t, err)
		require.InDelta(t, 200*time.Millisecond, time.Since(start), float64(100*time.Millisecond))
	case <-time.After(2 * time.Second):
		t.Fatal("Read didn't return after the deadline")
	}

	// Moving the deadline further away while reading
	go func() {
		buf := make([]byte, 2048)
		_, err := listener.Read(buf)
		done <- err
	}()

	require.NoError(t, listener.SetReadDeadline(time.Now().Add(100*time.Millisecond)))
	start = time.Now()
	time.Sleep(50 * time.Millisecond)
	require.NoError(t, listener.SetReadDeadline(time.Now().Add(300*time.Millisecond)))

	select {
	case err := <-done:
		requireTimeout(t, err)
		require.InDelta(t, 350*time.Millisecond, time.Since(start), float64(100*time.Millisecond))
	case <-time.After(2 * time.Second):
		t.Fatal("Read didn't return after the deadline")
	}
}

func TestWriteDeadline(t *testing.T) {
	caller, _ := deadlinePair(t, "127.0.0.1:6213")

	require.NoError(t, caller.SetWriteDeadline(time.Now().Add(-time.Second)))

	_, err := caller.Write([]byte("hello"))
	requireTimeout(t, err)

	require.NoError(t, caller.SetWriteDeadline(time.Time{}))

	_, err = caller.Write([]byte("hello"))
	require.NoError(t, err)
}

func TestDeadlineCaller(t *testing.T) {
	caller, _ := deadlinePair(t, "127.0.0.1:6214")

	// The caller side has the deadlines too
	require.NoError(t, caller.SetDeadline(time.Now().Add(50*time.Millisecond)))

	buf := make([]byte, 2048)
	_, err := caller.Read(buf)
	requireTimeout(t, err)
}
