package srt

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"
)

func idleTestPair(t *testing.T, cfg Config) (Conn, Conn) {
	t.Helper()
	ln, err := Listen("srt", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	type acceptedResult struct {
		conn Conn
		err  error
	}
	accepted := make(chan acceptedResult, 1)
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		req, err := ln.Accept2()
		if err != nil {
			accepted <- acceptedResult{err: err}
			return
		}
		conn, err := req.Accept()
		accepted <- acceptedResult{conn: conn, err: err}
	}()
	t.Cleanup(func() {
		ln.Close()
		select {
		case <-acceptDone:
		case <-time.After(3 * time.Second):
			t.Error("listener accept did not finish")
		}
	})
	client, err := Dial("srt", ln.Addr().String(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	select {
	case result := <-accepted:
		if result.err != nil || result.conn == nil {
			t.Fatalf("accept = (%v, %v)", result.conn, result.err)
		}
		t.Cleanup(func() { result.conn.Close() })
		return client, result.conn
	case <-time.After(3 * time.Second):
		t.Fatal("server accept timed out")
		return nil, nil
	}
}

func TestIdlePeersDeliverDataAfterPeerIdleTimeout(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PeerIdleTimeout = 2 * time.Second
	client, server := idleTestPair(t, cfg)
	payload := bytes.Repeat([]byte{'x'}, 1316)
	got := make([]byte, len(payload))
	result := make(chan error, 1)
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		_, err := io.ReadFull(server, got)
		result <- err
	}()
	t.Cleanup(func() {
		server.Close()
		select {
		case <-readDone:
		case <-time.After(3 * time.Second):
			t.Error("server read did not finish")
		}
	})

	// No application data is sent until after the peer-idle deadline. Control
	// traffic must retain the healthy session without producing an ACK storm.
	idle := time.NewTimer(3 * time.Second)
	defer idle.Stop()
	select {
	case err := <-result:
		t.Fatalf("idle peer closed before the next data write: %v", err)
	case <-idle.C:
	}
	for name, conn := range map[string]Conn{"client": client, "server": server} {
		stats := &Statistics{}
		conn.Stats(stats)
		if stats.Accumulated.PktSentACK > 12 {
			t.Fatalf("%s sent %d ACKs during three idle seconds", name, stats.Accumulated.PktSentACK)
		}
	}
	if n, err := client.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("write = (%d, %v), want %d bytes", n, err, len(payload))
	}
	select {
	case err := <-result:
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("post-idle read = %v, payload matches = %t", err, bytes.Equal(got, payload))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("post-idle data was not delivered")
	}
}

func TestIdleControlDoesNotKeepAnUnreachablePeerAlive(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PeerIdleTimeout = 2 * time.Second
	client, server := idleTestPair(t, cfg)
	// Closing the UDP socket bypasses a graceful SRT shutdown and injects a
	// peer that can no longer answer any control packet.
	if err := client.(*dialer).pc.Close(); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		_, err := server.Read(make([]byte, 1))
		result <- err
	}()
	t.Cleanup(func() {
		server.Close()
		select {
		case <-readDone:
		case <-time.After(3 * time.Second):
			t.Error("unreachable peer read did not finish")
		}
	})
	select {
	case err := <-result:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("unreachable peer read = %v, want EOF", err)
		}
	case <-time.After(cfg.PeerIdleTimeout + time.Second):
		t.Fatal("outbound ACK refresh extended the unreachable peer deadline")
	}
}
