package srt

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"testing"
	"time"

	"github.com/datarhei/gosrt/circular"
	"github.com/datarhei/gosrt/congestion/live"
	"github.com/datarhei/gosrt/packet"
	"github.com/stretchr/testify/require"
)

func TestDropRequestAdvancesACKWithoutWaitingForPlayout(t *testing.T) {
	for _, messageNumber := range []uint32{0, 42} {
		t.Run(strconv.FormatUint(uint64(messageNumber), 10), func(t *testing.T) {
			testDropRequestAdvancesACK(t, messageNumber)
		})
	}
}

func testDropRequestAdvancesACK(t *testing.T, messageNumber uint32) {
	var ack uint32
	var naks []uint32
	var delivered []uint32
	recv := live.NewReceiver(live.ReceiveConfig{
		InitialSequenceNumber: circular.New(100, packet.MAX_SEQUENCENUMBER),
		PeriodicACKInterval:   10,
		PeriodicNAKInterval:   20,
		OnSendACK:             func(seq circular.Number, _ bool) { ack = seq.Val() },
		OnSendNAK: func(seqs []circular.Number) {
			for _, seq := range seqs {
				naks = append(naks, seq.Val())
			}
		},
		OnDeliver: func(p packet.Packet) {
			delivered = append(delivered, p.Header().PacketSequenceNumber.Val())
		},
	})
	// A slow receiver clock must not delay acknowledgement of a sender drop.
	const playout = uint64(1_000_000_000_000)
	for _, seq := range []uint32{100, 103} {
		p := packet.NewPacket(nil)
		p.Header().PacketSequenceNumber = circular.New(seq, packet.MAX_SEQUENCENUMBER)
		p.Header().PktTsbpdTime = playout
		recv.Push(p)
	}
	recv.Tick(20)
	require.Equal(t, uint32(101), ack)
	require.Equal(t, []uint32{101, 102, 101, 102}, naks)
	naks = nil

	cfg := DefaultConfig()
	c := &srtConn{recv: recv, config: cfg, peerIdleTimeout: time.NewTimer(time.Hour), logger: NewLogger(nil)}
	defer c.peerIdleTimeout.Stop()
	// Use a complete wire packet so dispatch and inclusive big-endian bounds
	// are exercised independently of the DROPREQ encoder.
	var wire bytes.Buffer
	for _, word := range []uint32{0x80070000, messageNumber, 123, 1, 101, 102} {
		require.NoError(t, binary.Write(&wire, binary.BigEndian, word))
	}
	p, err := packet.NewPacketFromData(nil, wire.Bytes())
	require.NoError(t, err)
	c.handlePacket(p)
	recv.Tick(40)
	require.Equal(t, uint32(104), ack)
	require.Empty(t, naks)
	require.Empty(t, delivered)
	recv.Tick(playout)
	require.Equal(t, []uint32{100, 103}, delivered)
}

func TestDropRequestMalformedDoesNotChangeReceiver(t *testing.T) {
	var ack uint32
	recv := live.NewReceiver(live.ReceiveConfig{
		InitialSequenceNumber: circular.New(100, packet.MAX_SEQUENCENUMBER),
		OnSendACK:             func(seq circular.Number, _ bool) { ack = seq.Val() },
	})
	c := &srtConn{recv: recv, config: DefaultConfig(), peerIdleTimeout: time.NewTimer(time.Hour), logger: NewLogger(nil)}
	defer c.peerIdleTimeout.Stop()
	for _, data := range [][]byte{
		nil, {0, 0, 0, 100}, {0, 0, 0, 100, 0, 0, 0, 99},
		{0x80, 0, 0, 100, 0, 0, 0, 101}, {0, 0, 0, 100, 0, 0, 0, 101, 0},
	} {
		p := packet.NewPacket(nil)
		p.Header().IsControlPacket = true
		p.Header().ControlType = packet.CRTLTYPE_DROPREQ
		p.SetData(data)
		c.handlePacket(p)
		recv.Tick(20)
		require.Equal(t, uint32(100), ack)
	}
	require.Equal(t, uint64(5), c.statistics.pktRecvInvalid)
}

func TestDropRequestUDPDeliveryAndNAKSuppression(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ReceiverLatency = 500 * time.Millisecond
	cfg.PeerLatency = 500 * time.Millisecond
	client, server := idleTestPair(t, cfg)
	dl := client.(*dialer)
	rc := server.(*srtConn)
	initial := dl.initialPacketSequenceNumber
	// Bypass the sending congestion controller to inject an unrecoverable gap
	// while exercising a real handshake, UDP socket, dispatch and ACK timer.
	send := func(p packet.Packet) {
		t.Helper()
		p.Header().DestinationSocketId = server.SocketId()
		var wire bytes.Buffer
		require.NoError(t, p.Marshal(&wire))
		_, err := dl.pc.Write(wire.Bytes())
		require.NoError(t, err)
	}
	for _, offset := range []uint32{0, 3} {
		p := packet.NewPacket(nil)
		p.Header().PacketSequenceNumber = initial.Add(offset)
		p.Header().MessageNumber = offset + 1
		p.Header().Timestamp = 1000 + offset*1000
		p.SetData([]byte{byte(offset)})
		send(p)
	}
	lastACK := func() circular.Number {
		rc.ackLock.RLock()
		defer rc.ackLock.RUnlock()
		return rc.lastSentACK
	}
	require.Eventually(t, func() bool { return lastACK().Equals(initial.Inc()) }, time.Second, time.Millisecond)
	var before Statistics
	server.Stats(&before)
	require.Positive(t, before.Accumulated.PktSentNAK)
	p := packet.NewPacket(nil)
	p.Header().IsControlPacket = true
	p.Header().ControlType = packet.CRTLTYPE_DROPREQ
	p.Header().TypeSpecific = 0
	var payload [8]byte
	binary.BigEndian.PutUint32(payload[:4], initial.Inc().Val())
	binary.BigEndian.PutUint32(payload[4:], initial.Add(2).Val())
	p.SetData(payload[:])
	send(p)
	require.Eventually(t, func() bool { return lastACK().Equals(initial.Add(4)) }, 250*time.Millisecond, time.Millisecond)
	var afterDrop Statistics
	server.Stats(&afterDrop)
	// The two received packets must survive the request and reach Read.
	received := make(chan []byte, 1)
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		var got []byte
		for range 2 {
			p, err := server.ReadPacket()
			if err != nil {
				break
			}
			got = append(got, p.Data()...)
		}
		received <- got
	}()
	t.Cleanup(func() {
		server.Close()
		select {
		case <-readDone:
		case <-time.After(time.Second):
			t.Error("DROPREQ read did not finish")
		}
	})
	select {
	case got := <-received:
		require.Equal(t, []byte{0, 3}, got)
	case <-time.After(2 * time.Second):
		t.Fatal("received packets were not delivered after DROPREQ")
	}
	var after Statistics
	server.Stats(&after)
	require.Equal(t, afterDrop.Accumulated.PktSentNAK, after.Accumulated.PktSentNAK)
}
