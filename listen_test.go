package srt

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/datarhei/gosrt/internal/packet"

	"github.com/stretchr/testify/require"
)

func TestListenReuse(t *testing.T) {
	ln, err := Listen("srt", "127.0.0.1:6003", DefaultConfig())
	require.NoError(t, err)

	ln.Close()

	ln, err = Listen("srt", "127.0.0.1:6003", DefaultConfig())
	require.NoError(t, err)

	ln.Close()
}

func TestListen(t *testing.T) {
	ln, err := Listen("srt", "127.0.0.1:6003", DefaultConfig())
	require.NoError(t, err)

	listenWg := sync.WaitGroup{}
	listenWg.Add(1)

	go func(ln Listener) {
		listenWg.Done()
		for {
			_, _, err := ln.Accept(func(req ConnRequest) ConnType {
				require.Equal(t, "foobar", req.StreamId())
				require.False(t, req.IsEncrypted())

				return SUBSCRIBE
			})

			if err == ErrListenerClosed {
				return
			}

			require.NoError(t, err)
		}
	}(ln)

	listenWg.Wait()

	config := DefaultConfig()
	config.StreamId = "foobar"

	conn, err := Dial("srt", "127.0.0.1:6003", config)
	require.NoError(t, err)

	err = conn.Close()
	require.NoError(t, err)

	ln.Close()
}

func TestListenCrypt(t *testing.T) {
	ln, err := Listen("srt", "127.0.0.1:6003", DefaultConfig())
	require.NoError(t, err)

	listenWg := sync.WaitGroup{}
	listenWg.Add(1)

	go func(ln Listener) {
		listenWg.Done()
		for {
			_, _, err := ln.Accept(func(req ConnRequest) ConnType {
				require.Equal(t, "foobar", req.StreamId())
				require.True(t, req.IsEncrypted())

				if req.SetPassphrase("zaboofzaboof") != nil {
					return REJECT
				}

				return SUBSCRIBE
			})

			if err == ErrListenerClosed {
				return
			}

			require.NoError(t, err)
		}
	}(ln)

	listenWg.Wait()

	config := DefaultConfig()
	config.StreamId = "foobar"
	config.Passphrase = "zaboofzaboof"

	conn, err := Dial("srt", "127.0.0.1:6003", config)
	require.NoError(t, err)

	err = conn.Close()
	require.NoError(t, err)

	config.Passphrase = "raboofraboof"

	_, err = Dial("srt", "127.0.0.1:6003", config)
	require.Error(t, err)

	ln.Close()
}

func TestListenHSV4(t *testing.T) {
	start := time.Now()

	lc := net.ListenConfig{
		Control: ListenControl(DefaultConfig()),
	}

	lp, err := lc.ListenPacket(context.Background(), "udp", "127.0.0.1:6003")
	require.NoError(t, err)

	pc := lp.(*net.UDPConn)

	listenWg := sync.WaitGroup{}

	packets := make(chan packet.Packet, 16)

	listenWg.Add(1)

	go func() {
		buffer := make([]byte, MAX_MSS_SIZE)
		listenWg.Done()
		for {
			n, addr, err := pc.ReadFrom(buffer)
			if err != nil {
				return
			}

			p := packet.NewPacket(addr, buffer[:n])
			require.NotEqual(t, nil, p)

			if p.Header().ControlType != packet.CTRLTYPE_HANDSHAKE {
				continue
			}

			packets <- p
		}
	}()

	listenWg.Wait()

	go func() {
		conn, err := Dial("srt", "127.0.0.1:6003", DefaultConfig())
		if err != nil {
			if err == ErrClientClosed {
				return
			}
			require.NoError(t, err)
		}
		require.NotNil(t, conn)

		conn.Close()
	}()

	p := <-packets

	recvcif := &packet.CIFHandshake{}
	err = p.UnmarshalCIF(recvcif)
	require.NoError(t, err)

	require.Equal(t, uint32(4), recvcif.Version)
	require.Equal(t, uint16(0), recvcif.EncryptionField)
	require.Equal(t, uint16(2), recvcif.ExtensionField)
	require.Equal(t, packet.HSTYPE_INDUCTION, recvcif.HandshakeType)
	require.Empty(t, recvcif.SynCookie)

	p.Header().IsControlPacket = true
	p.Header().ControlType = packet.CTRLTYPE_HANDSHAKE
	p.Header().SubType = 0
	p.Header().TypeSpecific = 0
	p.Header().Timestamp = uint32(time.Since(start).Microseconds())
	p.Header().DestinationSocketId = recvcif.SRTSocketId

	sendcif := &packet.CIFHandshake{
		IsRequest:                   false,
		Version:                     4,
		EncryptionField:             0,
		ExtensionField:              2,
		InitialPacketSequenceNumber: recvcif.InitialPacketSequenceNumber,
		MaxTransmissionUnitSize:     recvcif.MaxTransmissionUnitSize,
		MaxFlowWindowSize:           recvcif.MaxFlowWindowSize,
		HandshakeType:               packet.HSTYPE_INDUCTION,
		SRTSocketId:                 recvcif.SRTSocketId,
		SynCookie:                   1234,
	}

	sendcif.PeerIP.FromNetAddr(pc.LocalAddr())

	p.MarshalCIF(sendcif)

	var data bytes.Buffer

	err = p.Marshal(&data)
	require.NoError(t, err)

	pc.WriteTo(data.Bytes(), p.Header().Addr)

	p = <-packets

	recvcif = &packet.CIFHandshake{}
	err = p.UnmarshalCIF(recvcif)
	require.NoError(t, err)

	require.Equal(t, uint32(4), recvcif.Version)
	require.Equal(t, uint16(0), recvcif.EncryptionField)
	require.Equal(t, uint16(2), recvcif.ExtensionField)
	require.Equal(t, packet.HSTYPE_CONCLUSION, recvcif.HandshakeType)
	require.Equal(t, sendcif.SynCookie, recvcif.SynCookie)

	p.Header().IsControlPacket = true
	p.Header().ControlType = packet.CTRLTYPE_HANDSHAKE
	p.Header().SubType = 0
	p.Header().TypeSpecific = 0
	p.Header().Timestamp = uint32(time.Since(start).Microseconds())
	p.Header().DestinationSocketId = recvcif.SRTSocketId

	sendcif = recvcif
	sendcif.IsRequest = false
	sendcif.SRTSocketId = 9876
	sendcif.SynCookie = 0

	sendcif.PeerIP.FromNetAddr(pc.LocalAddr())

	p.MarshalCIF(sendcif)

	data.Reset()

	err = p.Marshal(&data)
	require.NoError(t, err)

	pc.WriteTo(data.Bytes(), p.Header().Addr)

	pc.Close()
}

func TestListenHSV5(t *testing.T) {
	start := time.Now()

	lc := net.ListenConfig{
		Control: ListenControl(DefaultConfig()),
	}

	lp, err := lc.ListenPacket(context.Background(), "udp", "127.0.0.1:6003")
	require.NoError(t, err)

	pc := lp.(*net.UDPConn)

	listenWg := sync.WaitGroup{}

	packets := make(chan packet.Packet, 16)

	listenWg.Add(1)

	go func() {
		buffer := make([]byte, MAX_MSS_SIZE)
		listenWg.Done()
		for {
			n, addr, err := pc.ReadFrom(buffer)
			if err != nil {
				return
			}

			p := packet.NewPacket(addr, buffer[:n])
			require.NotEqual(t, nil, p)

			if p.Header().ControlType != packet.CTRLTYPE_HANDSHAKE {
				continue
			}

			packets <- p
		}
	}()

	listenWg.Wait()

	go func() {
		config := DefaultConfig()
		config.StreamId = "foobar"
		conn, err := Dial("srt", "127.0.0.1:6003", config)
		if err != nil {
			if err == ErrClientClosed {
				return
			}
			require.NoError(t, err)
		}
		require.NotNil(t, conn)

		conn.Close()
	}()

	p := <-packets

	recvcif := &packet.CIFHandshake{}
	err = p.UnmarshalCIF(recvcif)
	require.NoError(t, err)

	require.Equal(t, uint32(4), recvcif.Version)
	require.Equal(t, uint16(0), recvcif.EncryptionField)
	require.Equal(t, uint16(2), recvcif.ExtensionField)
	require.Equal(t, packet.HSTYPE_INDUCTION, recvcif.HandshakeType)
	require.Empty(t, recvcif.SynCookie)

	p.Header().IsControlPacket = true
	p.Header().ControlType = packet.CTRLTYPE_HANDSHAKE
	p.Header().SubType = 0
	p.Header().TypeSpecific = 0
	p.Header().Timestamp = uint32(time.Since(start).Microseconds())
	p.Header().DestinationSocketId = recvcif.SRTSocketId

	sendcif := &packet.CIFHandshake{
		IsRequest:                   false,
		Version:                     5,
		EncryptionField:             0,
		ExtensionField:              0x4A17,
		InitialPacketSequenceNumber: recvcif.InitialPacketSequenceNumber,
		MaxTransmissionUnitSize:     recvcif.MaxTransmissionUnitSize,
		MaxFlowWindowSize:           recvcif.MaxFlowWindowSize,
		HandshakeType:               packet.HSTYPE_INDUCTION,
		SRTSocketId:                 recvcif.SRTSocketId,
		SynCookie:                   1234,
	}

	sendcif.PeerIP.FromNetAddr(pc.LocalAddr())

	p.MarshalCIF(sendcif)

	var data bytes.Buffer

	err = p.Marshal(&data)
	require.NoError(t, err)

	pc.WriteTo(data.Bytes(), p.Header().Addr)

	p = <-packets

	recvcif = &packet.CIFHandshake{}
	err = p.UnmarshalCIF(recvcif)
	require.NoError(t, err)

	require.Equal(t, uint32(5), recvcif.Version)
	require.Equal(t, uint16(0), recvcif.EncryptionField)
	require.Equal(t, uint16(5), recvcif.ExtensionField)
	require.Equal(t, packet.HSTYPE_CONCLUSION, recvcif.HandshakeType)
	require.Equal(t, sendcif.SynCookie, recvcif.SynCookie)

	p.Header().IsControlPacket = true
	p.Header().ControlType = packet.CTRLTYPE_HANDSHAKE
	p.Header().SubType = 0
	p.Header().TypeSpecific = 0
	p.Header().Timestamp = uint32(time.Since(start).Microseconds())
	p.Header().DestinationSocketId = recvcif.SRTSocketId

	sendcif = recvcif
	sendcif.IsRequest = false
	sendcif.SRTSocketId = 9876
	sendcif.SynCookie = 0

	sendcif.PeerIP.FromNetAddr(pc.LocalAddr())

	p.MarshalCIF(sendcif)

	data.Reset()

	err = p.Marshal(&data)
	require.NoError(t, err)

	pc.WriteTo(data.Bytes(), p.Header().Addr)

	pc.Close()
}
