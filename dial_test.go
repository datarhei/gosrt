package srt

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/datarhei/gosrt/circular"
	"github.com/datarhei/gosrt/packet"

	"github.com/stretchr/testify/require"
)

func TestDialReject(t *testing.T) {
	ln, err := Listen("srt", "127.0.0.1:6003", DefaultConfig())
	require.NoError(t, err)

	listenWg := sync.WaitGroup{}
	listenWg.Add(1)

	go func(ln Listener) {
		listenWg.Done()
		for {
			_, _, err := ln.Accept(func(req ConnRequest) ConnType {
				return REJECT
			})

			if err == ErrListenerClosed {
				return
			}

			require.NoError(t, err)
		}
	}(ln)

	listenWg.Wait()

	conn, err := Dial("srt", "127.0.0.1:6003", DefaultConfig())
	require.Error(t, err)
	require.Nil(t, conn)

	ln.Close()
}

func TestDialOK(t *testing.T) {
	ln, err := Listen("srt", "127.0.0.1:6003", DefaultConfig())
	require.NoError(t, err)

	listenWg := sync.WaitGroup{}
	listenWg.Add(1)

	go func(ln Listener) {
		listenWg.Done()
		for {
			_, _, err := ln.Accept(func(req ConnRequest) ConnType {
				return SUBSCRIBE
			})

			if err == ErrListenerClosed {
				return
			}

			require.NoError(t, err)
		}
	}(ln)

	listenWg.Wait()

	conn, err := Dial("srt", "127.0.0.1:6003", DefaultConfig())
	require.NoError(t, err)

	err = conn.Close()
	require.NoError(t, err)

	ln.Close()
}

func TestDialV4(t *testing.T) {
	ln, err := Listen("srt", "127.0.0.1:6003", DefaultConfig())
	require.NoError(t, err)

	listenWg := sync.WaitGroup{}
	listenWg.Add(1)

	go func(ln Listener) {
		listenWg.Done()
		for {
			_, _, err := ln.Accept(func(req ConnRequest) ConnType {
				return SUBSCRIBE
			})

			if err == ErrListenerClosed {
				return
			}

			require.NoError(t, err)
		}
	}(ln)

	listenWg.Wait()

	start := time.Now()

	raddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:6003")
	require.NoError(t, err)

	pc, err := net.DialUDP("udp", nil, raddr)
	require.NoError(t, err)

	packets := make(chan packet.Packet, 16)

	listenWg.Add(1)

	go func() {
		buffer := make([]byte, MAX_MSS_SIZE)
		listenWg.Done()
		for {
			n, _, err := pc.ReadFrom(buffer)
			if err != nil {
				return
			}

			p, err := packet.NewPacketFromData(pc.RemoteAddr(), buffer[:n])
			require.NoError(t, err)

			packets <- p
		}
	}()

	p := packet.NewPacket(pc.RemoteAddr())

	p.Header().IsControlPacket = true
	p.Header().ControlType = packet.CTRLTYPE_HANDSHAKE
	p.Header().SubType = 0
	p.Header().TypeSpecific = 0
	p.Header().Timestamp = uint32(time.Since(start).Microseconds())
	p.Header().DestinationSocketId = 0

	sendcif := &packet.CIFHandshake{
		IsRequest:                   true,
		Version:                     4,
		EncryptionField:             0,
		ExtensionField:              2,
		InitialPacketSequenceNumber: circular.New(0, packet.MAX_SEQUENCENUMBER),
		MaxTransmissionUnitSize:     1500, // MTU size
		MaxFlowWindowSize:           25600,
		HandshakeType:               packet.HSTYPE_INDUCTION,
		SRTSocketId:                 1234,
		SynCookie:                   0,
	}

	sendcif.PeerIP.FromNetAddr(pc.LocalAddr())

	p.MarshalCIF(sendcif)

	var data bytes.Buffer

	err = p.Marshal(&data)
	require.NoError(t, err)

	pc.Write(data.Bytes())

	p = <-packets

	recvcif := &packet.CIFHandshake{}
	err = p.UnmarshalCIF(recvcif)
	require.NoError(t, err)

	require.Equal(t, false, recvcif.IsRequest)
	require.Equal(t, uint32(5), recvcif.Version)
	require.Equal(t, uint16(0), recvcif.EncryptionField)
	require.Equal(t, uint16(0x4A17), recvcif.ExtensionField)
	require.Equal(t, sendcif.InitialPacketSequenceNumber, recvcif.InitialPacketSequenceNumber)
	require.Equal(t, sendcif.MaxTransmissionUnitSize, recvcif.MaxTransmissionUnitSize)
	require.Equal(t, sendcif.MaxFlowWindowSize, recvcif.MaxFlowWindowSize)
	require.Equal(t, sendcif.HandshakeType, recvcif.HandshakeType)
	require.NotEmpty(t, recvcif.SynCookie)

	sendcif.HandshakeType = packet.HSTYPE_CONCLUSION
	sendcif.SynCookie = recvcif.SynCookie

	p.MarshalCIF(sendcif)

	p.Header().IsControlPacket = true

	p.Header().ControlType = packet.CTRLTYPE_HANDSHAKE
	p.Header().SubType = 0
	p.Header().TypeSpecific = 0

	p.Header().Timestamp = uint32(time.Since(start).Microseconds())
	p.Header().DestinationSocketId = 0

	data.Reset()

	err = p.Marshal(&data)
	require.NoError(t, err)

	pc.Write(data.Bytes())

	p = <-packets

	recvcif = &packet.CIFHandshake{}
	err = p.UnmarshalCIF(recvcif)
	require.NoError(t, err)

	require.Equal(t, false, recvcif.IsRequest)
	require.Equal(t, uint32(4), recvcif.Version)
	require.Equal(t, uint16(0), recvcif.EncryptionField)
	require.Equal(t, uint16(2), recvcif.ExtensionField)
	require.Equal(t, sendcif.InitialPacketSequenceNumber, recvcif.InitialPacketSequenceNumber)
	require.Equal(t, sendcif.MaxTransmissionUnitSize, recvcif.MaxTransmissionUnitSize)
	require.Equal(t, sendcif.MaxFlowWindowSize, recvcif.MaxFlowWindowSize)
	require.Equal(t, sendcif.HandshakeType, recvcif.HandshakeType)
	require.Empty(t, recvcif.SynCookie)

	require.False(t, recvcif.HasHS)
	require.False(t, recvcif.HasKM)
	require.False(t, recvcif.HasSID)

	pc.Close()
	ln.Close()
}

func TestDialV5(t *testing.T) {
	ln, err := Listen("srt", "127.0.0.1:6003", DefaultConfig())
	require.NoError(t, err)

	listenWg := sync.WaitGroup{}
	listenWg.Add(1)

	go func(ln Listener) {
		listenWg.Done()
		for {
			_, _, err := ln.Accept(func(req ConnRequest) ConnType {
				return SUBSCRIBE
			})

			if err == ErrListenerClosed {
				return
			}

			require.NoError(t, err)
		}
	}(ln)

	listenWg.Wait()

	start := time.Now()

	raddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:6003")
	require.NoError(t, err)

	pc, err := net.DialUDP("udp", nil, raddr)
	require.NoError(t, err)

	packets := make(chan packet.Packet, 16)

	listenWg.Add(1)

	go func() {
		buffer := make([]byte, MAX_MSS_SIZE)
		listenWg.Done()
		for {
			n, _, err := pc.ReadFrom(buffer)
			if err != nil {
				return
			}

			p, err := packet.NewPacketFromData(pc.RemoteAddr(), buffer[:n])
			require.NoError(t, err)

			packets <- p
		}
	}()

	p := packet.NewPacket(pc.RemoteAddr())

	p.Header().IsControlPacket = true

	p.Header().ControlType = packet.CTRLTYPE_HANDSHAKE
	p.Header().SubType = 0
	p.Header().TypeSpecific = 0

	p.Header().Timestamp = uint32(time.Since(start).Microseconds())
	p.Header().DestinationSocketId = 0

	sendcif := &packet.CIFHandshake{
		IsRequest:                   true,
		Version:                     4,
		EncryptionField:             0,
		ExtensionField:              2,
		InitialPacketSequenceNumber: circular.New(0, packet.MAX_SEQUENCENUMBER),
		MaxTransmissionUnitSize:     1500, // MTU size
		MaxFlowWindowSize:           25600,
		HandshakeType:               packet.HSTYPE_INDUCTION,
		SRTSocketId:                 1234,
		SynCookie:                   0,
	}

	sendcif.PeerIP.FromNetAddr(pc.LocalAddr())

	p.MarshalCIF(sendcif)

	var data bytes.Buffer

	err = p.Marshal(&data)
	require.NoError(t, err)

	pc.Write(data.Bytes())

	p = <-packets

	recvcif := &packet.CIFHandshake{}
	err = p.UnmarshalCIF(recvcif)
	require.NoError(t, err)

	require.Equal(t, false, recvcif.IsRequest)
	require.Equal(t, uint32(5), recvcif.Version)
	require.Equal(t, uint16(0), recvcif.EncryptionField)
	require.Equal(t, uint16(0x4A17), recvcif.ExtensionField)
	require.Equal(t, sendcif.InitialPacketSequenceNumber, recvcif.InitialPacketSequenceNumber)
	require.Equal(t, sendcif.MaxTransmissionUnitSize, recvcif.MaxTransmissionUnitSize)
	require.Equal(t, sendcif.MaxFlowWindowSize, recvcif.MaxFlowWindowSize)
	require.Equal(t, sendcif.HandshakeType, recvcif.HandshakeType)
	require.NotEmpty(t, recvcif.SynCookie)

	sendcif.Version = 5
	sendcif.ExtensionField = recvcif.ExtensionField
	sendcif.HandshakeType = packet.HSTYPE_CONCLUSION
	sendcif.SynCookie = recvcif.SynCookie

	sendcif.HasHS = true
	sendcif.SRTHS = &packet.CIFHandshakeExtension{
		SRTVersion: SRT_VERSION,
		SRTFlags: packet.CIFHandshakeExtensionFlags{
			TSBPDSND:      true,
			TSBPDRCV:      true,
			CRYPT:         true, // must always set to true
			TLPKTDROP:     true,
			PERIODICNAK:   true,
			REXMITFLG:     true,
			STREAM:        false,
			PACKET_FILTER: false,
		},
		RecvTSBPDDelay: uint16(120),
		SendTSBPDDelay: uint16(120),
	}

	sendcif.HasSID = true
	sendcif.StreamId = "foobar"

	p.MarshalCIF(sendcif)

	p.Header().IsControlPacket = true

	p.Header().ControlType = packet.CTRLTYPE_HANDSHAKE
	p.Header().SubType = 0
	p.Header().TypeSpecific = 0

	p.Header().Timestamp = uint32(time.Since(start).Microseconds())
	p.Header().DestinationSocketId = 0

	data.Reset()

	err = p.Marshal(&data)
	require.NoError(t, err)

	pc.Write(data.Bytes())

	p = <-packets

	recvcif = &packet.CIFHandshake{}
	err = p.UnmarshalCIF(recvcif)
	require.NoError(t, err)

	require.Equal(t, false, recvcif.IsRequest)
	require.Equal(t, uint32(5), recvcif.Version)
	require.Equal(t, uint16(0), recvcif.EncryptionField)
	require.Equal(t, uint16(5), recvcif.ExtensionField)
	require.Equal(t, sendcif.InitialPacketSequenceNumber, recvcif.InitialPacketSequenceNumber)
	require.Equal(t, sendcif.MaxTransmissionUnitSize, recvcif.MaxTransmissionUnitSize)
	require.Equal(t, sendcif.MaxFlowWindowSize, recvcif.MaxFlowWindowSize)
	require.Equal(t, sendcif.HandshakeType, recvcif.HandshakeType)
	require.Empty(t, recvcif.SynCookie)

	require.True(t, recvcif.HasHS)
	require.Equal(t, recvcif.SRTHS, sendcif.SRTHS)
	require.False(t, recvcif.HasKM)
	require.True(t, recvcif.HasSID)
	require.Equal(t, recvcif.StreamId, sendcif.StreamId)

	pc.Close()
	ln.Close()
}

// test support for servers based on libsrt <= 1.3.0
// in which DestinationSocketId of the CONCLUSION response is always zero.
func TestDialV5Pre130(t *testing.T) {
	ln, err := net.ListenPacket("udp", "127.0.0.1:6003")
	require.NoError(t, err)
	defer ln.Close()

	serverDone := make(chan error, 1)

	go func() {
		buf := make([]byte, MAX_MSS_SIZE)

		// Receive INDUCTION request.
		n, addr, err := ln.ReadFrom(buf)
		if err != nil {
			serverDone <- err
			return
		}
		p, err := packet.NewPacketFromData(addr, buf[:n])
		if err != nil {
			serverDone <- err
			return
		}
		recvcif := &packet.CIFHandshake{}
		if err = p.UnmarshalCIF(recvcif); err != nil {
			serverDone <- err
			return
		}
		callerSocketId := recvcif.SRTSocketId

		p.Header().IsControlPacket = true
		p.Header().ControlType = packet.CTRLTYPE_HANDSHAKE
		p.Header().SubType = 0
		p.Header().TypeSpecific = 0
		p.Header().Timestamp = 0
		p.Header().DestinationSocketId = callerSocketId
		inductionResp := &packet.CIFHandshake{
			IsRequest:                   false,
			Version:                     5,
			EncryptionField:             0,
			ExtensionField:              0x4A17,
			InitialPacketSequenceNumber: recvcif.InitialPacketSequenceNumber,
			MaxTransmissionUnitSize:     recvcif.MaxTransmissionUnitSize,
			MaxFlowWindowSize:           recvcif.MaxFlowWindowSize,
			HandshakeType:               packet.HSTYPE_INDUCTION,
			SRTSocketId:                 9876,
			SynCookie:                   0xdeadbeef,
		}
		inductionResp.PeerIP.FromNetAddr(ln.LocalAddr())
		p.MarshalCIF(inductionResp)
		var outbuf bytes.Buffer
		if err = p.Marshal(&outbuf); err != nil {
			serverDone <- err
			return
		}
		ln.WriteTo(outbuf.Bytes(), p.Header().Addr)

		// Receive CONCLUSION request.
		n, addr, err = ln.ReadFrom(buf)
		if err != nil {
			serverDone <- err
			return
		}
		p, err = packet.NewPacketFromData(addr, buf[:n])
		if err != nil {
			serverDone <- err
			return
		}
		recvcif = &packet.CIFHandshake{}
		if err = p.UnmarshalCIF(recvcif); err != nil {
			serverDone <- err
			return
		}

		// Send CONCLUSION response with DestinationSocketId = 0
		p.Header().IsControlPacket = true
		p.Header().ControlType = packet.CTRLTYPE_HANDSHAKE
		p.Header().SubType = 0
		p.Header().TypeSpecific = 0
		p.Header().Timestamp = 0
		p.Header().DestinationSocketId = 0
		conclusionResp := &packet.CIFHandshake{
			IsRequest:                   false,
			Version:                     5,
			EncryptionField:             0,
			ExtensionField:              1,
			InitialPacketSequenceNumber: recvcif.InitialPacketSequenceNumber,
			MaxTransmissionUnitSize:     recvcif.MaxTransmissionUnitSize,
			MaxFlowWindowSize:           recvcif.MaxFlowWindowSize,
			HandshakeType:               packet.HSTYPE_CONCLUSION,
			SRTSocketId:                 9876,
			SynCookie:                   0,
			HasHS:                       true,
			SRTHS: &packet.CIFHandshakeExtension{
				SRTVersion: SRT_VERSION,
				SRTFlags: packet.CIFHandshakeExtensionFlags{
					TSBPDSND:    true,
					TSBPDRCV:    true,
					CRYPT:       true,
					TLPKTDROP:   true,
					PERIODICNAK: true,
					REXMITFLG:   true,
				},
				RecvTSBPDDelay: uint16(DefaultConfig().ReceiverLatency.Milliseconds()),
				SendTSBPDDelay: uint16(DefaultConfig().PeerLatency.Milliseconds()),
			},
		}
		conclusionResp.PeerIP.FromNetAddr(ln.LocalAddr())
		p.MarshalCIF(conclusionResp)
		outbuf.Reset()
		if err = p.Marshal(&outbuf); err != nil {
			serverDone <- err
			return
		}
		ln.WriteTo(outbuf.Bytes(), p.Header().Addr)
		serverDone <- nil
	}()

	cfg := DefaultConfig()
	cfg.ConnectionTimeout = 3 * time.Second
	conn, err := Dial("srt", "127.0.0.1:6003", cfg)
	require.NoError(t, err)
	conn.Close()

	require.NoError(t, <-serverDone)
}

func TestDialV5MissingExtension(t *testing.T) {
	ln, err := net.ListenPacket("udp", "127.0.0.1:6003")
	require.NoError(t, err)
	defer ln.Close()

	go func() {
		// read induction request
		buf := make([]byte, MAX_MSS_SIZE)
		n, addr, err := ln.ReadFrom(buf)
		require.NoError(t, err)
		p, err := packet.NewPacketFromData(addr, buf[:n])
		require.NoError(t, err)
		recvcif := &packet.CIFHandshake{}
		err = p.UnmarshalCIF(recvcif)
		require.NoError(t, err)
		require.Equal(t, packet.HSTYPE_INDUCTION, recvcif.HandshakeType)

		// write induction response
		p.Header().IsControlPacket = true
		p.Header().ControlType = packet.CTRLTYPE_HANDSHAKE
		p.Header().SubType = 0
		p.Header().TypeSpecific = 0
		p.Header().Timestamp = 0
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
		sendcif.PeerIP.FromNetAddr(ln.LocalAddr())
		p.MarshalCIF(sendcif)
		var outbuf bytes.Buffer
		err = p.Marshal(&outbuf)
		require.NoError(t, err)
		ln.WriteTo(outbuf.Bytes(), p.Header().Addr)

		// read conclusion request
		n, addr, err = ln.ReadFrom(buf)
		require.NoError(t, err)
		p, err = packet.NewPacketFromData(addr, buf[:n])
		require.NoError(t, err)
		recvcif = &packet.CIFHandshake{}
		err = p.UnmarshalCIF(recvcif)
		require.NoError(t, err)
		require.Equal(t, packet.HSTYPE_CONCLUSION, recvcif.HandshakeType)

		// write invalid conclusion response
		p.Header().IsControlPacket = true
		p.Header().ControlType = packet.CTRLTYPE_HANDSHAKE
		p.Header().SubType = 0
		p.Header().TypeSpecific = 0
		p.Header().Timestamp = 0
		p.Header().DestinationSocketId = recvcif.SRTSocketId
		sendcif = recvcif
		sendcif.IsRequest = false
		sendcif.SRTSocketId = 9876
		sendcif.SynCookie = 0
		sendcif.PeerIP.FromNetAddr(ln.LocalAddr())
		sendcif.HasHS = false
		p.MarshalCIF(sendcif)
		outbuf.Reset()
		err = p.Marshal(&outbuf)
		require.NoError(t, err)
		ln.WriteTo(outbuf.Bytes(), p.Header().Addr)
	}()

	_, err = Dial("srt", "127.0.0.1:6003", DefaultConfig())
	require.EqualError(t, err, "missing handshake extension")
}
