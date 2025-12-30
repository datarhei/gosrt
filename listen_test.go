package srt

import (
	"bytes"
	"context"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/datarhei/gosrt/circular"
	"github.com/datarhei/gosrt/packet"

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

			p, err := packet.NewPacketFromData(addr, buffer[:n])
			require.NoError(t, err)

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

			p, err := packet.NewPacketFromData(addr, buffer[:n])
			require.NoError(t, err)

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

func TestListenAsync(t *testing.T) {
	const parallelCount = 2
	ln, err := Listen("srt", "127.0.0.1:6003", DefaultConfig())
	require.NoError(t, err)
	var (
		// All streams are pending
		pendingWg  sync.WaitGroup
		pendingSet sync.Map // Set of which streams are pending
		// All streams are connected
		connectedWg sync.WaitGroup
		// All listener goroutines are stopped
		listenerWg sync.WaitGroup
	)
	listenerWg.Add(parallelCount)
	pendingWg.Add(parallelCount)
	connectedWg.Add(parallelCount)
	for i := 0; i < parallelCount; i++ {
		go func() {
			defer listenerWg.Done()
			for {
				_, _, err := ln.Accept(func(req ConnRequest) ConnType {
					// Only call Done() if we're the first request for this stream
					if _, ok := pendingSet.Swap(req.StreamId(), struct{}{}); !ok {
						pendingWg.Done()
					}
					// Wait for all streams to be pending Before returning
					pendingWg.Wait()
					return PUBLISH
				})
				if err == ErrListenerClosed {
					return
				}
				require.NoError(t, err)
			}
		}()

		go func(streamId string) {
			config := DefaultConfig()
			config.StreamId = streamId
			conn, err := Dial("srt", "127.0.0.1:6003", config)
			require.NoError(t, err)
			connectedWg.Done()
			conn.Close()
		}(strconv.Itoa(i))
	}

	// Wait for all streams to be connected
	connectedWg.Wait()
	ln.Close()
	listenerWg.Wait()
}

func TestListenHSV5MissingExtension(t *testing.T) {
	ln, err := Listen("srt", "127.0.0.1:6003", DefaultConfig())
	require.NoError(t, err)

	listenDone := make(chan struct{})
	defer func() { <-listenDone }()

	go func() {
		defer close(listenDone)
		for {
			_, _, err := ln.Accept(func(req ConnRequest) ConnType {
				return SUBSCRIBE
			})
			if err != nil {
				break
			}
		}
	}()

	conn, err := net.Dial("udp", "127.0.0.1:6003")
	require.NoError(t, err)
	defer conn.Close()

	// send induction request
	p := packet.NewPacket(conn.RemoteAddr())
	p.Header().IsControlPacket = true
	p.Header().ControlType = packet.CTRLTYPE_HANDSHAKE
	p.Header().SubType = 0
	p.Header().TypeSpecific = 0
	p.Header().Timestamp = 0
	p.Header().DestinationSocketId = 0
	sendcif := &packet.CIFHandshake{
		IsRequest:                   true,
		Version:                     4,
		EncryptionField:             0,
		ExtensionField:              2,
		InitialPacketSequenceNumber: circular.New(10000, packet.MAX_SEQUENCENUMBER),
		MaxTransmissionUnitSize:     MAX_MSS_SIZE,
		MaxFlowWindowSize:           25600,
		HandshakeType:               packet.HSTYPE_INDUCTION,
		SRTSocketId:                 55555,
		SynCookie:                   0,
	}
	sendcif.PeerIP.FromNetAddr(conn.LocalAddr())
	p.MarshalCIF(sendcif)
	var buf bytes.Buffer
	err = p.Marshal(&buf)
	require.NoError(t, err)
	_, err = conn.Write(buf.Bytes())
	require.NoError(t, err)

	// read induction response
	inbuf := make([]byte, MAX_MSS_SIZE)
	n, err := conn.Read(inbuf)
	require.NoError(t, err)
	p, err = packet.NewPacketFromData(conn.RemoteAddr(), inbuf[:n])
	require.NoError(t, err)
	recvcif := &packet.CIFHandshake{}
	err = p.UnmarshalCIF(recvcif)
	require.NoError(t, err)

	// send conclusion
	p.Header().IsControlPacket = true
	p.Header().ControlType = packet.CTRLTYPE_HANDSHAKE
	p.Header().SubType = 0
	p.Header().TypeSpecific = 0
	p.Header().Timestamp = 0
	p.Header().DestinationSocketId = 0 // recvcif.SRTSocketId
	sendcif.Version = 5
	sendcif.ExtensionField = recvcif.ExtensionField
	sendcif.HandshakeType = packet.HSTYPE_CONCLUSION
	sendcif.SynCookie = recvcif.SynCookie
	sendcif.HasSID = true
	sendcif.StreamId = "foobar"
	p.MarshalCIF(sendcif)
	buf.Reset()
	err = p.Marshal(&buf)
	require.NoError(t, err)
	_, err = conn.Write(buf.Bytes())
	require.NoError(t, err)

	// read error
	n, err = conn.Read(inbuf)
	require.NoError(t, err)
	p, err = packet.NewPacketFromData(conn.RemoteAddr(), inbuf[:n])
	require.NoError(t, err)
	recvcif = &packet.CIFHandshake{}
	err = p.UnmarshalCIF(recvcif)
	require.NoError(t, err)
	require.Equal(t, recvcif.HandshakeType, packet.HandshakeType(REJ_ROGUE))

	ln.Close()
}

func TestListenParallelRequests(t *testing.T) {
	ln, err := Listen("srt", "127.0.0.1:6003", DefaultConfig())
	require.NoError(t, err)

	listenDone := make(chan struct{})
	defer func() { <-listenDone }()

	var reqReady sync.WaitGroup
	reqReady.Add(4)

	var serverSideConnReady sync.WaitGroup
	serverSideConnReady.Add(4)

	go func() {
		defer close(listenDone)

		for {
			req, err := ln.Accept2()
			if err != nil {
				break
			}

			reqReady.Done()

			go func() {
				defer serverSideConnReady.Done()

				// wait for all requests to be pending
				reqReady.Wait()

				conn, err := req.Accept()
				require.NoError(t, err)
				conn.Close()
			}()
		}
	}()

	var clientSideConnReady sync.WaitGroup

	for i := 0; i < 4; i++ {
		clientSideConnReady.Add(1)

		go func() {
			defer clientSideConnReady.Done()

			config := DefaultConfig()
			config.StreamId = "foobar"

			conn, err := Dial("srt", "127.0.0.1:6003", config)
			require.NoError(t, err)

			err = conn.Close()
			require.NoError(t, err)
		}()
	}

	serverSideConnReady.Wait()
	clientSideConnReady.Wait()

	ln.Close()
}

func TestListenDiscardRepeatedHandshakes(t *testing.T) {
	ln, err := Listen("srt", "127.0.0.1:6003", DefaultConfig())
	require.NoError(t, err)

	singleReqReceived := make(chan struct{})

	listenDone := make(chan struct{})
	defer func() { <-listenDone }()

	defer ln.Close()

	go func() {
		defer close(listenDone)

		for {
			req, err := ln.Accept2()
			if err != nil {
				break
			}

			close(singleReqReceived)
			defer req.Reject(REJ_CLOSE)
		}
	}()

	for i := 0; i < 4; i++ {
		conn, err := net.Dial("udp", "127.0.0.1:6003")
		require.NoError(t, err)
		defer conn.Close()

		// send induction request
		p := packet.NewPacket(conn.RemoteAddr())
		p.Header().IsControlPacket = true
		p.Header().ControlType = packet.CTRLTYPE_HANDSHAKE
		p.Header().SubType = 0
		p.Header().TypeSpecific = 0
		p.Header().Timestamp = 0
		p.Header().DestinationSocketId = 0
		sendcif := &packet.CIFHandshake{
			IsRequest:                   true,
			Version:                     4,
			EncryptionField:             0,
			ExtensionField:              2,
			InitialPacketSequenceNumber: circular.New(10000, packet.MAX_SEQUENCENUMBER),
			MaxTransmissionUnitSize:     MAX_MSS_SIZE,
			MaxFlowWindowSize:           25600,
			HandshakeType:               packet.HSTYPE_INDUCTION,
			SRTSocketId:                 55555,
			SynCookie:                   0,
		}
		sendcif.PeerIP.FromNetAddr(conn.LocalAddr())
		p.MarshalCIF(sendcif)
		var buf bytes.Buffer
		err = p.Marshal(&buf)
		require.NoError(t, err)
		_, err = conn.Write(buf.Bytes())
		require.NoError(t, err)

		// read induction response
		inbuf := make([]byte, 1024)
		n, err := conn.Read(inbuf)
		require.NoError(t, err)
		p, err = packet.NewPacketFromData(conn.RemoteAddr(), inbuf[:n])
		require.NoError(t, err)
		recvcif := &packet.CIFHandshake{}
		err = p.UnmarshalCIF(recvcif)
		require.NoError(t, err)

		// send conclusion
		p.Header().IsControlPacket = true
		p.Header().ControlType = packet.CTRLTYPE_HANDSHAKE
		p.Header().SubType = 0
		p.Header().TypeSpecific = 0
		p.Header().Timestamp = 0
		p.Header().DestinationSocketId = 0 // recvcif.SRTSocketId
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
		buf.Reset()
		err = p.Marshal(&buf)
		require.NoError(t, err)
		_, err = conn.Write(buf.Bytes())
		require.NoError(t, err)
	}

	<-singleReqReceived
}

func TestListenAcceptAndDiscardRepeatedHandshakes(t *testing.T) {
	ln, err := Listen("srt", "127.0.0.1:6003", DefaultConfig())
	require.NoError(t, err)

	singleReqAccepted := make(chan struct{})

	listenDone := make(chan struct{})
	defer func() { <-listenDone }()

	defer ln.Close()

	go func() {
		defer close(listenDone)

		for {
			req, err := ln.Accept2()
			if err != nil {
				break
			}

			conn, err := req.Accept()
			require.NoError(t, err)
			defer conn.Close()

			close(singleReqAccepted)
		}
	}()

	conn, err := net.Dial("udp", "127.0.0.1:6003")
	require.NoError(t, err)
	defer conn.Close()

	// write induction request
	p := packet.NewPacket(conn.RemoteAddr())
	p.Header().IsControlPacket = true
	p.Header().ControlType = packet.CTRLTYPE_HANDSHAKE
	p.Header().SubType = 0
	p.Header().TypeSpecific = 0
	p.Header().Timestamp = 0
	p.Header().DestinationSocketId = 0
	sendcif := &packet.CIFHandshake{
		IsRequest:                   true,
		Version:                     4,
		EncryptionField:             0,
		ExtensionField:              2,
		InitialPacketSequenceNumber: circular.New(10000, packet.MAX_SEQUENCENUMBER),
		MaxTransmissionUnitSize:     MAX_MSS_SIZE,
		MaxFlowWindowSize:           25600,
		HandshakeType:               packet.HSTYPE_INDUCTION,
		SRTSocketId:                 55555,
		SynCookie:                   0,
	}
	sendcif.PeerIP.FromNetAddr(conn.LocalAddr())
	p.MarshalCIF(sendcif)
	var buf bytes.Buffer
	err = p.Marshal(&buf)
	require.NoError(t, err)
	_, err = conn.Write(buf.Bytes())
	require.NoError(t, err)

	// read induction response
	inbuf := make([]byte, MAX_MSS_SIZE)
	n, err := conn.Read(inbuf)
	require.NoError(t, err)
	p, err = packet.NewPacketFromData(conn.RemoteAddr(), inbuf[:n])
	require.NoError(t, err)
	recvcif := &packet.CIFHandshake{}
	err = p.UnmarshalCIF(recvcif)
	require.NoError(t, err)

	// write conclusion request
	p.Header().IsControlPacket = true
	p.Header().ControlType = packet.CTRLTYPE_HANDSHAKE
	p.Header().SubType = 0
	p.Header().TypeSpecific = 0
	p.Header().Timestamp = 0
	p.Header().DestinationSocketId = 0
	sendcif.Version = 5
	sendcif.ExtensionField = recvcif.ExtensionField
	sendcif.HandshakeType = packet.HSTYPE_CONCLUSION
	sendcif.SRTSocketId = 234425644
	sendcif.SynCookie = recvcif.SynCookie
	sendcif.HasHS = true
	sendcif.SRTHS = &packet.CIFHandshakeExtension{
		SRTVersion: SRT_VERSION,
		SRTFlags: packet.CIFHandshakeExtensionFlags{
			TSBPDSND:      true,
			TSBPDRCV:      true,
			CRYPT:         true,
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
	buf.Reset()
	err = p.Marshal(&buf)
	require.NoError(t, err)
	_, err = conn.Write(buf.Bytes())
	require.NoError(t, err)

	// read conclusion response
	n, err = conn.Read(inbuf)
	require.NoError(t, err)
	p, err = packet.NewPacketFromData(conn.RemoteAddr(), inbuf[:n])
	require.NoError(t, err)
	recvcif = &packet.CIFHandshake{}
	err = p.UnmarshalCIF(recvcif)
	require.NoError(t, err)
	require.Equal(t, packet.HSTYPE_CONCLUSION, recvcif.HandshakeType)
	require.False(t, recvcif.IsRequest)

	<-singleReqAccepted

	// write conclusion request, again
	_, err = conn.Write(buf.Bytes())
	require.NoError(t, err)

	// wait some time to make sure that close(singleReqAccepted) is not triggered
	time.Sleep(500 * time.Millisecond)
}
