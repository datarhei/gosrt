package srt

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// LossyProxy simulates a network with packet loss and delay.
type LossyProxy struct {
	mu         sync.RWMutex
	clientAddr *net.UDPAddr
	serverAddr *net.UDPAddr
	conn       *net.UDPConn
	delay      time.Duration
	dropRate   int // 1 in N packets dropped
	pktCount   int
}

func (p *LossyProxy) Start(listenAddr string, forwardAddr string) error {
	serverUdpAddr, err := net.ResolveUDPAddr("udp", forwardAddr)
	if err != nil {
		return err
	}
	p.serverAddr = serverUdpAddr

	listenUdpAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return err
	}
	
	p.conn, err = net.ListenUDP("udp", listenUdpAddr)
	if err != nil {
		return err
	}

	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := p.conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			
			packetCopy := make([]byte, n)
			copy(packetCopy, buf[:n])

			p.pktCount++
			if p.dropRate > 0 && p.pktCount%p.dropRate == 0 {
				// Drop packet
				continue
			}

			// Add delay
			go func(data []byte, fromAddr *net.UDPAddr) {
				time.Sleep(p.delay)
				if fromAddr.String() == p.serverAddr.String() {
					// from server, forward to client
					p.mu.RLock()
					clientAddr := p.clientAddr
					p.mu.RUnlock()
					if clientAddr != nil {
						p.conn.WriteToUDP(data, clientAddr)
					}
				} else {
					// from client, forward to server
					p.mu.Lock()
					p.clientAddr = fromAddr
					p.mu.Unlock()
					p.conn.WriteToUDP(data, p.serverAddr)
				}
			}(packetCopy, addr)
		}
	}()

	return nil
}

func (p *LossyProxy) Stop() {
	if p.conn != nil {
		p.conn.Close()
	}
}

func TestFEC_Benefit_WithoutFECDropsPackets(t *testing.T) {
	// Start lossy proxy
	proxy := &LossyProxy{
		delay:    100 * time.Millisecond,
		dropRate: 15, // ~6.6% packet loss
	}
	err := proxy.Start("127.0.0.1:6005", "127.0.0.1:6006")
	require.NoError(t, err)
	defer proxy.Stop()

	// Server config
	serverConfig := DefaultConfig()
	// Set low latency so that ARQ cannot recover the packets in time (RTT = 200ms)
	serverConfig.Latency = 120 * time.Millisecond 

	ln, err := Listen("srt", "127.0.0.1:6006", serverConfig)
	require.NoError(t, err)
	defer ln.Close()

	var wg sync.WaitGroup
	wg.Add(1)

	var serverStats *Statistics

	go func() {
		defer wg.Done()
		conn, _, err := ln.Accept(func(req ConnRequest) ConnType {
			return SUBSCRIBE
		})
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 1024)
		for {
			_, err := conn.Read(buf)
			if err != nil {
				break
			}
		}
		
		var stats Statistics
		conn.Stats(&stats)
		serverStats = &stats
	}()

	// Client config
	clientConfig := DefaultConfig()
	clientConfig.Latency = 120 * time.Millisecond

	// Dial proxy
	conn, err := Dial("srt", "127.0.0.1:6005", clientConfig)
	require.NoError(t, err)

	// Send 100 packets
	for i := 0; i < 100; i++ {
		payload := bytes.Repeat([]byte{byte(i)}, 1000)
		_, err := conn.Write(payload)
		require.NoError(t, err)
		time.Sleep(5 * time.Millisecond) // send rate
	}

	time.Sleep(1 * time.Second) // wait to clear
	conn.Close()

	wg.Wait()

	require.NotNil(t, serverStats)

	fmt.Printf("\n--- Without FEC (Current Flow) ---\n")
	fmt.Printf("Packets Received: %d\n", serverStats.Accumulated.PktRecv)
	fmt.Printf("Packets Dropped at Receiver (Too Late): %d\n", serverStats.Accumulated.PktRecvDrop)
	fmt.Printf("Packets Lost at Receiver: %d\n", serverStats.Accumulated.PktRecvLoss)
	fmt.Printf("----------------------------------\n\n")

	// If RTT (200ms) > Latency (120ms), dropped packets will be too late for ARQ.
	// Therefore, PktRecvDrop MUST be greater than 0 without FEC.
	require.Greater(t, serverStats.Accumulated.PktRecvDrop, uint64(0), "Expected receiver to drop packets due to ARQ being too slow. This proves FEC is needed.")
}

func TestFEC_Benefit_WithFECReconstructsPackets(t *testing.T) {
	// Start lossy proxy
	proxy := &LossyProxy{
		delay:    100 * time.Millisecond,
		dropRate: 15, // ~6.6% packet loss
	}
	err := proxy.Start("127.0.0.1:6007", "127.0.0.1:6008")
	require.NoError(t, err)
	defer proxy.Stop()

	// Server config
	serverConfig := DefaultConfig()
	serverConfig.Latency = 120 * time.Millisecond 
	serverConfig.PacketFilter = "fec,cols:10,rows:1,layout:even"

	ln, err := Listen("srt", "127.0.0.1:6008", serverConfig)
	require.NoError(t, err)
	defer ln.Close()

	var wg sync.WaitGroup
	wg.Add(1)

	var serverStats *Statistics

	go func() {
		defer wg.Done()
		conn, _, err := ln.Accept(func(req ConnRequest) ConnType {
			return SUBSCRIBE
		})
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 2000)
		receivedCount := 0
		for {
			n, err := conn.Read(buf)
			if err != nil {
				break
			}
			if n > 0 {
				receivedCount++
			}
		}
		
		var stats Statistics
		conn.Stats(&stats)
		serverStats = &stats

		fmt.Printf("Application Received Packets: %d\n", receivedCount)
		require.Equal(t, 100, receivedCount, "Expected application to receive all 100 packets because of FEC")
	}()

	// Client config
	clientConfig := DefaultConfig()
	clientConfig.Latency = 120 * time.Millisecond
	clientConfig.PacketFilter = "fec,cols:10,rows:1,layout:even"

	// Dial proxy
	conn, err := Dial("srt", "127.0.0.1:6007", clientConfig)
	require.NoError(t, err)

	// Send 100 packets
	for i := 0; i < 100; i++ {
		payload := bytes.Repeat([]byte{byte(i)}, 1000)
		_, err := conn.Write(payload)
		require.NoError(t, err)
		time.Sleep(5 * time.Millisecond) // send rate
	}

	time.Sleep(1 * time.Second) // wait to clear
	conn.Close()

	wg.Wait()

	require.NotNil(t, serverStats)

	fmt.Printf("\n--- With FEC (New Flow) ---\n")
	fmt.Printf("Packets Received: %d\n", serverStats.Accumulated.PktRecv)
	fmt.Printf("Packets Dropped at Receiver (Too Late): %d\n", serverStats.Accumulated.PktRecvDrop)
	fmt.Printf("Packets Received at Network: %d\n", serverStats.Accumulated.PktRecv)
	fmt.Printf("Packets Dropped at Receiver (Network ARQ Late): %d\n", serverStats.Accumulated.PktRecvDrop)
	fmt.Printf("Packets Lost at Receiver (Network Gaps): %d\n", serverStats.Accumulated.PktRecvLoss)
	fmt.Printf("----------------------------------\n\n")

	// Note: We don't check serverStats.Accumulated.PktRecvDrop == 0 anymore, 
	// because ARQ will still retransmit late packets and they will be counted as dropped.
	// The true verification is the require.Equal(t, 100, receivedCount) in the reader goroutine!
}

