package srt

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// These tests check FEC interoperability with libsrt, using srt-live-transmit. They are skipped if srt-live-transmit is not installed.
//
// The lossy proxy delays every packet by 100ms (RTT 200ms) and the latency is 120ms, so lost packets can't be recovered by retransmissions in time. Only FEC can recover them.

const interopChunkSize = 1316

func interopChunk(i int) []byte {
	chunk := make([]byte, interopChunkSize)
	binary.BigEndian.PutUint32(chunk[0:4], uint32(i))
	for j := 8; j < len(chunk); j++ {
		chunk[j] = byte(i*31 + j)
	}
	binary.BigEndian.PutUint32(chunk[4:8], crc32.ChecksumIEEE(chunk[8:]))
	return chunk
}

type interopResult struct {
	received  int
	corrupted int
	missing   []int
}

func checkInteropChunks(chunks [][]byte, sent int) interopResult {
	res := interopResult{}
	seen := map[int]bool{}

	for _, chunk := range chunks {
		if len(chunk) != interopChunkSize || binary.BigEndian.Uint32(chunk[4:8]) != crc32.ChecksumIEEE(chunk[8:]) {
			res.corrupted++
			continue
		}

		i := int(binary.BigEndian.Uint32(chunk[0:4]))
		if !bytes.Equal(chunk, interopChunk(i)) {
			res.corrupted++
			continue
		}

		seen[i] = true
		res.received++
	}

	for i := 0; i < sent; i++ {
		if !seen[i] {
			res.missing = append(res.missing, i)
		}
	}

	return res
}

func requireSrtLiveTransmit(t *testing.T) string {
	path, err := exec.LookPath("srt-live-transmit")
	if err != nil {
		t.Skip("srt-live-transmit not found")
	}
	return path
}

func runLibsrtPublisherToGoSRT(t *testing.T, filter string, proxyPort, listenPort int, n int) interopResult {
	slt := requireSrtLiveTransmit(t)

	proxy := &LossyProxy{
		delay:                100 * time.Millisecond,
		dropRate:             15,
		dropOriginalDataOnly: true,
	}
	err := proxy.Start(fmt.Sprintf("127.0.0.1:%d", proxyPort), fmt.Sprintf("127.0.0.1:%d", listenPort))
	require.NoError(t, err)
	defer proxy.Stop()

	config := DefaultConfig()
	config.Latency = 120 * time.Millisecond
	config.PacketFilter = filter

	ln, err := Listen("srt", fmt.Sprintf("127.0.0.1:%d", listenPort), config)
	require.NoError(t, err)
	defer ln.Close()

	var chunks [][]byte
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()

		conn, _, err := ln.Accept(func(req ConnRequest) ConnType { return PUBLISH })
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 2048)
		for {
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			chunks = append(chunks, bytes.Clone(buf[:n]))
		}
	}()

	url := fmt.Sprintf("srt://127.0.0.1:%d?latency=120", proxyPort)
	if len(filter) != 0 {
		url += "&packetfilter=" + filter
	}

	cmd := exec.Command(slt, "-q", fmt.Sprintf("-chunk:%d", interopChunkSize), "file://con", url)
	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	require.NoError(t, cmd.Start())

	// Give the handshake some time, it might need retries because of the packet loss
	time.Sleep(time.Second)

	for i := 0; i < n; i++ {
		_, err := stdin.Write(interopChunk(i))
		require.NoError(t, err)
		time.Sleep(2 * time.Millisecond)
	}

	time.Sleep(time.Second)
	stdin.Close()

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		cmd.Process.Kill()
		<-done
	}

	wg.Wait()

	t.Logf("srt-live-transmit: %s", stderr.String())

	return checkInteropChunks(chunks, n)
}

func runGoSRTToLibsrtSubscriber(t *testing.T, filter string, proxyPort, listenPort int, n int) interopResult {
	slt := requireSrtLiveTransmit(t)

	proxy := &LossyProxy{
		delay:                100 * time.Millisecond,
		dropRate:             15,
		dropOriginalDataOnly: true,
	}
	err := proxy.Start(fmt.Sprintf("127.0.0.1:%d", proxyPort), fmt.Sprintf("127.0.0.1:%d", listenPort))
	require.NoError(t, err)
	defer proxy.Stop()

	url := fmt.Sprintf("srt://127.0.0.1:%d?mode=listener&latency=120", listenPort)
	if len(filter) != 0 {
		url += "&packetfilter=" + filter
	}

	cmd := exec.Command(slt, "-q", fmt.Sprintf("-chunk:%d", interopChunkSize), url, "file://con")
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	require.NoError(t, cmd.Start())
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
		t.Logf("srt-live-transmit: %s", stderr.String())
	}()

	var output bytes.Buffer
	readDone := make(chan struct{})
	go func() {
		io.Copy(&output, stdout)
		close(readDone)
	}()

	config := DefaultConfig()
	config.Latency = 120 * time.Millisecond
	config.PacketFilter = filter

	var conn Conn
	for i := 0; i < 20; i++ {
		conn, err = Dial("srt", fmt.Sprintf("127.0.0.1:%d", proxyPort), config)
		if err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	require.NoError(t, err)

	for i := 0; i < n; i++ {
		_, err := conn.Write(interopChunk(i))
		require.NoError(t, err)
		time.Sleep(2 * time.Millisecond)
	}

	time.Sleep(2 * time.Second)
	conn.Close()

	// Stop it gracefully, such that it flushes its output
	cmd.Process.Signal(os.Interrupt)

	select {
	case <-readDone:
	case <-time.After(3 * time.Second):
		cmd.Process.Kill()
		<-readDone
	}

	data := output.Bytes()
	chunks := [][]byte{}
	for len(data) >= interopChunkSize {
		chunks = append(chunks, data[:interopChunkSize])
		data = data[interopChunkSize:]
	}
	if len(data) != 0 {
		chunks = append(chunks, data)
	}

	return checkInteropChunks(chunks, n)
}

func TestFECInteropLibsrtPublisher(t *testing.T) {
	n := 500

	// Without FEC, packets are lost. This proves that the test setup needs FEC.
	res := runLibsrtPublisherToGoSRT(t, "", 6301, 6302, n)
	t.Logf("without FEC: received %d/%d, corrupted %d, missing %d", res.received, n, res.corrupted, len(res.missing))
	require.NotEmpty(t, res.missing, "expected losses without FEC")

	res = runLibsrtPublisherToGoSRT(t, "fec,cols:10", 6303, 6304, n)
	t.Logf("with FEC: received %d/%d, corrupted %d, missing %v", res.received, n, res.corrupted, res.missing)
	require.Equal(t, 0, res.corrupted)
	require.Empty(t, res.missing)
}

func TestFECInteropLibsrtSubscriber(t *testing.T) {
	n := 500

	res := runGoSRTToLibsrtSubscriber(t, "", 6311, 6312, n)
	t.Logf("without FEC: received %d/%d, corrupted %d, missing %d", res.received, n, res.corrupted, len(res.missing))
	require.NotEmpty(t, res.missing, "expected losses without FEC")

	res = runGoSRTToLibsrtSubscriber(t, "fec,cols:10", 6313, 6314, n)
	t.Logf("with FEC: received %d/%d, corrupted %d, missing %v", res.received, n, res.corrupted, res.missing)
	require.Equal(t, 0, res.corrupted)
	require.Empty(t, res.missing)
}
