package srt

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPktSentRecv(t *testing.T) {
	message := "Hello World!"
	channel := NewPubSub(PubSubConfig{})

	config := DefaultConfig()

	server := Server{
		Addr:   "127.0.0.1:6003",
		Config: &config,
		HandleConnect: func(req ConnRequest) ConnType {
			streamid := req.StreamId()

			switch streamid {
			case "publish":
				return PUBLISH
			case "subscribe":
				return SUBSCRIBE
			}

			return REJECT
		},
		HandlePublish: func(conn Conn) {
			channel.Publish(conn)

			conn.Close()
		},
		HandleSubscribe: func(conn Conn) {
			channel.Subscribe(conn)

			conn.Close()
		},
	}

	err := server.Listen()
	require.NoError(t, err)

	defer server.Shutdown()

	go func() {
		err := server.Serve()
		if err == ErrServerClosed {
			return
		}
		require.NoError(t, err)
	}()

	statsReader := Statistics{}
	statsWriter := Statistics{}

	readerConnected := make(chan struct{})
	readerDone := make(chan struct{})

	dataReader := bytes.Buffer{}

	go func() {
		defer close(readerDone)

		config := DefaultConfig()
		config.StreamId = "subscribe"

		conn, err := Dial("srt", "127.0.0.1:6003", config)
		if !assert.NoError(t, err) {
			panic(err.Error())
		}

		close(readerConnected)

		buffer := make([]byte, 2048)

		for {
			n, err := conn.Read(buffer)
			if n != 0 {
				dataReader.Write(buffer[:n])
			}

			if err != nil {
				break
			}
		}

		conn.Stats(&statsReader)

		err = conn.Close()
		require.NoError(t, err)
	}()

	<-readerConnected

	writerDone := make(chan struct{})

	go func() {
		defer close(writerDone)

		config := DefaultConfig()
		config.StreamId = "publish"

		conn, err := Dial("srt", "127.0.0.1:6003", config)
		if !assert.NoError(t, err) {
			panic(err.Error())
		}

		n, err := conn.Write([]byte(message))
		if !assert.NoError(t, err) {
			panic(err.Error())
		}
		assert.Equal(t, 12, n)

		time.Sleep(3 * time.Second)

		conn.Stats(&statsWriter)

		err = conn.Close()
		assert.NoError(t, err)
	}()

	<-writerDone
	<-readerDone

	reader := dataReader.String()

	require.Equal(t, message, reader)

	require.Equal(t, uint64(len(message)+44), statsReader.Accumulated.ByteRecv)
	require.Equal(t, uint64(1), statsReader.Accumulated.PktRecv)

	require.Equal(t, uint64(len(message)+44), statsWriter.Accumulated.ByteSent)
	require.Equal(t, uint64(1), statsWriter.Accumulated.PktSent)
}

func TestPktRecvLoss(t *testing.T) {
	message := "Hello World!"
	channel := NewPubSub(PubSubConfig{})

	config := DefaultConfig()

	statsReader := Statistics{}
	statsWriter := Statistics{}

	wg := sync.WaitGroup{}

	wg.Add(1)

	server := Server{
		Addr:   "127.0.0.1:6003",
		Config: &config,
		HandleConnect: func(req ConnRequest) ConnType {
			streamid := req.StreamId()

			switch streamid {
			case "publish":
				return PUBLISH
			case "subscribe":
				return SUBSCRIBE
			}

			return REJECT
		},
		HandlePublish: func(conn Conn) {
			defer wg.Done()

			channel.Publish(conn)

			conn.Stats(&statsReader)

			conn.Close()
		},
		HandleSubscribe: func(conn Conn) {
			channel.Subscribe(conn)

			conn.Close()
		},
	}

	err := server.Listen()
	require.NoError(t, err)

	defer server.Shutdown()

	go func() {
		err := server.Serve()
		if err == ErrServerClosed {
			return
		}
		require.NoError(t, err)
	}()

	wg.Add(1)

	go func() {
		defer wg.Done()

		config := DefaultConfig()
		config.StreamId = "publish"

		conn, err := Dial("srt", "127.0.0.1:6003", config)
		if !assert.NoError(t, err) {
			panic(err.Error())
		}

		n, err := conn.Write([]byte(message))
		if !assert.NoError(t, err) {
			panic(err.Error())
		}
		assert.Equal(t, 12, n)

		time.Sleep(3 * time.Second)

		conn.Stats(&statsWriter)

		err = conn.Close()
		assert.NoError(t, err)
	}()

	wg.Wait()

	require.Equal(t, uint64(len(message)+44), statsReader.Accumulated.ByteRecv)
	require.Equal(t, uint64(1), statsReader.Accumulated.PktRecv)

	require.Equal(t, uint64(len(message)+44), statsWriter.Accumulated.ByteSent)
	require.Equal(t, uint64(1), statsWriter.Accumulated.PktSent)
}
