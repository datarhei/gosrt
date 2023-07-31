package srt

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPubSub(t *testing.T) {
	message := "Hello World!"
	channel := NewPubSub(PubSubConfig{})

	config := DefaultConfig()

	server := Server{
		Addr:   "127.0.0.1:6003",
		Config: &config,
		HandleConnect: func(req ConnRequest) ConnType {
			streamid := req.StreamId()

			if streamid == "publish" {
				return PUBLISH
			} else if streamid == "subscribe" {
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

	go func() {
		err := server.Serve()
		if err == ErrServerClosed {
			return
		}
		require.NoError(t, err)
	}()

	readerWg := sync.WaitGroup{}
	readerWg.Add(2)

	dataReader1 := bytes.Buffer{}
	dataReader2 := bytes.Buffer{}

	go func() {
		config := DefaultConfig()
		config.StreamId = "subscribe"

		conn, err := Dial("srt", "127.0.0.1:6003", config)
		if !assert.NoError(t, err) {
			panic(err.Error())
		}

		buffer := make([]byte, 2048)

		readerWg.Done()

		for {
			n, err := conn.Read(buffer)
			if n != 0 {
				dataReader1.Write(buffer[:n])
			}

			if err != nil {
				break
			}
		}

		err = conn.Close()
		require.NoError(t, err)
	}()

	go func() {
		config := DefaultConfig()
		config.StreamId = "subscribe"

		conn, err := Dial("srt", "127.0.0.1:6003", config)
		if !assert.NoError(t, err) {
			panic(err.Error())
		}

		buffer := make([]byte, 2048)

		readerWg.Done()

		for {
			n, err := conn.Read(buffer)
			if n != 0 {
				dataReader2.Write(buffer[:n])
			}

			if err != nil {
				break
			}
		}

		err = conn.Close()
		require.NoError(t, err)
	}()

	readerWg.Wait()

	writerWg := sync.WaitGroup{}
	writerWg.Add(1)

	go func() {
		config := DefaultConfig()
		config.StreamId = "publish"

		conn, err := Dial("srt", "127.0.0.1:6003", config)
		if !assert.NoError(t, err) {
			panic(err.Error())
		}

		n, err := conn.Write([]byte(message))
		require.NoError(t, err)
		require.Equal(t, 12, n)

		time.Sleep(3 * time.Second)

		err = conn.Close()
		require.NoError(t, err)

		writerWg.Done()
	}()

	writerWg.Wait()

	server.Shutdown()

	reader1 := dataReader1.String()
	reader2 := dataReader2.String()

	require.Equal(t, message, reader1)
	require.Equal(t, message, reader2)
}
