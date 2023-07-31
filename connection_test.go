package srt

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryption(t *testing.T) {
	message := "Hello World!"
	passphrase := "foobarfoobar"
	channel := NewPubSub(PubSubConfig{})

	config := DefaultConfig()
	config.EnforcedEncryption = true

	server := Server{
		Addr:   "127.0.0.1:6003",
		Config: &config,
		HandleConnect: func(req ConnRequest) ConnType {
			if req.IsEncrypted() {
				if err := req.SetPassphrase(passphrase); err != nil {
					return REJECT
				}
			}

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

	defer server.Shutdown()

	go func() {
		if err := server.ListenAndServe(); err != nil {
			if err == ErrServerClosed {
				return
			}

			if !assert.NoError(t, err) {
				panic(err.Error())
			}
		}
	}()

	{
		// Reject connection if wrong password is set
		config := DefaultConfig()
		config.StreamId = "subscribe"
		config.Passphrase = "barfoobarfoo"

		_, err := Dial("srt", "127.0.0.1:6003", config)
		require.Error(t, err)
	}
	// Test transmitting an encrypted message

	readerConnected := make(chan struct{})
	readerDone := make(chan struct{})

	dataReader1 := bytes.Buffer{}

	go func() {
		defer close(readerDone)

		config := DefaultConfig()
		config.StreamId = "subscribe"
		config.Passphrase = "foobarfoobar"

		conn, err := Dial("srt", "127.0.0.1:6003", config)
		if !assert.NoError(t, err) {
			panic(err.Error())
		}

		close(readerConnected)

		buffer := make([]byte, 2048)

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

	<-readerConnected

	writerDone := make(chan struct{})

	go func() {
		defer close(writerDone)

		config := DefaultConfig()
		config.StreamId = "publish"
		config.Passphrase = "foobarfoobar"

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

		err = conn.Close()
		assert.NoError(t, err)
	}()

	<-writerDone
	<-readerDone

	reader1 := dataReader1.String()

	require.Equal(t, message, reader1)
}

func TestEncryptionKeySwap(t *testing.T) {
	message := "Hello World!"
	passphrase := "foobarfoobar"
	channel := NewPubSub(PubSubConfig{})

	config := DefaultConfig()
	config.EnforcedEncryption = true

	server := Server{
		Addr:   "127.0.0.1:6003",
		Config: &config,
		HandleConnect: func(req ConnRequest) ConnType {
			if req.IsEncrypted() {
				if err := req.SetPassphrase(passphrase); err != nil {
					return REJECT
				}
			}

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

	defer server.Shutdown()

	go func() {
		if err := server.ListenAndServe(); err != nil {
			if err == ErrServerClosed {
				return
			}

			if !assert.NoError(t, err) {
				panic(err.Error())
			}
		}
	}()

	// Test transmitting encrypted messages with key swap in between

	dataReader1 := bytes.Buffer{}

	readerConnected := make(chan struct{})
	readerDone := make(chan struct{})

	go func() {
		defer close(readerDone)

		config := DefaultConfig()
		config.StreamId = "subscribe"
		config.Passphrase = "foobarfoobar"

		conn, err := Dial("srt", "127.0.0.1:6003", config)
		if !assert.NoError(t, err) {
			panic(err.Error())
		}

		buffer := make([]byte, 2048)

		close(readerConnected)

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

	<-readerConnected

	writerDone := make(chan struct{})

	go func() {
		defer close(writerDone)

		config := DefaultConfig()
		config.StreamId = "publish"
		config.Passphrase = "foobarfoobar"
		// Swap encryption key after 50 sent messages
		config.KMPreAnnounce = 10
		config.KMRefreshRate = 30

		conn, err := Dial("srt", "127.0.0.1:6003", config)
		if !assert.NoError(t, err) {
			panic(err.Error())
		}

		// Send 150 messages
		for i := 0; i < 150; i++ {
			n, err := conn.Write([]byte(message))
			if !assert.NoError(t, err) {
				panic(err.Error())
			}
			assert.Equal(t, 12, n)
		}

		time.Sleep(3 * time.Second)

		err = conn.Close()
		assert.NoError(t, err)
	}()

	<-writerDone
	<-readerDone

	reader1 := dataReader1.String()

	require.Equal(t, strings.Repeat(message, 150), reader1)
}
