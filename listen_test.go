package srt

import (
	"sync"
	"testing"

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
