package srt

import (
	"sync"
	"testing"

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
