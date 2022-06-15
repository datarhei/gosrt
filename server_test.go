package srt

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestServer(t *testing.T) {
	server := Server{
		Addr: "127.0.0.1:6006",
		HandleConnect: func(req ConnRequest) ConnType {
			streamid := req.StreamId()

			if streamid == "publish" {
				return PUBLISH
			} else if streamid == "subscribe" {
				return SUBSCRIBE
			}

			return REJECT
		},
	}

	serverWg := sync.WaitGroup{}
	serverWg.Add(1)

	go func(s *Server) {
		serverWg.Done()
		if err := s.ListenAndServe(); err != nil {
			if err == ErrServerClosed {
				return
			}

			require.NoError(t, err)
		}
	}(&server)

	serverWg.Wait()

	config := DefaultConfig()
	config.StreamId = "publish"

	conn, err := Dial("srt", "127.0.0.1:6006", config)
	require.NoError(t, err)

	err = conn.Close()
	require.NoError(t, err)

	config = DefaultConfig()
	config.StreamId = "subscribe"

	conn, err = Dial("srt", "127.0.0.1:6006", config)
	require.NoError(t, err)

	err = conn.Close()
	require.NoError(t, err)

	config = DefaultConfig()
	config.StreamId = "nothing"

	_, err = Dial("srt", "127.0.0.1:6006", config)
	require.Error(t, err)

	server.Shutdown()
}
