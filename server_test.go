package srt

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestServer(t *testing.T) {
	server := Server{
		Addr: "127.0.0.1:6003",
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

	config := DefaultConfig()
	config.StreamId = "publish"

	conn, err := Dial("srt", "127.0.0.1:6003", config)
	require.NoError(t, err)

	err = conn.Close()
	require.NoError(t, err)

	config = DefaultConfig()
	config.StreamId = "subscribe"

	conn, err = Dial("srt", "127.0.0.1:6003", config)
	require.NoError(t, err)

	err = conn.Close()
	require.NoError(t, err)

	config = DefaultConfig()
	config.StreamId = "nothing"

	_, err = Dial("srt", "127.0.0.1:6003", config)
	require.Error(t, err)
}
