package main

import (
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"

	"github.com/datarhei/gosrt"
)

// server is an implementation of the Server interface
type server struct {
	// Configuration parameter taken from the Config
	addr  string
	app   string
	token string

	server *srt.Server

	// Map of publishing channels and a lock to serialize
	// access to the map.
	channels map[string]*srt.PubSub
	lock     sync.RWMutex
}

func (s *server) ListenAndServe() error {
	if len(s.app) == 0 {
		s.app = "/"
	}

	return s.server.ListenAndServe()
}

func (s *server) Shutdown() {
	s.server.Shutdown()
}

func main() {
	s := server{
		channels: make(map[string]*srt.PubSub),
	}

	flag.StringVar(&s.addr, "addr", "", "Address to listen on")
	flag.StringVar(&s.app, "app", "", "write cpu profile to `file`")
	flag.StringVar(&s.token, "token", "", "write memory profile to `file`")

	flag.Parse()

	s.server = &srt.Server{
		Addr:            s.addr,
		HandleConnect:   s.handleConnect,
		HandlePublish:   s.handlePublish,
		HandleSubscribe: s.handleSubscribe,
		Debug:           false,
	}

	fmt.Fprintf(os.Stderr, "Listening on %s\n", s.addr)

	go func() {
		if err := s.ListenAndServe(); err != nil && err != srt.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "SRT Server: %s\n", err)
			os.Exit(2)
		}
	}()

	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt)
	<-quit

	s.Shutdown()

	return
}

func (s *server) log(who, action, path, message string, client net.Addr) {
	fmt.Fprintf(os.Stderr, "%-10s %10s %s (%s) %s\n", who, action, path, client, message)
}

func (s *server) handleConnect(client net.Addr, streamId string) srt.ConnType {
	var mode srt.ConnType = srt.SUBSCRIBE
	path := streamId

	if strings.HasPrefix(streamId, "publish:") == true {
		mode = srt.PUBLISH
		path = strings.TrimPrefix(streamId, "publish:")
	} else if strings.HasPrefix(streamId, "subscribe:") == true {
		path = strings.TrimPrefix(streamId, "subscribe:")
	}

	u, err := url.Parse(path)
	if err != nil {
		return srt.REJECT
	}

	// Check the token
	token := u.Query().Get("token")
	if len(s.token) != 0 && s.token != token {
		s.log("CONNECT", "FORBIDDEN", u.Path, "invalid token ("+token+")", client)
		return srt.REJECT
	}

	// Check the app patch
	if !strings.HasPrefix(u.Path, s.app) {
		s.log("CONNECT", "FORBIDDEN", u.Path, "invalid app", client)
		return srt.REJECT
	}

	if len(strings.TrimPrefix(u.Path, s.app)) == 0 {
		s.log("CONNECT", "INVALID", u.Path, "stream name not provided", client)
		return srt.REJECT
	}

	s.lock.RLock()
	pubsub := s.channels[u.Path]
	s.lock.RUnlock()

	if mode == srt.PUBLISH && pubsub != nil {
		s.log("CONNECT", "CONFLICT", u.Path, "already publishing", client)
		return srt.REJECT
	}

	if mode == srt.SUBSCRIBE && pubsub == nil {
		s.log("CONNECT", "NOTFOUND", u.Path, "", client)
		return srt.REJECT
	}

	return mode
}

func (s *server) handlePublish(conn srt.Conn) {
	streamId := conn.StreamId()
	client := conn.RemoteAddr()
	path := strings.TrimPrefix(streamId, "publish:")
	u, _ := url.Parse(path)

	// Look for the stream
	s.lock.Lock()
	pubsub := s.channels[u.Path]
	if pubsub == nil {
		pubsub = srt.NewPubSub()
		s.channels[u.Path] = pubsub
	} else {
		pubsub = nil
	}
	s.lock.Unlock()

	if pubsub == nil {
		s.log("PUBLISH", "CONFLICT", u.Path, "already publishing", client)
		conn.Close()
		return
	}

	s.log("PUBLISH", "START", u.Path, "", client)

	pubsub.Publish(conn)

	s.lock.Lock()
	delete(s.channels, u.Path)
	s.lock.Unlock()

	s.log("PUBLISH", "STOP", u.Path, "", client)

	conn.Close()
}

func (s *server) handleSubscribe(conn srt.Conn) {
	streamId := conn.StreamId()
	client := conn.RemoteAddr()
	path := strings.TrimPrefix(streamId, "subscribe:")
	u, _ := url.Parse(path)

	s.log("SUBSCRIBE", "START", u.Path, "", client)

	// Look for the stream
	s.lock.RLock()
	pubsub := s.channels[u.Path]
	s.lock.RUnlock()

	if pubsub == nil {
		s.log("SUBSCRIBE", "NOTFOUND", u.Path, "", client)
		conn.Close()
		return
	}

	pubsub.Subscribe(conn)

	s.log("SUBSCRIBE", "STOP", u.Path, "", client)

	conn.Close()
}
