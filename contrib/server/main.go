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

	srt "github.com/datarhei/gosrt"
	"github.com/pkg/profile"
)

// server is an implementation of the Server framework
type server struct {
	// Configuration parameter taken from the Config
	addr       string
	app        string
	token      string
	passphrase string
	logtopics  string
	profile    bool

	server *srt.Server

	// Map of publishing channels and a lock to serialize
	// access to the map.
	channels map[string]srt.PubSub
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
		channels: make(map[string]srt.PubSub),
	}

	flag.StringVar(&s.addr, "addr", "", "address to listen on")
	flag.StringVar(&s.app, "app", "", "path prefix for streamid")
	flag.StringVar(&s.token, "token", "", "token query param for streamid")
	flag.StringVar(&s.passphrase, "passphrase", "", "passphrase for de- and enrcypting the data")
	flag.StringVar(&s.logtopics, "logtopics", "", "topics for the log output")
	flag.BoolVar(&s.profile, "profile", false, "enable profiling")

	flag.Parse()

	if len(s.addr) == 0 {
		fmt.Fprintf(os.Stderr, "Provide a listen address with -addr\n")
		os.Exit(1)
	}

	if s.profile {
		defer profile.Start(profile.NoShutdownHook).Stop()
	}

	config := srt.DefaultConfig

	if len(s.logtopics) != 0 {
		config.Logger = srt.NewLogger(strings.Split(s.logtopics, ","))
	}

	config.KMPreAnnounce = 200
	config.KMRefreshRate = 10000

	s.server = &srt.Server{
		Addr:            s.addr,
		HandleConnect:   s.handleConnect,
		HandlePublish:   s.handlePublish,
		HandleSubscribe: s.handleSubscribe,
		Config:          &config,
	}

	fmt.Fprintf(os.Stderr, "Listening on %s\n", s.addr)

	go func() {
		if config.Logger == nil {
			return
		}

		for m := range config.Logger.Listen() {
			fmt.Fprintf(os.Stderr, "%#08x %s (in %s:%d)\n%s \n", m.SocketId, m.Topic, m.File, m.Line, m.Message)
		}
	}()

	go func() {
		if err := s.ListenAndServe(); err != nil && err != srt.ErrListenerClosed {
			fmt.Fprintf(os.Stderr, "SRT Server: %s\n", err)
			os.Exit(2)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit

	s.Shutdown()

	if config.Logger != nil {
		config.Logger.Close()
	}
}

func (s *server) log(who, action, path, message string, client net.Addr) {
	fmt.Fprintf(os.Stderr, "%-10s %10s %s (%s) %s\n", who, action, path, client, message)
}

func (s *server) handleConnect(req srt.ConnRequest) srt.ConnType {
	var mode srt.ConnType = srt.SUBSCRIBE
	client := req.RemoteAddr()
	streamId := req.StreamId()
	path := streamId

	if strings.HasPrefix(streamId, "publish:") {
		mode = srt.PUBLISH
		path = strings.TrimPrefix(streamId, "publish:")
	} else if strings.HasPrefix(streamId, "subscribe:") {
		path = strings.TrimPrefix(streamId, "subscribe:")
	}

	u, err := url.Parse(path)
	if err != nil {
		return srt.REJECT
	}

	if req.IsEncrypted() {
		if err := req.SetPassphrase(s.passphrase); err != nil {
			s.log("CONNECT", "FORBIDDEN", u.Path, err.Error(), client)
			return srt.REJECT
		}
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
		pubsub = srt.NewPubSub(srt.PubSubConfig{
			Logger: s.server.Config.Logger,
		})
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

	fmt.Fprintf(os.Stderr, "%+v\n", conn.Stats())

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

	fmt.Fprintf(os.Stderr, "%+v\n", conn.Stats())

	conn.Close()
}
