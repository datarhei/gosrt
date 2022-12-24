package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"time"

	srt "github.com/datarhei/gosrt"
)

type stats struct {
	bprev  uint64
	btotal uint64
	prev   uint64
	total  uint64

	lock sync.Mutex

	period time.Duration
	last   time.Time
}

func (s *stats) init(period time.Duration) {
	s.bprev = 0
	s.btotal = 0
	s.prev = 0
	s.total = 0

	s.period = period
	s.last = time.Now()

	go s.tick()
}

func (s *stats) tick() {
	ticker := time.NewTicker(s.period)
	defer ticker.Stop()

	for c := range ticker.C {
		s.lock.Lock()
		diff := c.Sub(s.last)

		bavg := float64(s.btotal-s.bprev) * 8 / (1000 * 1000 * diff.Seconds())
		avg := float64(s.total-s.prev) / diff.Seconds()

		s.bprev = s.btotal
		s.prev = s.total
		s.last = c

		s.lock.Unlock()

		fmt.Fprintf(os.Stderr, "\r%-54s: %8.3f kpackets (%8.3f packets/s), %8.3f mbytes (%8.3f Mbps)", c, float64(s.total)/1024, avg, float64(s.btotal)/1024/1024, bavg)
	}
}

func (s *stats) update(n uint64) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.btotal += n
	s.total++
}

func main() {
	var from string
	var to string
	var logtopics string

	flag.StringVar(&from, "from", "", "Address to read from, sources: srt://, udp://, - (stdin)")
	flag.StringVar(&to, "to", "", "Address to write to, targets: srt://, udp://, file://, - (stdout)")
	flag.StringVar(&logtopics, "logtopics", "", "topics for the log output")

	flag.Parse()

	var logger srt.Logger

	if len(logtopics) != 0 {
		logger = srt.NewLogger(strings.Split(logtopics, ","))
	}

	go func() {
		if logger == nil {
			return
		}

		for m := range logger.Listen() {
			fmt.Fprintf(os.Stderr, "%#08x %s (in %s:%d)\n%s \n", m.SocketId, m.Topic, m.File, m.Line, m.Message)
		}
	}()

	r, err := openReader(from, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: from: %v\n", err)
		flag.PrintDefaults()
		os.Exit(1)
	}

	w, err := openWriter(to, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: to: %v\n", err)
		flag.PrintDefaults()
		os.Exit(1)
	}

	doneChan := make(chan error)

	go func() {
		buffer := make([]byte, 2048)

		s := stats{}
		s.init(200 * time.Millisecond)

		for {
			n, err := r.Read(buffer)
			if err != nil {
				doneChan <- fmt.Errorf("read: %w", err)
				return
			}

			s.update(uint64(n))

			if _, err := w.Write(buffer[:n]); err != nil {
				doneChan <- fmt.Errorf("write: %w", err)
				return
			}
		}
	}()

	go func() {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, os.Interrupt)
		<-quit

		doneChan <- nil
	}()

	if err := <-doneChan; err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	} else {
		fmt.Fprint(os.Stderr, "\n")
	}

	w.Close()

	if srtconn, ok := w.(srt.Conn); ok {
		stats := &srt.Statistics{}
		srtconn.Stats(stats)

		data, err := json.MarshalIndent(stats, "", "   ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "writer: %+v\n", stats)
		} else {
			fmt.Fprintf(os.Stderr, "writer: %s\n", string(data))
		}
	}

	r.Close()

	if srtconn, ok := r.(srt.Conn); ok {
		stats := &srt.Statistics{}
		srtconn.Stats(stats)

		data, err := json.MarshalIndent(stats, "", "   ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "reader: %+v\n", stats)
		} else {
			fmt.Fprintf(os.Stderr, "reader: %s\n", string(data))
		}
	}

	if logger != nil {
		logger.Close()
	}
}

func openReader(addr string, logger srt.Logger) (io.ReadCloser, error) {
	if len(addr) == 0 {
		return nil, fmt.Errorf("the address must not be empty")
	}

	if addr == "-" {
		return os.Stdin, nil
	}

	if strings.HasPrefix(addr, "debug://") {
		readerOptions := DebugReaderOptions{}
		parts := strings.SplitN(strings.TrimPrefix(addr, "debug://"), "?", 2)
		if len(parts) > 1 {
			options, err := url.ParseQuery(parts[1])
			if err != nil {
				return nil, err
			}

			if x, err := strconv.ParseUint(options.Get("bitrate"), 10, 64); err == nil {
				readerOptions.Bitrate = x
			}
		}

		r, err := NewDebugReader(readerOptions)

		return r, err
	}

	u, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}

	if u.Scheme == "srt" {
		config := srt.DefaultConfig()
		if err := config.UnmarshalQuery(u.RawQuery); err != nil {
			return nil, err
		}
		config.Logger = logger

		mode := u.Query().Get("mode")

		if mode == "listener" {
			ln, err := srt.Listen("srt", u.Host, config)
			if err != nil {
				return nil, err
			}

			conn, _, err := ln.Accept(func(req srt.ConnRequest) srt.ConnType {
				if config.StreamId != req.StreamId() {
					return srt.REJECT
				}

				req.SetPassphrase(config.Passphrase)

				return srt.PUBLISH
			})
			if err != nil {
				return nil, err
			}

			if conn == nil {
				return nil, fmt.Errorf("incoming connection rejected")
			}

			return conn, nil
		} else if mode == "caller" {
			conn, err := srt.Dial("srt", u.Host, config)
			if err != nil {
				return nil, err
			}

			return conn, nil
		} else {
			return nil, fmt.Errorf("unsupported mode")
		}
	} else if u.Scheme == "udp" {
		laddr, err := net.ResolveUDPAddr("udp", u.Host)
		if err != nil {
			return nil, err
		}

		conn, err := net.ListenUDP("udp", laddr)
		if err != nil {
			return nil, err
		}

		return conn, nil
	}

	return nil, fmt.Errorf("unsupported reader")
}

func openWriter(addr string, logger srt.Logger) (io.WriteCloser, error) {
	if len(addr) == 0 {
		return nil, fmt.Errorf("the address must not be empty")
	}

	if addr == "-" {
		return NewNonblockingWriter(os.Stdout, 2048), nil
	}

	if strings.HasPrefix(addr, "file://") {
		path := strings.TrimPrefix(addr, "file://")
		file, err := os.Create(path)
		if err != nil {
			return nil, err
		}

		return NewNonblockingWriter(file, 2048), nil
	}

	u, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}

	if u.Scheme == "srt" {
		config := srt.DefaultConfig()
		if err := config.UnmarshalQuery(u.RawQuery); err != nil {
			return nil, err
		}
		config.Logger = logger

		mode := u.Query().Get("mode")

		if mode == "listener" {
			ln, err := srt.Listen("srt", u.Host, config)
			if err != nil {
				return nil, err
			}

			conn, _, err := ln.Accept(func(req srt.ConnRequest) srt.ConnType {
				if config.StreamId != req.StreamId() {
					return srt.REJECT
				}

				req.SetPassphrase(config.Passphrase)

				return srt.SUBSCRIBE
			})
			if err != nil {
				return nil, err
			}

			if conn == nil {
				return nil, fmt.Errorf("incoming connection rejected")
			}

			return conn, nil
		} else if mode == "caller" {
			conn, err := srt.Dial("srt", u.Host, config)
			if err != nil {
				return nil, err
			}

			return conn, nil
		} else {
			return nil, fmt.Errorf("unsupported mode")
		}
	} else if u.Scheme == "udp" {
		raddr, err := net.ResolveUDPAddr("udp", u.Host)
		if err != nil {
			return nil, err
		}

		conn, err := net.DialUDP("udp", nil, raddr)
		if err != nil {
			return nil, err
		}

		return conn, nil
	}

	return nil, fmt.Errorf("unsupported writer")
}
