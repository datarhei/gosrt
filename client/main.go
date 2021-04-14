// Copyright 2020 FOSS GmbH. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/signal"
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

		fmt.Fprintf(os.Stderr, "%s: %f packets/s, %f Mbps\n", c, avg, bavg)
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

	flag.StringVar(&from, "from", "", "Address to read from")
	flag.StringVar(&to, "to", "", "Address to write to")

	flag.Parse()

	r, err := openReader(from)
	if err != nil {
		fmt.Fprintf(os.Stderr, "from: %v\n", err)
		os.Exit(1)
	}

	w, err := openWriter(to)
	if err != nil {
		fmt.Fprintf(os.Stderr, "to: %v\n", err)
		os.Exit(1)
	}

	doneChan := make(chan error)

	go func() {
		wr := srt.NewNonblockingWriter(w, 2048)
		defer wr.Close()

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

			//fmt.Fprintf(os.Stderr, "writing %d bytes\n", n)

			if _, err := wr.Write(buffer[:n]); err != nil {
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
		fmt.Fprintf(os.Stderr, "%v\n", err)
	}

	r.Close()

	if srtconn, ok := r.(srt.Conn); ok {
		stats := srtconn.Stats()

		fmt.Fprintf(os.Stderr, "%+v\n", stats)
	}

	w.Close()
}

func openReader(addr string) (io.ReadWriteCloser, error) {
	if len(addr) == 0 {
		return nil, fmt.Errorf("reader: the address must not be empty")
	}

	if addr == "-" {
		return os.Stdin, nil
	}

	u, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}

	if u.Scheme == "srt" {
		config := srt.DefaultConfig
		if err := config.UnmarshalQuery(u.RawQuery); err != nil {
			return nil, err
		}

		mode := u.Query().Get("mode")

		if mode == "listener" {
			ln, err := srt.Listen("udp", u.Host, config)
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
				return nil, fmt.Errorf("reader: incoming connection rejected")
			}

			return conn, nil
		} else if mode == "caller" {
			conn, err := srt.Dial("udp", u.Host, config)
			if err != nil {
				return nil, err
			}

			return conn, nil
		} else {
			return nil, fmt.Errorf("reader: unsupported mode")
		}
	}

	if u.Scheme == "udp" {
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

	return nil, fmt.Errorf("reader: unsupported reader")
}

func openWriter(addr string) (io.ReadWriteCloser, error) {
	if len(addr) == 0 {
		return nil, fmt.Errorf("writer: the address must not be empty")
	}

	if addr == "-" {
		return os.Stdout, nil
	}

	u, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}

	if u.Scheme == "srt" {
		config := srt.DefaultConfig
		if err := config.UnmarshalQuery(u.RawQuery); err != nil {
			return nil, err
		}

		mode := u.Query().Get("mode")

		if mode == "listener" {
			ln, err := srt.Listen("udp", u.Host, config)
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
				return nil, fmt.Errorf("writer: incoming connection rejected")
			}

			return conn, nil
		} else if mode == "caller" {
			conn, err := srt.Dial("udp", u.Host, config)
			if err != nil {
				return nil, err
			}

			return conn, nil
		} else {
			return nil, fmt.Errorf("writer: unsupported mode")
		}
	}

	if u.Scheme == "udp" {
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

	return nil, fmt.Errorf("writer: unsupported writer")
}
