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

	"github.com/datarhei/gosrt"
)

func main() {
	var from string
	var to string

	flag.StringVar(&from, "from", "", "Address to read from")
	flag.StringVar(&to, "to", "", "Address to write to")

	flag.Parse()

	r, err := openReader(from)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reader: %v\n", err)
		os.Exit(1)
	}

	w, err := openWriter(to)
	if err != nil {
		fmt.Fprintf(os.Stderr, "writer: %v\n", err)
		os.Exit(1)
	}

	doneChan := make(chan error)

	go func() {
		wr := srt.NewNonblockingWriter(w)
		defer wr.Close()

		buffer := make([]byte, 2048)

		for {
			n, err := r.Read(buffer)
			if err != nil {
				doneChan <- err
				return
			}

			//fmt.Fprintf(os.Stderr, "read: got %d bytes\n", n)

			if _, err := wr.Write(buffer[:n]); err != nil {
				doneChan <- err
				return
			}
		}

		doneChan <- nil
	}()

	go func() {
		quit := make(chan os.Signal)
		signal.Notify(quit, os.Interrupt)
		<-quit

		doneChan <- nil
	}()

	if err := <-doneChan; err != nil {
		fmt.Fprintf(os.Stderr, "read: %v\n", err)
	}

	r.Close()
	w.Close()
}

func openReader(addr string) (io.ReadWriteCloser, error) {
	if len(addr) == 0 {
		return nil, fmt.Errorf("The address must not be empty")
	}

	if addr == "-" {
		return os.Stdin, nil
	}

	u, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}

	if u.Scheme == "srt" {
		streamId := u.Query().Get("streamid")
		conn, err := srt.Dial("udp", u.Host, srt.DialConfig{
			StreamId: streamId,
		})
		if err != nil {
			return nil, err
		}

		return conn, nil
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

	return nil, fmt.Errorf("unsupported reader")
}

func openWriter(addr string) (io.ReadWriteCloser, error) {
	if len(addr) == 0 {
		return nil, fmt.Errorf("The address must not be empty")
	}

	if addr == "-" {
		return os.Stdout, nil
	}

	u, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}

	if u.Scheme == "srt" {
		streamId := u.Query().Get("streamid")
		conn, err := srt.Dial("udp", u.Host, srt.DialConfig{
			StreamId: streamId,
		})
		if err != nil {
			return nil, err
		}

		return conn, nil
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

	return nil, fmt.Errorf("unsupported writer")
}
