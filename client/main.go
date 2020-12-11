// Copyright 2020 FOSS GmbH. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/datarhei/gosrt"
)

type client struct {
	addr     string
	streamId string
}

func main() {
	c := client{}

	flag.StringVar(&c.addr, "addr", "", "Address to connect to")
	flag.StringVar(&c.streamId, "streamid", "", "streamId")

	flag.Parse()

	conn, err := srt.Dial("udp", c.addr, srt.DialConfig{
		StreamId: c.streamId,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "dial: %v\n", err)
		os.Exit(1)
	}

	doneChan := make(chan error)

	go func() {
		wr := srt.NewNonblockingWriter(os.Stdout)
		defer wr.Close()

		buffer := make([]byte, 2048)

		for {
			n, err := conn.Read(buffer)
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

	conn.Close()
}
