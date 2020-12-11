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

		for {
			n, err := conn.ReadPacket()
			if err != nil {
				doneChan <- err
				return
			}

			//fmt.Fprintf(os.Stderr, "read: got %d bytes\n", n)

			wr.Write(n.Data())
		}

		wr.Close()

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
