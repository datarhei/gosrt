package main

import (
	"os"
	"os/signal"
	"flag"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"net"

	"github.com/datarhei/gosrt"
)

func main() {
	var deliverData = flag.Bool("deliver", false, "Deliver packet data to stdout")
	var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to `file`")
	var memprofile = flag.String("memprofile", "", "write memory profile to `file`")
	var traceprofile = flag.String("traceprofile", "", "write trace profile to `file`")

	flag.Parse()

	if *cpuprofile != "" {
        f, err := os.Create(*cpuprofile)
        if err != nil {
            srt.Log("could not create CPU profile: %s\n", err)
            os.Exit(1)
        }
        defer f.Close()
        if err := pprof.StartCPUProfile(f); err != nil {
            srt.Log("could not start CPU profile: %s\n", err)
            os.Exit(1)
        }
        defer pprof.StopCPUProfile()
    }

    if *traceprofile != "" {
    	f, err := os.Create(*traceprofile)
		if err != nil {
			srt.Log("failed to create trace output file: %v\n", err)
			os.Exit(1)
		}
		defer func() {
			if err := f.Close(); err != nil {
				srt.Log("failed to close trace file: %v\n", err)
				os.Exit(1)
			}
		}()

		if err := trace.Start(f); err != nil {
			srt.Log("failed to start trace: %v\n", err)
			os.Exit(1)
		}
		defer trace.Stop()
    }

    srt.Log("listening on udp://:6001\n")

	// Listen creates a server
	ln, err := srt.Listen("udp", ":6001")
	if err != nil {
	    // handle error
	    srt.Log("failed starting server: %v\n", err)
	    os.Exit(1)
	}

	go func() {
		for {
		    conn, mode, err := ln.Accept(func(addr net.Addr, streamId string) srt.ConnType {
		    	if streamId == "publish" {
		    		return srt.PUBLISH
		    	}

		    	if streamId == "subscribe" {
		    		return srt.SUBSCRIBE
		    	}

		        return srt.REJECT
		    })

		    if err != nil {
		        // handle error
		    }

		    if conn == nil {
		        // rejected connection
		        continue
		    }

		    if mode == srt.PUBLISH {
		    	go handlePublish(conn, *deliverData)
		    } else {
		   		go handleSubscribe(conn, *deliverData)
		   	}
		}
	}()

	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt)
	<-quit

	ln.Close()

	srt.Log("Server exited\n")

	if *memprofile != "" {
        f, err := os.Create(*memprofile)
        if err != nil {
            srt.Log("could not create memory profile: %s\n", err)
            os.Exit(1)
        }
        defer f.Close() // error handling omitted for example
        runtime.GC() // get up-to-date statistics
        if err := pprof.WriteHeapProfile(f); err != nil {
            srt.Log("could not write memory profile: %s\n", err)
            os.Exit(1)
        }
    }

	return
}

var pubsub *srt.PubSub = srt.NewPubSub()

func handlePublish(conn srt.Conn, deliverData bool) {
	srt.Log("got PUBLISH connection\n")

	if deliverData == true {
		totalbytes := 0

		// publishing
		for {
			p, err := conn.ReadPacket()
			if err != nil {
				srt.Log("got %11d bytes in total\n", totalbytes)
				break
			}

			if deliverData == true {
				totalbytes += len(p.Data())
				srt.Log("got %11d bytes\r", totalbytes)
				//os.Stdout.Write(p.data)
			}
		}
	} else {
		pubsub.Publish(conn)
	}

	srt.Log("leaving PUBLISH connection\n")

	conn.Close()
}

func handleSubscribe(conn srt.Conn, deliverData bool) {
	srt.Log("got SUBSCRIBE connection\n")

	pubsub.Subscribe(conn)

	srt.Log("leaving SUBSCRIBE connection\n")

	conn.Close()
}
