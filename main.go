package main

import (
	"context"
	"os"
	"os/signal"
	"time"
	"flag"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
)

func main() {
	var deliverData = flag.Bool("deliver", false, "Deliver packet data to stdout")
	var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to `file`")
	var memprofile = flag.String("memprofile", "", "write memory profile to `file`")
	var traceprofile = flag.String("traceprofile", "", "write trace profile to `file`")

	flag.Parse()
/*
	ticks := uint32(0)

	send := NewSEND(42, 10)
	send.deliver = func(p *Packet) {
		log("delivering %d @ %d\n", p.packetSequenceNumber, p.PktTsbpdTime)
	}
	send.tick(ticks)
	ticks++

	p := &Packet{
		PktTsbpdTime: 3,
	}
	send.push(p)
	send.tick(ticks)
	ticks++

	p = &Packet{
		PktTsbpdTime: 4,
	}
	send.push(p)
	send.tick(ticks)
	ticks++

	p = &Packet{
		PktTsbpdTime: 5,
	}
	send.push(p)
	send.tick(ticks)
	ticks++

	p = &Packet{
		PktTsbpdTime: 6,
	}
	send.push(p)
	send.tick(ticks)
	ticks++

	send.nak([]uint32{42,42})

	p = &Packet{
		PktTsbpdTime: 7,
	}
	send.push(p)
	send.tick(ticks)
	ticks++

	p = &Packet{
		PktTsbpdTime: 8,
	}
	send.push(p)
	send.tick(ticks)
	ticks++

	send.tick(ticks)
	ticks++

	send.tick(ticks)
	ticks++

	send.ack(46)

	send.tick(ticks)
	ticks++

	send.tick(ticks)
	ticks++

	send.tick(ticks)
	ticks++

	send.tick(ticks)
	ticks++

	send.tick(ticks)
	ticks++

	send.tick(ticks)
	ticks++

	send.tick(ticks)
	ticks++
*/
/*
	recv := NewRECV(1, 2, 4)
	recv.tick(ticks)
	ticks++

	p := &Packet{
		packetSequenceNumber: 1,
		timestamp: 0,
		PktTsbpdTime: 10,
	}
	recv.push(p)
	recv.tick(ticks)
	ticks++

	p = &Packet{
		packetSequenceNumber: 2,
		timestamp: 1,
		PktTsbpdTime: 11,
	}
	recv.push(p)
	recv.tick(ticks)
	ticks++

	p = &Packet{
		packetSequenceNumber: 4,
		timestamp: 3,
		PktTsbpdTime: 14,
	}
	recv.push(p)
	recv.tick(ticks)
	ticks++

	p = &Packet{
		packetSequenceNumber: 5,
		timestamp: 4,
		PktTsbpdTime: 15,
	}
	recv.push(p)
	recv.tick(ticks)
	ticks++

	p = &Packet{
		packetSequenceNumber: 6,
		timestamp: 5,
		PktTsbpdTime: 16,
	}
	recv.push(p)
	recv.tick(ticks)
	ticks++

	p = &Packet{
		packetSequenceNumber: 3,
		timestamp: 2,
		PktTsbpdTime: 13,
	}
	//recv.push(p)
	recv.tick(ticks)
	ticks++

	recv.tick(ticks)
	ticks++

	p = &Packet{
		packetSequenceNumber: 5,
		timestamp: 4,
		PktTsbpdTime: 15,
	}
	recv.push(p)

	recv.tick(ticks)
	ticks++
	recv.tick(ticks)
	ticks++
	recv.tick(ticks)
	ticks++
	recv.tick(ticks)
	ticks++

	p = &Packet{
		packetSequenceNumber: 3,
		timestamp: 2,
		PktTsbpdTime: 13,
	}
	recv.push(p)
	recv.tick(ticks)
	ticks++
*/

	if *cpuprofile != "" {
        f, err := os.Create(*cpuprofile)
        if err != nil {
            log("could not create CPU profile: %s\n", err)
            os.Exit(1)
        }
        defer f.Close() // error handling omitted for example
        if err := pprof.StartCPUProfile(f); err != nil {
            log("could not start CPU profile: %s\n", err)
            os.Exit(1)
        }
        defer pprof.StopCPUProfile()
    }

    if *traceprofile != "" {
    	f, err := os.Create(*traceprofile)
		if err != nil {
			log("failed to create trace output file: %v\n", err)
			os.Exit(1)
		}
		defer func() {
			if err := f.Close(); err != nil {
				log("failed to close trace file: %v\n", err)
				os.Exit(1)
			}
		}()

		if err := trace.Start(f); err != nil {
			log("failed to start trace: %v\n", err)
			os.Exit(1)
		}
		defer trace.Stop()
    }

	server := New("127.0.0.1:6001", *deliverData)

	go func() {
		if err := server.ListenAndServe(); err != nil {
			log("SRT server: %s\n", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log("Server shutdown: %s\n", err)
	}

	log("Server exited\n")

	if *memprofile != "" {
        f, err := os.Create(*memprofile)
        if err != nil {
            log("could not create memory profile: %s\n", err)
            os.Exit(1)
        }
        defer f.Close() // error handling omitted for example
        runtime.GC() // get up-to-date statistics
        if err := pprof.WriteHeapProfile(f); err != nil {
            log("could not write memory profile: %s\n", err)
            os.Exit(1)
        }
    }

	return
}
