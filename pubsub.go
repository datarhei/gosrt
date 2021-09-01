// Copyright 2020 FOSS GmbH. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package srt

import (
	"fmt"
	"io"
	"sync"

	"github.com/datarhei/gosrt/internal/packet"
)

type PubSubConfig struct {
	Logger Logger
}

type PubSub interface {
	Publish(c Conn) error
	Subscribe(c Conn) error
}

type pubSub struct {
	incoming  chan packet.Packet
	abort     chan struct{}
	lock      sync.Mutex
	listeners map[uint32]chan packet.Packet
	logger    Logger
}

func NewPubSub(config PubSubConfig) PubSub {
	pb := &pubSub{
		incoming:  make(chan packet.Packet, 1024),
		listeners: make(map[uint32]chan packet.Packet),
		abort:     make(chan struct{}),
		logger:    config.Logger,
	}

	if pb.logger == nil {
		pb.logger = NewLogger(nil)
	}

	go pb.broadcast()

	return pb
}

func (pb *pubSub) broadcast() {
	defer func() {
		pb.logger.Print("pubsub:close", 0, 1, func() string { return "exiting broadcast loop" })
	}()

	pb.logger.Print("pubsub:new", 0, 1, func() string { return "starting broadcast loop" })

	for {
		select {
		case <-pb.abort:
			return
		case p := <-pb.incoming:
			pb.lock.Lock()
			for socketId, c := range pb.listeners {
				pp := p.Clone()

				select {
				case c <- pp:
				default:
					pb.logger.Print("pubsub:error", socketId, 1, func() string { return "broadcast target queue is full" })
				}
			}
			pb.lock.Unlock()

			// We don't need this packet anymore
			p.Decommission()
		}
	}
}

func (pb *pubSub) Publish(c Conn) error {
	var p packet.Packet
	var err error
	conn, ok := c.(*srtConn)
	if !ok {
		err := fmt.Errorf("the provided connection is not a SRT connection")
		pb.logger.Print("pubsub:error", 0, 1, func() string { return err.Error() })
		return err
	}

	pb.logger.Print("pubsub:publish", conn.SocketId(), 1, func() string { return "new publisher" })

	for {
		p, err = conn.readPacket()
		if err != nil {
			pb.logger.Print("pubsub:error", conn.SocketId(), 1, func() string { return err.Error() })
			break
		}

		select {
		case pb.incoming <- p:
		default:
			pb.logger.Print("pubsub:error", conn.SocketId(), 1, func() string { return "incoming queue is full" })
		}
	}

	close(pb.abort)

	return err
}

func (pb *pubSub) Subscribe(c Conn) error {
	l := make(chan packet.Packet, 1024)
	socketId := c.SocketId()
	conn, ok := c.(*srtConn)
	if !ok {
		err := fmt.Errorf("the provided connection is not a SRT connection")
		pb.logger.Print("pubsub:error", 0, 1, func() string { return err.Error() })
		return err
	}

	pb.logger.Print("pubsub:subscribe", conn.SocketId(), 1, func() string { return "new subscriber" })

	pb.lock.Lock()
	pb.listeners[socketId] = l
	pb.lock.Unlock()

	defer func() {
		pb.lock.Lock()
		delete(pb.listeners, socketId)
		pb.lock.Unlock()
	}()

	for {
		select {
		case <-pb.abort:
			return io.EOF
		case p := <-l:
			err := conn.writePacket(p)
			p.Decommission()
			if err != nil {
				pb.logger.Print("pubsub:error", conn.SocketId(), 1, func() string { return err.Error() })
				return err
			}
		}
	}
}
