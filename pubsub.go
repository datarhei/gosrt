package srt

import (
	"sync"
)

type PubSub struct {
	incoming chan *Packet
	abort chan struct{}
	lock sync.Mutex
	listeners map[uint32]chan *Packet
}

func NewPubSub() *PubSub {
	pb := &PubSub{
		incoming: make(chan *Packet, 1024),
		listeners: make(map[uint32]chan *Packet),
		abort: make(chan struct{}),
	}

	go pb.broadcast()

	return pb
}

func (pb *PubSub) broadcast() {
	defer func() {
		log("exiting broadcast loop\n")
	}()

	for {
		select {
		case <-pb.abort:
			return
		case p := <-pb.incoming:
			pb.lock.Lock()
			for _, c := range pb.listeners {
				pp := p.Clone()

				select {
				case c<-pp:
				default:
					log("broadcast target queue is full\n")
				}
			}
			pb.lock.Unlock()
		}
	}
}

func (pb *PubSub) Publish(c Conn) error {
	var p *Packet
	var err error

	for {
		p, err = c.ReadPacket()
		if err != nil {
			break
		}

		select {
		case pb.incoming<- p:
		default:
			log("incoming queue is full\n")
		}
	}

	close(pb.abort)

	return err
}

func (pb *PubSub) Subscribe(c Conn) error {
	l := make(chan *Packet, 1024)
	socketId := c.SocketId()

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
			return EOF
		case p := <-l:
			if err := c.WritePacket(p); err != nil {
				return err
			}
		}
	}

	return nil
}
