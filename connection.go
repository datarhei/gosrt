package main

import (
	"net"
)

type Conn interface {
	ListenAndServe()
	Push(p *Packet)
	DeliverTo(d PacketWriter)
	RemoteAddr() net.Addr
	SocketId() uint32
	PeerSocketId() uint32
	StreamId() string
	Shutdown(func())
	Close()
}
