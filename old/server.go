package old

import (
	"context"
	//"encoding/hex"
	"errors"
	"net"
	"os"
	"sync"
	"time"
)

type Server struct {
	address string
	pc      net.PacketConn

	isShutdown bool

	stop           sync.WaitGroup
	stopMain       chan struct{}
	stopReader     chan struct{}
	stopWriter     chan struct{}
	stopDispatcher chan struct{}

	rawPacketPool sync.Pool
	packetPool    sync.Pool

	rcvQueue chan *RawPacket
	sndQueue chan *RawPacket

	packetQueue chan *Packet

	start time.Time

	conns     map[uint32]Conn
	streamids map[string]*pubSub
	lock      sync.RWMutex

	syncookie SYNCookie

	deliverData bool
}

func New(address string, deliverData bool) Server {
	s := Server{
		address: address,
		deliverData: deliverData,
	}

	s.rawPacketPool = sync.Pool{
		New: func() interface{} {
			return new(RawPacket)
		},
	}

	s.packetPool = sync.Pool{
		New: func() interface{} {
			return new(Packet)
		},
	}

	s.stopMain = make(chan struct{}, 1)
	s.stopReader = make(chan struct{}, 1)
	s.stopWriter = make(chan struct{}, 1)
	s.stopDispatcher = make(chan struct{}, 1)

	s.rcvQueue = make(chan *RawPacket, 128)
	s.sndQueue = make(chan *RawPacket, 128)

	s.packetQueue = make(chan *Packet, 128)

	s.conns = make(map[uint32]Conn)
	s.streamids = make(map[string]*pubSub)

	s.syncookie = NewSYNCookie(address)

	return s
}

func (s *Server) ListenAndServe() error {
	go s.dispatcher()

	go s.reader()
	go s.writer()

	pc, err := net.ListenPacket("udp", s.address)
	if err != nil {
		return err
	}

	defer pc.Close()

	s.pc = pc

	doneChan := make(chan error, 1)

	s.start = time.Now()

	go func() {
		buffer := make([]byte, 1500)
		index := 0
		for {
			if s.isShutdown == true {
				doneChan <- nil
				return
			}

			pc.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, addr, err := pc.ReadFrom(buffer)
			if err != nil {
				if errors.Is(err, os.ErrDeadlineExceeded) == true {
					continue
				}

				doneChan <- err
				return
			}

			p := s.rawPacketPool.Get().(*RawPacket)
			p.data.Reset()

			p.addr = addr
			p.data.Write(buffer[:n])

			s.rcvQueue <- p

			index++
			/*
				if index >= 10 {
					doneChan <- err
					return
				}
			*/
		}
	}()

	log("listening on %s\n", s.address)

	select {
	case err = <-doneChan:
		break
	}

	if err != nil {
		s.shutdown()
	}

	log("listen shutdown\n")

	return err
}

func (s *Server) Shutdown(context.Context) error {
	s.isShutdown = true

	s.shutdown()

	return nil
}

func (s *Server) shutdown() error {
	s.lock.Lock()
	for _, conn := range s.conns {
		s.stop.Add(1)
		conn.Shutdown(func() {
			s.stop.Done()
		})
	}
	s.lock.Unlock()

	s.stopDispatcher <- struct{}{}
	s.stopReader <- struct{}{}
	s.stopWriter <- struct{}{}

	s.stop.Add(3)

	s.stop.Wait()

	return nil
}

func (s *Server) createPacket() *Packet {
	return new(Packet)
	//return s.packetPool.Get().(*Packet)
}

func (s *Server) recyclePacket(p *Packet) {
	return
/*
	if p == nil {
		return
	}

	s.packetPool.Put(p)
*/
}

type connectMode int

const (
	REJECT connectMode = connectMode(1 << iota)
	PUBLISH
	SUBSCRIBE
)

func (s *Server) handlePublish(conn Conn) {

}

func (s *Server) handleSubscribe(conn Conn) {

}

func (s *Server) handleConnect(addr net.Addr, streamId string) (connectMode, string) {
	if streamId == "publish" {
		return PUBLISH, "something"
	}

	return SUBSCRIBE, "something"

	/*
	accessControl struct {
		username string
		resource string
		hostname string
		sessionId string
		purpose string
		mode string
		other []string
	}

	// Appendix B.  SRT Access Control
	purpose := "stream"
	mode := "request"

	if strings.HasPrefix(streamId, "#!::") == true {
		fields := strings.Split(c.streamId[4:], ",")

		for _, f := range fields {
			switch f[0] {
			case 'u': c.accessControl.username = f[2:]
			case 'r': c.accessControl.resource = f[2:]
			case 'h': c.accessControl.hostname = f[2:]
			case 's': c.accessControl.sessionId = f[2:]
			case 't': c.accessControl.purpose = f[2:]
			case 'm': c.accessControl.mode = f[2:]
			default:
				c.accessControl.other = append(c.accessControl.other, f)
			}
		}
	}

	return false
	*/
}

func (s *Server) reader() {
	defer func() {
		log("server: left reader loop\n")
		s.stop.Done()
	}()

	for {
		select {
		case <-s.stopReader:
			return
		case b := <-s.rcvQueue:
			if s.isShutdown == true {
				break
			}

			buffer := make([]byte, b.data.Len())
			copy(buffer, b.data.Bytes())
			addr := b.addr

			s.rawPacketPool.Put(b)

			//logIn("packet-received: bytes=%d from=%s\n", len(buffer), addr.String())
			//logIn("%s", hex.Dump(buffer[:16]))

			p := s.createPacket()

			p.addr = addr

			if err := p.Unmarshal(buffer); err != nil {
				s.recyclePacket(p)
				break
			}

			if p.isControlPacket == true {
				//logIn("%s", p.String())
			}

			if p.destinationSocketId == 0 {
				if p.isControlPacket == true && p.controlType == CTRLTYPE_HANDSHAKE {
					s.handleHandshake(p)
				}

				break
			}

			s.packetQueue <- p
		}
	}
}

func (s *Server) dispatcher() {
	defer func() {
		log("server: left dispatcher loop\n")
		s.stop.Done()
	}()

	for {
		select {
		case <-s.stopDispatcher:
			return
		case p := <-s.packetQueue:
			s.lock.RLock()
			conn, ok := s.conns[p.destinationSocketId]
			s.lock.RUnlock()

			if !ok {
				// ignore the packet, we don't know the destination
				break
			}

			conn.Push(p)
		}
	}
}

func (s *Server) handleHandshake(p *Packet) {
	cif := &CIFHandshake{}

	if err := cif.Unmarshal(p.data); err != nil {
		logIn("cif error: %s\n", err)
		s.recyclePacket(p)
		return
	}

	logIn("%s\n", cif.String())

	// assemble the response (4.3.1.  Caller-Listener Handshake)

	p.controlType = CTRLTYPE_HANDSHAKE
	p.subType = 0
	p.typeSpecific = 0
	p.timestamp = uint32(time.Now().Sub(s.start).Microseconds())
	p.destinationSocketId = cif.srtSocketId

	if cif.handshakeType == HSTYPE_INDUCTION {
		// cif
		cif.version = 5
		cif.encryptionField = 0
		cif.extensionField = 0x4A17
		cif.initialPacketSequenceNumber = 0
		cif.maxTransmissionUnitSize = 0
		cif.maxFlowWindowSize = 0
		cif.srtSocketId = 0
		cif.synCookie = s.syncookie.Get(p.addr.String())

		// leave the IP as is

		p.SetCIF(cif)

		logOut("%s\n", cif.String())

		s.send(p)
	} else if cif.handshakeType == HSTYPE_CONCLUSION {
		// Verify the SYN cookie
		if s.syncookie.Verify(cif.synCookie, p.addr.String()) == false {
			cif.handshakeType = REJ_ROGUE
			p.SetCIF(cif)
			s.send(p)

			return
		}

		// We only support HSv5
		if cif.version != 5 {
			cif.handshakeType = REJ_ROGUE
			p.SetCIF(cif)
			s.send(p)

			return
		}

		// Check the required SRT flags
		if cif.srtFlags.TSBPDSND == false || cif.srtFlags.TSBPDRCV == false || cif.srtFlags.TLPKTDROP == false || cif.srtFlags.PERIODICNAK == false || cif.srtFlags.REXMITFLG == false {
			cif.handshakeType = REJ_ROGUE
			p.SetCIF(cif)
			s.send(p)

			return
		}

		// We only support live streaming
		if cif.srtFlags.STREAM == true {
			cif.handshakeType = REJ_MESSAGEAPI
			p.SetCIF(cif)
			s.send(p)

			return
		}

		// Verify the validity of the the connection. This is handed to the server application  implementation
		mode, id := s.handleConnect(p.addr, cif.streamId)
		if mode == REJECT {
			cif.handshakeType = REJ_PEER
			p.SetCIF(cif)
			s.send(p)

			return
		}

		socketId := uint32(time.Now().Sub(s.start).Microseconds())

		// new connection
		var conn Conn

		now := time.Now()

		if mode == PUBLISH {
			log("new publisher wants to publish on %s\n", id)
			conn = &PublisherConn{
				addr:         p.addr,
				start:        now,
				socketId:     socketId,
				peerSocketId: cif.srtSocketId,
				streamId:     cif.streamId,
				TsbpdTimeBase:  p.timestamp,
				TsbpdDelay:    uint32(cif.recvTSBPDDelay) * 1000,
				Drift:         0,
				send:          s.send,
				createPacket:  s.createPacket,
				recyclePacket: s.recyclePacket,
				onShutdown:    s.connectionShutdown,
				initialPacketSequenceNumber: cif.initialPacketSequenceNumber,
				deliverData: s.deliverData,
			}

			// add connection
			s.lock.Lock()
			_, ok := s.streamids[id]
			if ok == true {
				// We already have such a stream
				cif.handshakeType = REJ_PEER
				p.SetCIF(cif)
				s.send(p)

				return
			}

			// new pubsub ...
			ps := NewPubSub(conn)
			s.streamids[id] = ps
			s.conns[socketId] = conn
			s.lock.Unlock()
		} else {
			log("new subscriber wants to subscribe to %s\n", id)
			conn = &SubscriberConn{
				addr:         p.addr,
				start:        now,
				socketId:     socketId,
				peerSocketId: cif.srtSocketId,
				streamId:     cif.streamId,
				send:          s.send,
				createPacket:  s.createPacket,
				recyclePacket: s.recyclePacket,
				onShutdown:    s.connectionShutdown,
				initialPacketSequenceNumber: cif.initialPacketSequenceNumber,
				deliverData: s.deliverData,
			}

			// add connection
			s.lock.Lock()
			ps, ok := s.streamids[id]
			if ok == false {
				// There's no stream we can subscribe to
				cif.handshakeType = REJ_PEER
				p.SetCIF(cif)
				s.send(p)

				return
			}

			// subscribe
			ps.Subscribe(conn)
			s.conns[socketId] = conn
			s.lock.Unlock()

			p.timestamp = uint32(time.Now().Sub(now).Microseconds())
		}

		conn.ListenAndServe()

		log("new connection: %#08x (%s)\n", conn.SocketId(), conn.StreamId())

		cif.srtSocketId = socketId
		cif.synCookie = 0

		//  3.2.1.1.1.  Handshake Extension Message Flags
		cif.srtVersion = 0x00010402
		cif.srtFlags.TSBPDSND = true
		cif.srtFlags.TSBPDRCV = true
		cif.srtFlags.CRYPT = true
		cif.srtFlags.TLPKTDROP = true
		cif.srtFlags.PERIODICNAK = true
		cif.srtFlags.REXMITFLG = true
		cif.srtFlags.STREAM = false
		cif.srtFlags.PACKET_FILTER = true

		p.SetCIF(cif)

		logOut("%s\n", cif.String())

		s.send(p)
	} else {
		log("   unknown handshakeType\n")
		s.recyclePacket(p)
	}
}

type PacketWriter interface {
	Write(p *Packet)
}

type pubSub struct {
	conns map[uint32]Conn
	data chan *Packet
	done chan struct{}
	lock sync.RWMutex
}

func NewPubSub(conn Conn) *pubSub {
	ps := &pubSub{
		conns: make(map[uint32]Conn),
		data: make(chan *Packet, 128),
		done: make(chan struct{}),
	}

	conn.DeliverTo(ps)

	go ps.writer()

	return ps
}

func (ps *pubSub) Close() {
	close(ps.done)

	ps.lock.RLock()
	for _, c := range ps.conns {
		c.Close()
	}
	ps.lock.RUnlock()
}

func (ps *pubSub) Write(p *Packet) {
	select {
	case ps.data <- p:
	default:
	}
}

func (ps *pubSub) Subscribe(conn Conn) {
	id := conn.SocketId()

	ps.lock.Lock()
	defer ps.lock.Unlock()

	_, ok := ps.conns[id]
	if !ok {
		ps.conns[id] = conn
	}
}

func (ps *pubSub) Unsubscribe(conn Conn) {
	id := conn.SocketId()

	ps.lock.Lock()
	defer ps.lock.Unlock()

	_, ok := ps.conns[id]
	if ok {
		delete(ps.conns, id)
	}
}

func (ps *pubSub) writer() {
	for {
		select {
		case <- ps.done:
			return
		case p := <- ps.data:
			ps.lock.RLock()
			for _, c := range ps.conns {
				//log("broadcasting packet to %d\n", c.SocketId())
				c.Push(p)
			}
			ps.lock.RUnlock()
		}
	}
}

func (s *Server) connectionShutdown(socketId uint32, streamId string) {
	s.lock.Lock()
	defer s.lock.Unlock()

	delete(s.conns, socketId)
	delete(s.streamids, streamId)

	log("server: removed connection %d (%s)\n", socketId, streamId)

	time.Sleep(1)
}

func (s *Server) send(p *Packet) {
	b := s.rawPacketPool.Get().(*RawPacket)
	b.data.Reset()

	p.Marshal(&b.data)

	b.addr = p.addr

	s.sndQueue <- b
}

func (s *Server) writer() {
	defer func() {
		log("server: left writer loop\n")
		s.stop.Done()
	}()

	for {
		select {
		case <-s.stopWriter:
			return
		case b := <-s.sndQueue:
			buffer := b.data.Bytes()

			//logOut("packet-send: bytes=%d to=%s\n", len(buffer), b.addr.String())
			//logOut("%s", hex.Dump(buffer))

			//addr, _ := net.ResolveUDPAddr("udp", b.addr)

			// Write the packet's contents back to the client.
			s.pc.WriteTo(buffer, b.addr)

			s.rawPacketPool.Put(b)
		}
	}
}
