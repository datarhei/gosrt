# Interface

Similar to the "net" package.

```
// Dial connects to a server
conn, err := srt.Dial("udp", "localhost:6001", DialConfig{
    StreamId: "/publish/live/foobar.stream", 
})

// Listen creates a server
ln, err := srt.Listen("udp", ":6001", ListenConfig{})
if err != nil {
    // handle error
}

... or instead of ListenConfig there are functions to modify the options, e.g. ...

ln.SetBla()

for {
    conn, mode, err := ln.Accept(func(addr net.Addr, streamId string) {
        return REJECT
    })

    if err != nil {
        // handle error
    }

    if conn == nil {
        // rejected connection
        continue
    }

    go handleConnection(conn)
}

// Implements net.Listener interface??? <- no, because the Accept function has a different signature
func (ln *Listener) Accept(func(addr net.Addr, streamId string) connType) {
    return Conn
}

func (ln *Listener) Close() {}

func (ln *Listener) Addr() {}

type Listener struct {
    ...
}

type Addr interface {
    net.Addr
    Socket() uint32
}
```

```
type PacketWriter interface {
    Write(p *Packet)
}

type Conn struct {
    Close() error
    StreamId() string

    LocalAddr() srt.Addr
    RemoteAddr() srt.Addr

    ReadPacket(p *Packet)
    WritePacket(p *Packet)
    WritePacketTo(w PacketWriter)
}
```
