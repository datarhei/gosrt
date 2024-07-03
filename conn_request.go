package srt

import (
	"fmt"
	"net"
	"time"

	"github.com/datarhei/gosrt/crypto"
	"github.com/datarhei/gosrt/packet"
)

// ConnRequest is an incoming connection request
type ConnRequest interface {
	// RemoteAddr returns the address of the peer. The returned net.Addr
	// is a copy and can be used at will.
	RemoteAddr() net.Addr

	// Version returns the handshake version of the incoming request. Currently
	// known versions are 4 and 5. With version 4 the StreamId will always be
	// empty and IsEncrypted will always return false. An incoming version 4
	// connection will always be publishing.
	Version() uint32

	// StreamId returns the streamid of the requesting connection. Use this
	// to decide what to do with the connection.
	StreamId() string

	// IsEncrypted returns whether the connection is encrypted. If it is
	// encrypted, use SetPassphrase to set the passphrase for decrypting.
	IsEncrypted() bool

	// SetPassphrase sets the passphrase in order to decrypt the incoming
	// data. Returns an error if the passphrase did not work or the connection
	// is not encrypted.
	SetPassphrase(p string) error

	// SetRejectionReason sets the rejection reason for the connection. If
	// no set, REJ_PEER will be used.
	SetRejectionReason(r RejectionReason)
}

// connRequest implements the ConnRequest interface
type connRequest struct {
	addr      net.Addr
	start     time.Time
	socketId  uint32
	timestamp uint32

	config          Config
	handshake       *packet.CIFHandshake
	crypto          crypto.Crypto
	passphrase      string
	rejectionReason RejectionReason
}

func (req *connRequest) RemoteAddr() net.Addr {
	addr, _ := net.ResolveUDPAddr("udp", req.addr.String())
	return addr
}

func (req *connRequest) Version() uint32 {
	return req.handshake.Version
}

func (req *connRequest) StreamId() string {
	return req.handshake.StreamId
}

func (req *connRequest) IsEncrypted() bool {
	return req.crypto != nil
}

func (req *connRequest) SetPassphrase(passphrase string) error {
	if req.handshake.Version == 5 {
		if req.crypto == nil {
			return fmt.Errorf("listen: request without encryption")
		}

		if err := req.crypto.UnmarshalKM(req.handshake.SRTKM, passphrase); err != nil {
			return err
		}
	}

	req.passphrase = passphrase

	return nil
}

func (req *connRequest) SetRejectionReason(reason RejectionReason) {
	req.rejectionReason = reason
}
