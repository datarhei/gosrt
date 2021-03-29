// Copyright 2020 FOSS GmbH. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package srt

import (
	"fmt"
	"time"
)

type Config struct {
	// Type of congestion control. 'live' or 'file'
	// SRTO_CONGESTION
	Congestion string

	// Connection timeout.
	// SRTO_CONNTIMEO
	ConnectionTimeout time.Duration

	// Enable drift tracer.
	// SRTO_DRIFTTRACER
	DriftTrace bool

	// Reject connection if parties set different passphrase.
	// SRTO_ENFORCEDENCRYPTION
	EnforceEncryption bool

	// Flow control window size. Bytes.
	// SRTO_FC
	FC uint32

	// Accept group connections.
	// SRTO_GROUPCONNECT
	GroupConnect bool

	// Group stability timeout.
	// SRTO_GROUPSTABTIMEO
	GroupStabilityTimeout time.Duration

	// Input bandwidth. Bytes.
	// SRTO_INPUTBW
	InputBW uint32

	// IP socket type of service
	// SRTO_IPTOS
	IPTOS int

	// Defines IP socket "time to live" option.
	// SRTO_IPTTL
	IPTTL int

	// Allow only IPv6.
	// SRTO_IPV6ONLY
	IPv6Only bool

	// Duration of Stream Encryption key switchover. Packets.
	// SRTO_KMPREANNOUNCE
	KMPreAnnounce uint32

	// Stream encryption key refresh rate. Packets.
	// SRTO_KMREFRESHRATE
	KMRefreshRate uint32

	// Defines the maximum accepted transmission latency.
	// SRTO_LATENCY
	Latency time.Duration

	// Link linger value
	// SRTO_LINGER
	Linger time.Duration

	// Packet reorder tolerance.
	// SRTO_LOSSMAXTTL
	LossMaxTTL uint32

	// Bandwidth limit in bytes.
	// SRTO_MAXBW
	MaxBW uint32

	// Enable SRT message mode.
	// SRTO_MESSAGEAPI
	MessageAPI bool

	// Minimum SRT library version of a peer.
	// SRTO_MINVERSION
	MinVersion string

	// MTU size
	// SRTO_MSS
	MSS uint

	// Enable periodic NAK reports
	// SRTO_NAKREPORT
	NAKReport bool

	// Limit bandwidth overhead, percents
	// SRTO_OHEADBW
	OverheadBW uint

	// Set up the packet filter.
	// SRTO_PACKETFILTER
	PacketFilter string

	// Password for the encrypted transmission.
	// SRTO_PASSPHRASE
	Passphrase string

	// Maximum payload size. Bytes.
	// SRTO_PAYLOADSIZE
	PayloadSize uint

	// Crypto key length in bytes.
	// SRTO_PBKEYLEN
	PBKeylen int

	// Peer idle timeout.
	// SRTO_PEERIDLETIMEO
	PeerIdleTimeout time.Duration

	// Minimum receiver latency to be requested by sender.
	// SRTO_PEERLATENCY
	PeerLatency time.Duration

	// Receiver buffer size. Bytes.
	// SRTO_RCVBUF
	ReceiverBufferSize uint32

	// Receiver-side latency.
	// SRTO_RCVLATENCY
	ReceiverLatency time.Duration

	// Sender buffer size. Bytes.
	// SRTO_SNDBUF
	SendBufferSize uint32

	// Sender's delay before dropping packets.
	// SRTO_SNDDROPDELAY
	SendDropDelay time.Duration

	// Stream ID (settable in caller mode only, visible on the listener peer)
	// SRTO_STREAMID
	StreamId string

	// Drop too late packets.
	// SRTO_TLPKTDROP
	TooLatePacketDrop bool

	// Transmission type. 'live' or 'file'.
	// SRTO_TRANSTYPE
	TransmissionType string

	// Timestamp-based packet delivery mode.
	// SRTO_TSBPDMODE
	TSBPDMode bool
}

var DefaultConfig Config = Config{
	Congestion:            "live",
	ConnectionTimeout:     2 * time.Second,
	DriftTrace:            true,
	EnforceEncryption:     false,
	FC:                    8192,
	GroupConnect:          false,
	GroupStabilityTimeout: 0,
	InputBW:               0,
	IPTOS:                 0,
	IPTTL:                 0,
	IPv6Only:              false,
	KMPreAnnounce:         4000,
	KMRefreshRate:         1 << 24,
	Latency:               120 * time.Millisecond,
	Linger:                2 * time.Second,
	LossMaxTTL:            0,
	MaxBW:                 0,
	MessageAPI:            false,
	MinVersion:            "1.4.2",
	MSS:                   1500,
	NAKReport:             true,
	OverheadBW:            10,
	PacketFilter:          "",
	Passphrase:            "",
	PayloadSize:           1316,
	PBKeylen:              16,
	PeerIdleTimeout:       2 * time.Second,
	PeerLatency:           120 * time.Millisecond,
	ReceiverBufferSize:    0,
	ReceiverLatency:       120 * time.Millisecond,
	SendBufferSize:        0,
	SendDropDelay:         1 * time.Second,
	StreamId:              "",
	TooLatePacketDrop:     true,
	TransmissionType:      "live",
	TSBPDMode:             true,
}

func (c Config) Validate() error {
	if c.TransmissionType != "live" {
		return fmt.Errorf("TransmissionType must be 'live'.")
	}

	c.Congestion = "live"
	c.NAKReport = true
	c.TooLatePacketDrop = true
	c.TSBPDMode = true

	if c.Congestion != "live" {
		return fmt.Errorf("Congestion mode must be 'live'.")
	}

	if c.ConnectionTimeout <= 0 {
		return fmt.Errorf("ConnectionTimeout must be greater than 0.")
	}

	if c.GroupConnect == true {
		return fmt.Errorf("GroupConnect is not supported.")
	}

	if c.IPTOS > 0 && c.IPTOS > 255 {
		return fmt.Errorf("IPTOS must be lower than 255.")
	}

	if c.IPTTL > 0 && c.IPTTL > 255 {
		return fmt.Errorf("IPTTL must be between 1 and 255.")
	}

	if c.IPv6Only == true {
		return fmt.Errorf("IPv6Only is not supported.")
	}

	if c.KMRefreshRate != 0 && c.KMRefreshRate <= c.KMPreAnnounce {
		return fmt.Errorf("KMRefreshRate must be greater than KMPreAnnounce.")
	}

	if c.Latency < 0 {
		return fmt.Errorf("Latency must be greater than 0.")
	}

	if c.Latency != 0 {
		c.PeerLatency = c.Latency
		c.ReceiverLatency = c.Latency
	}

	if c.MSS < 76 {
		return fmt.Errorf("MSS must be greater than 76.")
	}

	if c.NAKReport == false {
		return fmt.Errorf("NAKReport must be enabled.")
	}

	if c.OverheadBW < 10 || c.OverheadBW > 100 {
		return fmt.Errorf("OverheadBW must be between 5 and 100.")
	}

	if len(c.PacketFilter) != 0 {
		return fmt.Errorf("PacketFilter are not supported.")
	}

	if c.PBKeylen != 16 && c.PBKeylen != 24 && c.PBKeylen != 32 {
		return fmt.Errorf("PBKeylen must be 16, 24, or 32 bytes.")
	}

	if c.PeerLatency < 0 {
		return fmt.Errorf("PeerLatency must be greater than 0.")
	}

	if c.ReceiverLatency < 0 {
		return fmt.Errorf("ReceiverLatency must be greater than 0.")
	}

	if c.SendDropDelay < 0 {
		return fmt.Errorf("SendDropDelay must be greater than 0.")
	}

	if len(c.StreamId) > 512 {
		return fmt.Errorf("StreamId. must be shorter than or equal to 512 bytes.")
	}

	if c.TooLatePacketDrop == false {
		return fmt.Errorf("TooLatePacketDrop must be enabled.")
	}

	if c.TransmissionType != "live" {
		return fmt.Errorf("TransmissionType must be 'live'.")
	}

	if c.TSBPDMode == false {
		return fmt.Errorf("TSBPDMode must be enabled.")
	}

	return nil
}
