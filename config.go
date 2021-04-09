// Copyright 2020 FOSS GmbH. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package srt

import (
	"fmt"
	"time"
)

const (
	UDP_HEADER_SIZE  = 28
	SRT_HEADER_SIZE  = 16
	MIN_MSS_SIZE     = 76
	MAX_MSS_SIZE     = 1500
	MIN_PAYLOAD_SIZE = MIN_MSS_SIZE - UDP_HEADER_SIZE - SRT_HEADER_SIZE
	MAX_PAYLOAD_SIZE = MAX_MSS_SIZE - UDP_HEADER_SIZE - SRT_HEADER_SIZE
	SRT_VERSION      = 0x010402
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

	// Flow control window size. Packets.
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
	InputBW int64

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
	KMPreAnnounce uint64

	// Stream encryption key refresh rate. Packets.
	// SRTO_KMREFRESHRATE
	KMRefreshRate uint64

	// Defines the maximum accepted transmission latency.
	// SRTO_LATENCY
	Latency time.Duration

	// Packet reorder tolerance.
	// SRTO_LOSSMAXTTL
	LossMaxTTL uint32

	// Bandwidth limit in bytes.
	// SRTO_MAXBW
	MaxBW int64

	// Enable SRT message mode.
	// SRTO_MESSAGEAPI
	MessageAPI bool

	// Minimum input bandwidth
	// This option is effective only if both SRTO_MAXBW and SRTO_INPUTBW are set to 0. It controls the minimum allowed value of the input bitrate estimate.
	// SRTO_MININPUTBW
	MinInputBW int64

	// Minimum SRT library version of a peer.
	// SRTO_MINVERSION
	MinVersion uint32

	// MTU size
	// SRTO_MSS
	MSS uint32

	// Enable periodic NAK reports
	// SRTO_NAKREPORT
	NAKReport bool

	// Limit bandwidth overhead, percents
	// SRTO_OHEADBW
	OverheadBW int64

	// Set up the packet filter.
	// SRTO_PACKETFILTER
	PacketFilter string

	// Password for the encrypted transmission.
	// SRTO_PASSPHRASE
	Passphrase string

	// Maximum payload size. Bytes.
	// SRTO_PAYLOADSIZE
	PayloadSize uint32

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
	ConnectionTimeout:     3 * time.Second,
	DriftTrace:            true,
	EnforceEncryption:     true,
	FC:                    25600,
	GroupConnect:          false,
	GroupStabilityTimeout: 0,
	InputBW:               0,
	IPTOS:                 0,
	IPTTL:                 0,
	IPv6Only:              false,
	KMPreAnnounce:         1 << 12,
	KMRefreshRate:         1 << 24,
	Latency:               -1,
	LossMaxTTL:            0,
	MaxBW:                 -1,
	MessageAPI:            false,
	MinVersion:            0x010402,
	MSS:                   MAX_MSS_SIZE,
	NAKReport:             true,
	OverheadBW:            25,
	PacketFilter:          "",
	Passphrase:            "",
	PayloadSize:           MAX_PAYLOAD_SIZE,
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

	if c.KMRefreshRate != 0 {
		if c.KMPreAnnounce < 1 || c.KMPreAnnounce > c.KMRefreshRate/2 {
			return fmt.Errorf("KMPreAnnounce must be greater than 1 and smaller than KMRefreshRate/2.")
		}
	}

	if c.Latency >= 0 {
		c.PeerLatency = c.Latency
		c.ReceiverLatency = c.Latency
	}

	if c.MinVersion != SRT_VERSION {
		return fmt.Errorf("MinVersion must be %#06x.", SRT_VERSION)
	}

	if c.MSS < MIN_MSS_SIZE || c.MSS > MAX_MSS_SIZE {
		return fmt.Errorf("MSS must be between %d and %d (both inclusive).", MIN_MSS_SIZE, MAX_MSS_SIZE)
	}

	if c.NAKReport == false {
		return fmt.Errorf("NAKReport must be enabled.")
	}

	if c.OverheadBW < 10 || c.OverheadBW > 100 {
		return fmt.Errorf("OverheadBW must be between 10 and 100.")
	}

	if len(c.PacketFilter) != 0 {
		return fmt.Errorf("PacketFilter are not supported.")
	}

	if c.PayloadSize < MIN_PAYLOAD_SIZE || c.PayloadSize > MAX_PAYLOAD_SIZE {
		return fmt.Errorf("PayloadSize must be between %d and %d (both inclusive).", MIN_PAYLOAD_SIZE, MAX_PAYLOAD_SIZE)
	}

	if c.PayloadSize > c.MSS-uint32(SRT_HEADER_SIZE+UDP_HEADER_SIZE) {
		return fmt.Errorf("PayloadSize must not be larger than %d (MSS - %d)", c.MSS-uint32(SRT_HEADER_SIZE+UDP_HEADER_SIZE), SRT_HEADER_SIZE-UDP_HEADER_SIZE)
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
