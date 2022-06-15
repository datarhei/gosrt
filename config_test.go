package srt

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	err := DefaultConfig().Validate()

	if err != nil {
		require.NoError(t, err, "Failed to verify the default configuration: %s", err)
	}
}

func TestMarshalUnmarshal(t *testing.T) {
	wantConfig := Config{
		Congestion:            "xxx",
		ConnectionTimeout:     42 * time.Second,
		DriftTracer:           false,
		EnforcedEncryption:    false,
		FC:                    42,
		GroupConnect:          true,
		GroupStabilityTimeout: 42 * time.Second,
		InputBW:               42,
		IPTOS:                 42,
		IPTTL:                 42,
		IPv6Only:              42,
		KMPreAnnounce:         42,
		KMRefreshRate:         42,
		Latency:               42 * time.Second,
		LossMaxTTL:            42,
		MaxBW:                 42,
		MessageAPI:            true,
		MinInputBW:            42,
		MSS:                   42,
		NAKReport:             false,
		OverheadBW:            42,
		PacketFilter:          "FEC",
		Passphrase:            "foobar",
		PayloadSize:           42,
		PBKeylen:              42,
		PeerIdleTimeout:       42 * time.Second,
		PeerLatency:           42 * time.Second,
		ReceiverBufferSize:    42,
		ReceiverLatency:       42 * time.Second,
		SendBufferSize:        42,
		SendDropDelay:         42 * time.Second,
		StreamId:              "foobaz",
		TooLatePacketDrop:     false,
		TransmissionType:      "yyy",
		TSBPDMode:             false,
		Logger:                nil,
	}

	url := wantConfig.MarshalURL("localhost", 6000)

	config := Config{}
	config.UnmarshalURL(url)

	require.Equal(t, wantConfig, config)
}
