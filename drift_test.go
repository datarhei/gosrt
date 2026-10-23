package srt

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// feedDrift adds a full span of samples where the packets arrive with the given drift.
func feedDrift(t *testing.T, d *driftTracer, drift, rtt int64) {
	for i := uint(1); i <= d.maxSpan; i++ {
		pktBaseTime := int64(i) * 10_000
		updated := d.addSample(pktBaseTime+drift, pktBaseTime, rtt)

		require.Equal(t, i == d.maxSpan, updated, "sample %d", i)
	}
}

func TestDriftTracerSmallDrift(t *testing.T) {
	d := newDriftTracer()

	require.Equal(t, int64(0), d.correction())

	feedDrift(t, d, 3000, 20_000)

	require.Equal(t, int64(3000), d.drift)
	require.Equal(t, int64(0), d.baseShift)
	require.Equal(t, int64(3000), d.correction())
}

func TestDriftTracerOverdrift(t *testing.T) {
	d := newDriftTracer()

	feedDrift(t, d, 12000, 20_000)

	require.Equal(t, int64(7000), d.drift)
	require.Equal(t, int64(5000), d.baseShift)
	require.Equal(t, int64(12000), d.correction())

	// The drift stays the same, the time base is shifted further, the correction stays the same.
	feedDrift(t, d, 12000, 20_000)

	require.Equal(t, int64(2000), d.drift)
	require.Equal(t, int64(10000), d.baseShift)
	require.Equal(t, int64(12000), d.correction())
}

func TestDriftTracerNegativeDrift(t *testing.T) {
	d := newDriftTracer()

	feedDrift(t, d, -8000, 20_000)

	require.Equal(t, int64(-3000), d.drift)
	require.Equal(t, int64(-5000), d.baseShift)
	require.Equal(t, int64(-8000), d.correction())
}

func TestDriftTracerRTTChange(t *testing.T) {
	d := newDriftTracer()

	// The first sample sets the reference RTT.
	require.False(t, d.addSample(10_000, 10_000, 20_000))

	// The RTT increased by 4ms, i.e. the one way delay by 2ms. Packets arriving
	// 2ms later are not a drift.
	for i := uint(2); i <= d.maxSpan; i++ {
		pktBaseTime := int64(i) * 10_000
		d.addSample(pktBaseTime+2000, pktBaseTime, 24_000)
	}

	require.InDelta(t, 0, d.correction(), 2)
}

func TestDriftTracerInflatedFirstRTT(t *testing.T) {
	d := newDriftTracer()

	// The first RTT sample is inflated, all others are steady. There's no drift.
	for i := uint(1); i <= d.maxSpan; i++ {
		rtt := int64(2000)
		if i == 1 {
			rtt = 9500
		}

		pktBaseTime := int64(i) * 10_000
		d.addSample(pktBaseTime, pktBaseTime, rtt)
	}

	require.InDelta(t, 0, d.correction(), 10)
}
