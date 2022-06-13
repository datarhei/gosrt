package srt

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHasTopic(t *testing.T) {
	l := NewLogger([]string{
		"packet:recv:dump",
	})

	ok := l.HasTopic("foobar")
	require.False(t, ok)

	ok = l.HasTopic("packet:recv:dump")
	require.True(t, ok)

	ok = l.HasTopic("packet:recv")
	require.False(t, ok)

	ok = l.HasTopic("packet")
	require.False(t, ok)
}

var result bool

func BenchmarkHasTopicNil(b *testing.B) {
	l := NewLogger(nil)

	var r bool
	for n := 0; n < b.N; n++ {
		r = l.HasTopic("foobar")
	}

	result = r
}

func BenchmarkHasTopicD1(b *testing.B) {
	l := NewLogger([]string{
		"packet:recv:dump",
	})

	var r bool
	for n := 0; n < b.N; n++ {
		r = l.HasTopic("packet")
	}

	result = r
}

func BenchmarkHasTopicD2(b *testing.B) {
	l := NewLogger([]string{
		"packet:recv:dump",
	})

	var r bool
	for n := 0; n < b.N; n++ {
		r = l.HasTopic("packet:recv")
	}

	result = r
}

func BenchmarkHasTopicD3(b *testing.B) {
	l := NewLogger([]string{
		"packet:recv:dump",
	})

	var r bool
	for n := 0; n < b.N; n++ {
		r = l.HasTopic("packet:recv:dump")
	}

	result = r
}
