package net

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSYNCookie(t *testing.T) {
	counter := int64(0)

	s := NewSYNCookie("192.168.0.1", 42, func() int64 {
		return counter
	})

	require.Equal(t, "dl2INvNSQTZ5zQu9MxNmGyAVmNkB33io", s.secret1)
	require.Equal(t, "nwj2qrsh3xyC8OmCp1gObD0iOtQNQsLi", s.secret2)

	cookie := s.Get("192.168.0.2")

	require.Equal(t, uint32(0xe6303651), cookie)

	require.True(t, s.Verify(cookie, "192.168.0.2"))

	require.False(t, s.Verify(cookie, "192.168.0.3"))
	require.False(t, s.Verify(cookie-95854, "192.168.0.2"))

	counter = 1

	require.True(t, s.Verify(cookie, "192.168.0.2"))

	counter = 2

	require.False(t, s.Verify(cookie, "192.168.0.2"))
}
