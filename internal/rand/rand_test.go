package rand

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRandomString(t *testing.T) {
	s1, err := RandomString(42, AlphaNumericCharset)
	require.NoError(t, err)

	s2, err := RandomString(42, AlphaNumericCharset)
	require.NoError(t, err)

	require.NotEqual(t, s1, s2)
}

func TestUint32(t *testing.T) {
	u1, err := Uint32()
	require.NoError(t, err)

	u2, err := Uint32()
	require.NoError(t, err)

	require.NotEqual(t, u1, u2)
}

func TestInt63(t *testing.T) {
	u1, err := Int63()
	require.NoError(t, err)

	u2, err := Int63()
	require.NoError(t, err)

	require.NotEqual(t, u1, u2)
}

func TestInt63n(t *testing.T) {
	u1, err := Int63n(42)
	require.NoError(t, err)

	u2, err := Int63n(42)
	require.NoError(t, err)

	require.NotEqual(t, u1, u2)

	u3, err := Int63n(64)
	require.NoError(t, err)

	u4, err := Int63n(64)
	require.NoError(t, err)

	require.NotEqual(t, u3, u4)
}
