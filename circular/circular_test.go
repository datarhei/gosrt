package circular

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

const max uint32 = 0b11111111_11111111_11111111_11111111

func ExampleNumber_Inc() {
	a := New(42, max)
	b := a.Inc()

	fmt.Println(b.Val())
	// Output: 43
}

func TestIncNoWrap(t *testing.T) {
	a := New(42, max)

	require.Equal(t, uint32(42), a.Val())

	a = a.Inc()

	require.Equal(t, uint32(43), a.Val())
}

func TestIncWrap(t *testing.T) {
	a := New(max-1, max)

	require.Equal(t, max-1, a.Val())

	a = a.Inc()

	require.Equal(t, max, a.Val())

	a = a.Inc()

	require.Equal(t, uint32(0), a.Val())
}

func TestDecNoWrap(t *testing.T) {
	a := New(42, max)

	require.Equal(t, uint32(42), a.Val())

	a = a.Dec()

	require.Equal(t, uint32(41), a.Val())
}

func TestDecWrap(t *testing.T) {
	a := New(0, max)

	require.Equal(t, uint32(0), a.Val())

	a = a.Dec()

	require.Equal(t, max, a.Val())

	a = a.Dec()

	require.Equal(t, max-1, a.Val())
}

func TestDistanceNoWrap(t *testing.T) {
	a := New(42, max)
	b := New(50, max)

	d := a.Distance(b)

	require.Equal(t, uint32(8), d)

	d = b.Distance(a)

	require.Equal(t, uint32(8), d)
}

func TestDistanceWrap(t *testing.T) {
	a := New(2, max)
	b := New(max-2, max)

	d := a.Distance(b)

	require.Equal(t, uint32(5), d)

	d = b.Distance(a)

	require.Equal(t, uint32(5), d)
}

func TestLt(t *testing.T) {
	a := New(42, max)
	b := New(50, max)
	c := New(max-10, max)

	x := a.Lt(b)

	require.Equal(t, true, x)

	x = b.Lt(a)

	require.Equal(t, false, x)

	x = a.Lt(c)

	require.Equal(t, false, x)

	x = c.Lt(a)

	require.Equal(t, true, x)
}

func TestGt(t *testing.T) {
	a := New(42, max)
	b := New(50, max)
	c := New(max-10, max)

	x := a.Gt(b)

	require.Equal(t, false, x)

	x = b.Gt(a)

	require.Equal(t, true, x)

	x = a.Gt(c)

	require.Equal(t, true, x)

	x = c.Gt(a)

	require.Equal(t, false, x)
}

func TestAdd(t *testing.T) {
	a := New(max-42, max)

	a = a.Add(42)

	require.Equal(t, max, a.Val())

	a = a.Add(1)

	require.Equal(t, uint32(0), a.Val())
}

func TestSub(t *testing.T) {
	a := New(42, max)

	a = a.Sub(42)

	require.Equal(t, uint32(0), a.Val())

	a = a.Sub(1)

	require.Equal(t, max, a.Val())
}
