package srt

import (
	"testing"
)

const max uint32 = 0b11111111_11111111_11111111_11111111

func TestIncNoWrap(t *testing.T) {
	a := newCircular(42, max)

	if a.Val() != 42 {
		t.Fatalf("Unexpected value: %d (wanted: %d)", a.Val(), 42)
	}

	a = a.Inc()

	if a.Val() != 43 {
		t.Fatalf("Unexpected value: %d (wanted: %d)", a.Val(), 43)
	}
}

func TestIncWrap(t *testing.T) {
	a := newCircular(max-1, max)

	if a.Val() != max-1 {
		t.Fatalf("Unexpected value: %d (wanted: %d)", a.Val(), max-1)
	}

	a = a.Inc()

	if a.Val() != max {
		t.Fatalf("Unexpected value: %d (wanted: %d)", a.Val(), max)
	}

	a = a.Inc()

	if a.Val() != 0 {
		t.Fatalf("Unexpected value: %d (wanted: %d)", a.Val(), 0)
	}
}

func TestDecNoWrap(t *testing.T) {
	a := newCircular(42, max)

	if a.Val() != 42 {
		t.Fatalf("Unexpected value: %d (wanted: %d)", a.Val(), 42)
	}

	a = a.Dec()

	if a.Val() != 41 {
		t.Fatalf("Unexpected value: %d (wanted: %d)", a.Val(), 41)
	}
}

func TestDecWrap(t *testing.T) {
	a := newCircular(0, max)

	if a.Val() != 0 {
		t.Fatalf("Unexpected value: %d (wanted: %d)", a.Val(), 0)
	}

	a = a.Dec()

	if a.Val() != max {
		t.Fatalf("Unexpected value: %d (wanted: %d)", a.Val(), max)
	}

	a = a.Dec()

	if a.Val() != max-1 {
		t.Fatalf("Unexpected value: %d (wanted: %d)", a.Val(), max-1)
	}
}

func TestDistanceNoWrap(t *testing.T) {
	a := newCircular(42, max)
	b := newCircular(50, max)

	d := a.Distance(b)

	if d != 8 {
		t.Fatalf("Unexpected value: %d (wanted: %d)", d, 8)
	}

	d = b.Distance(a)

	if d != 8 {
		t.Fatalf("Unexpected value: %d (wanted: %d)", d, 8)
	}
}

func TestDistanceWrap(t *testing.T) {
	a := newCircular(2, max)
	b := newCircular(max-2, max)

	d := a.Distance(b)

	if d != 5 {
		t.Fatalf("Unexpected value: %d (wanted: %d)", d, 5)
	}

	d = b.Distance(a)

	if d != 5 {
		t.Fatalf("Unexpected value: %d (wanted: %d)", d, 5)
	}
}

func TestLt(t *testing.T) {
	a := newCircular(42, max)
	b := newCircular(50, max)
	c := newCircular(max-10, max)

	x := a.Lt(b)

	if x != true {
		t.Fatalf("Unexpected value: %v (wanted: %v)", x, true)
	}

	x = b.Lt(a)

	if x != false {
		t.Fatalf("Unexpected value: %v (wanted: %v)", x, false)
	}

	x = a.Lt(c)

	if x != false {
		t.Fatalf("Unexpected value: %v (wanted: %v)", x, false)
	}

	x = c.Lt(a)

	if x != true {
		t.Fatalf("Unexpected value: %v (wanted: %v)", x, true)
	}
}

func TestGt(t *testing.T) {
	a := newCircular(42, max)
	b := newCircular(50, max)
	c := newCircular(max-10, max)

	x := a.Gt(b)

	if x != false {
		t.Fatalf("Unexpected value: %v (wanted: %v)", x, false)
	}

	x = b.Gt(a)

	if x != true {
		t.Fatalf("Unexpected value: %v (wanted: %v)", x, true)
	}

	x = a.Gt(c)

	if x != true {
		t.Fatalf("Unexpected value: %v (wanted: %v)", x, true)
	}

	x = c.Gt(a)

	if x != false {
		t.Fatalf("Unexpected value: %v (wanted: %v)", x, false)
	}
}

func TestAdd(t *testing.T) {
	a := newCircular(max-42, max)

	a = a.Add(42)

	if a.Val() != max {
		t.Fatalf("Unexpected value: %v (wanted: %v)", a.Val(), max)
	}

	a = a.Add(1)

	if a.Val() != 0 {
		t.Fatalf("Unexpected value: %v (wanted: %v)", a.Val(), 0)
	}
}

func TestSub(t *testing.T) {
	a := newCircular(42, max)

	a = a.Sub(42)

	if a.Val() != 0 {
		t.Fatalf("Unexpected value: %v (wanted: %v)", a.Val(), 0)
	}

	a = a.Sub(1)

	if a.Val() != max {
		t.Fatalf("Unexpected value: %v (wanted: %v)", a.Val(), max)
	}
}
