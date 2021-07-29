// Copyright 2020 FOSS GmbH. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package srt

// circular represents a "circular number". This is a number that can be
// increased (or decreased) indefinitely while only using up a limited amount of
// memory. This feature comes with the limitiation in how distant two such
// number can be. Circular numbers have a maximum. The maximum distance is
// half the maximum value. If a number that has the maximum value is
// increased by 1, it becomes 0. If a number that has the value of 0 is
// decreased by 1, it becomes the maximum value. By comparing two circular
// numbers it is not possible to tell how often they wrapped. Therefore these
// two numbers must come from the same domain in order to make sense of the
// camparison.
type circular struct {
	max       uint32
	threshold uint32
	value     uint32
}

// newCircular returns a new circular number with the value of x and
// the maximum of max.
func newCircular(x, max uint32) circular {
	c := circular{
		value:     0,
		max:       max,
		threshold: max / 2,
	}

	if x > max {
		return c.Add(x)
	}

	c.value = x

	return c
}

// Val returns the current value of the number
func (a circular) Val() uint32 {
	return a.value
}

// Equals returns whether to circular numbers have the same value
func (a circular) Equals(b circular) bool {
	return a.value == b.value
}

// Distance returns the distance of to circular numbers
func (a circular) Distance(b circular) uint32 {
	if a.Equals(b) {
		return 0
	}

	var d uint32

	if a.value > b.value {
		d = a.value - b.value
	} else {
		d = b.value - a.value
	}

	if d >= a.threshold {
		d = a.max - d + 1
	}

	return d
}

// Lt returns whether the circular number is lower than the circular number b
func (a circular) Lt(b circular) bool {
	if a.Equals(b) {
		return false
	}

	var d uint32 = 0
	var altb bool = false

	if a.value > b.value {
		d = a.value - b.value
	} else {
		d = b.value - a.value
		altb = true
	}

	if d < a.threshold {
		return altb
	}

	return !altb
}

// Lte returns whether the circular number is lower than or equal to the circular number b
func (a circular) Lte(b circular) bool {
	if a.Equals(b) {
		return true
	}

	return a.Lt(b)
}

// Gt returns whether the circular number is greather than the circular number b
func (a circular) Gt(b circular) bool {
	if a.Equals(b) {
		return false
	}

	var d uint32 = 0
	var agtb bool = false

	if a.value > b.value {
		d = a.value - b.value
		agtb = true
	} else {
		d = b.value - a.value
	}

	if d < a.threshold {
		return agtb
	}

	return !agtb
}

// Gte returns whether the circular number is greather than or equal to the circular number b
func (a circular) Gte(b circular) bool {
	if a.Equals(b) {
		return true
	}

	return a.Gt(b)
}

// Inc returns a new circular number with a value that is increased by 1
func (a circular) Inc() circular {
	b := a

	if b.value == b.max {
		b.value = 0
	} else {
		b.value++
	}

	return b
}

// Add returns a new circular number with a value that is increased by b
func (a circular) Add(b uint32) circular {
	c := a
	x := c.max - c.value

	if b <= x {
		c.value += b
	} else {
		c.value = b - x - 1
	}

	return c
}

// Dec returns a new circular number with a value that is decreased by 1
func (a circular) Dec() circular {
	b := a

	if b.value == 0 {
		b.value = b.max
	} else {
		b.value--
	}

	return b
}

// Sub returns a new circular number with a value that is decreased by b
func (a circular) Sub(b uint32) circular {
	c := a

	if b <= c.value {
		c.value -= b
	} else {
		c.value = c.max - (b - c.value) + 1
	}

	return c
}
