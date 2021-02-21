package srt

type circular struct {
	max       uint32
	threshold uint32
	value     uint32
}

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

func (a circular) Val() uint32 {
	return a.value
}

func (a circular) Equals(b circular) bool {
	return a.value == b.value
}

func (a circular) Distance(b circular) uint32 {
	if a.Equals(b) == true {
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

func (a circular) Lt(b circular) bool {
	if a.Equals(b) == true {
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

func (a circular) Lte(b circular) bool {
	if a.Equals(b) == true {
		return true
	}

	return a.Lt(b)
}

func (a circular) Gt(b circular) bool {
	if a.Equals(b) == true {
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

func (a circular) Gte(b circular) bool {
	if a.Equals(b) == true {
		return true
	}

	return a.Gt(b)
}

func (a circular) Inc() circular {
	b := a

	if b.value == b.max {
		b.value = 0
	} else {
		b.value++
	}

	return b
}

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

func (a circular) Dec() circular {
	b := a

	if b.value == 0 {
		b.value = b.max
	} else {
		b.value--
	}

	return b
}

func (a circular) Sub(b uint32) circular {
	c := a

	if b <= c.value {
		c.value -= b
	} else {
		c.value = c.max - (b - c.value) + 1
	}

	return c
}
