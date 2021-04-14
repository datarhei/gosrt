// Copyright 2020 FOSS GmbH. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package sync

const (
	stopperStop int = 1
	stopperDone int = 2
)

type Stopper interface {
	Check() <-chan int
	Stop()
	Done()
}

type stopper struct {
	c chan int
	d chan int
}

func NewStopper() Stopper {
	s := &stopper{
		c: make(chan int),
		d: make(chan int),
	}

	return s
}

func (s *stopper) Check() <-chan int {
	return s.c
}

func (s *stopper) Stop() {
	s.c <- stopperStop

	for n := range s.d {
		if n == stopperDone {
			return
		}
	}
}

func (s *stopper) Done() {
	s.d <- stopperDone
}
