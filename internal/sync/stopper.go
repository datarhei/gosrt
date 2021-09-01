// Copyright 2020 FOSS GmbH. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package sync provides synchronisation tools
package sync

import "sync"

type Stopper interface {
	// Check returns a channel that's closed when Stop() has been called.
	Check() <-chan struct{}

	// Stop will close the Check() channel and then wait until Done() has been called.
	Stop()

	// Done will release the waiting Stop() call. You should not call
	// this function before Stop() has been called.
	Done()
}

type stopper struct {
	channel chan struct{}
	wait    sync.WaitGroup
	stop    sync.Once
	done    sync.Once
}

// NewStopper returns a new Stopper. A Stopper can't be reused after
// Stop() has been called.
func NewStopper() Stopper {
	s := &stopper{
		channel: make(chan struct{}),
	}

	return s
}

func (s *stopper) Check() <-chan struct{} {
	return s.channel
}

func (s *stopper) Stop() {
	s.stop.Do(func() {
		s.wait.Add(1)
		close(s.channel)
		s.wait.Wait()
	})
}

func (s *stopper) Done() {
	s.done.Do(func() {
		s.wait.Done()
	})
}
