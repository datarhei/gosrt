// Copyright 2020 FOSS GmbH. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package srt

import (
	"bytes"
	"io"
	"sync"
	"time"
)

type NonblockingWriter interface {
	Write(p []byte) (int, error)
	Close() error
}

type nonblockingWriter struct {
	dst  io.Writer
	buf  *bytes.Buffer
	lock sync.RWMutex
	size int
	done bool
}

func NewNonblockingWriter(wr io.Writer, size int) NonblockingWriter {
	u := &nonblockingWriter{
		dst:  wr,
		buf:  new(bytes.Buffer),
		size: size,
		done: false,
	}

	if u.size <= 0 {
		u.size = 2048
	}

	go u.writer()

	return u
}

func (u *nonblockingWriter) Write(p []byte) (int, error) {
	if u.done {
		return 0, io.EOF
	}

	u.lock.Lock()
	defer u.lock.Unlock()

	return u.buf.Write(p)
}

func (u *nonblockingWriter) Close() error {
	u.done = true

	return nil
}

func (u *nonblockingWriter) writer() {
	p := make([]byte, u.size)

	for {
		u.lock.RLock()
		n, err := u.buf.Read(p)
		u.lock.RUnlock()

		if n == 0 || err == io.EOF {
			if u.done {
				break
			}

			time.Sleep(10 * time.Millisecond)
			continue
		}

		if _, err := u.dst.Write(p[:n]); err != nil {
			break
		}
	}

	u.done = true
}
