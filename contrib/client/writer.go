package main

import (
	"bytes"
	"io"
	"sync"
	"time"
)

// NonblockingWriter is a io.Writer and io.Closer that won't block
// any writes. If the underlying writer is blocking the data will be
// buffered until it's available again.
type NonblockingWriter interface {
	io.Writer
	io.Closer
}

// nonblockingWriter implements the NonblockingWriter interface
type nonblockingWriter struct {
	dst  io.Writer
	buf  *bytes.Buffer
	lock sync.RWMutex
	size int
	done bool
}

// NewNonblockingWriter return a new NonBlockingWriter with writer as the
// underlying writer. The size is the number of bytes to write to the
// underlying writer in one iteration. It written as fast as possible to
// the underlying writer. If there's no more data available to write
// a pause of 10 milliseconds will be done. There's currently no limit
// for the amount of data to be buffered. A call of the Close function
// will close this writer. The underlying writer will not be closed. In
// case there's an error while writing to the underlying writer, this
// will close itself.
func NewNonblockingWriter(writer io.Writer, size int) NonblockingWriter {
	u := &nonblockingWriter{
		dst:  writer,
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

// writer writes to the underlying writer in chunks read from
// the buffer. If the buffer is empty, a short pause will be made.
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
