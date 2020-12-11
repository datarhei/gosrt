package srt

import (
	"io"
	"bytes"
	"sync"
	"time"
)

type NonblockingWriter struct {
	dst io.Writer
	buf *bytes.Buffer
	lock sync.RWMutex
	done bool
}

func NewNonblockingWriter(wr io.Writer) *NonblockingWriter {
	u := &NonblockingWriter{
		dst: wr,
		buf: new(bytes.Buffer),
		done: false,
	}

	go u.writer()

	return u
}

func (u *NonblockingWriter) Write(p []byte) (int, error) {
	if u.done == true {
		return 0, io.EOF
	}

	u.lock.Lock()
	defer u.lock.Unlock()

	return u.buf.Write(p)
}

func (u *NonblockingWriter) Close() error {
	u.done = true

	return nil
}

func (u *NonblockingWriter) writer() {
	p := make([]byte, 2048)

	for {
		u.lock.RLock()
		n, err := u.buf.Read(p)
		u.lock.RUnlock()

		if n == 0 || err == io.EOF {
			if u.done == true {
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
