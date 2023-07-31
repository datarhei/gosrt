package net

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"strconv"
	"time"
)

func randInt63() (int64, error) {
	var b [8]byte
	_, err := rand.Read(b[:])
	if err != nil {
		return 0, err
	}

	return int64(uint64(b[0]&0b01111111)<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])), nil
}

// https://cs.opensource.google/go/go/+/refs/tags/go1.20.4:src/math/rand/rand.go;l=119
func randInt63n(n int64) (int64, error) {
	if n&(n-1) == 0 { // n is power of two, can mask
		r, err := randInt63()
		if err != nil {
			return 0, err
		}
		return r & (n - 1), nil
	}

	max := int64((1 << 63) - 1 - (1<<63)%uint64(n))

	v, err := randInt63()
	if err != nil {
		return 0, err
	}

	for v > max {
		v, err = randInt63()
		if err != nil {
			return 0, err
		}
	}

	return v % n, nil
}

// https://www.calhoun.io/creating-random-strings-in-go/
func randomString(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	b := make([]byte, length)
	for i := range b {
		j, err := randInt63n(int64(len(charset)))
		if err != nil {
			return "", err
		}
		b[i] = charset[int(j)]
	}

	return string(b), nil
}

type SYNCookie struct {
	secret1 string
	secret2 string
	daddr   string
	counter func() int64
}

func defaultCounter() int64 {
	return time.Now().Unix() >> 6
}

func NewSYNCookie(daddr string, counter func() int64) (*SYNCookie, error) {
	s := &SYNCookie{
		daddr:   daddr,
		counter: counter,
	}

	if s.counter == nil {
		s.counter = defaultCounter
	}

	var err error
	s.secret1, err = randomString(32)
	if err != nil {
		return nil, err
	}

	s.secret2, err = randomString(32)
	if err != nil {
		return nil, err
	}

	return s, err
}

func (s *SYNCookie) Get(saddr string) uint32 {
	return s.calculate(s.counter(), saddr)
}

func (s *SYNCookie) Verify(cookie uint32, saddr string) bool {
	counter := s.counter()

	if s.calculate(counter, saddr) == cookie {
		return true
	}

	if s.calculate(counter-1, saddr) == cookie {
		return true
	}

	return false
}

func (s *SYNCookie) calculate(counter int64, saddr string) uint32 {
	data := s.secret1 + s.daddr + saddr + s.secret2 + strconv.FormatInt(counter, 10)

	md5sum := md5.Sum([]byte(data))

	return binary.BigEndian.Uint32(md5sum[0:])
}
