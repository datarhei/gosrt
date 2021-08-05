// Copyright 2020 FOSS GmbH. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package srt

import (
	"runtime"
	"strings"
	"time"
)

type Logger interface {
	HasTopic(topic string) bool
	Print(topic string, socketId uint32, skip int, message func() string)
	Listen() <-chan Log
	Close()
}

type logger struct {
	logQueue chan Log
	topics   map[string]bool
}

func NewLogger(topics []string) Logger {
	l := &logger{
		logQueue: make(chan Log, 1024),
		topics:   make(map[string]bool),
	}

	for _, topic := range topics {
		l.topics[topic] = true
	}

	return l
}

func (l *logger) HasTopic(topic string) bool {
	if len(l.topics) == 0 {
		return false
	}

	if ok := l.topics[topic]; ok {
		return true
	}

	len := len(topic)

	for {
		i := strings.LastIndexByte(topic[:len], ':')
		if i == -1 {
			break
		}

		len = i

		if ok := l.topics[topic[:len]]; !ok {
			continue
		}

		return true
	}

	return false
}

func (l *logger) Print(topic string, socketId uint32, skip int, message func() string) {
	if !l.HasTopic(topic) {
		return
	}

	_, file, line, _ := runtime.Caller(skip)

	msg := Log{
		Time:     time.Now(),
		SocketId: socketId,
		Topic:    topic,
		Message:  message(),
		File:     file,
		Line:     line,
	}

	// Write to log queue, but don't block if it's full
	select {
	case l.logQueue <- msg:
	default:
	}
}

func (l *logger) Listen() <-chan Log {
	return l.logQueue
}

func (l *logger) Close() {
	close(l.logQueue)
}

type Log struct {
	Time     time.Time
	SocketId uint32
	Topic    string
	Message  string
	File     string
	Line     int
}
