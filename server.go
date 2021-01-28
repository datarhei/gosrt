// Copyright 2020 FOSS GmbH. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package srt

// server is an implementation of the Server interface
type Server struct {
	// The address the SRT server should listen on, e.g. ":6001"
	Addr string

	Config *Config

	HandleConnect   func(cr ConnRequest) ConnType
	HandlePublish   func(conn Conn)
	HandleSubscribe func(conn Conn)

	Debug bool

	ln Listener
}

// ListenAndServe starts the SRT server
func (s *Server) ListenAndServe() error {
	if s.HandlePublish == nil {
		s.HandlePublish = s.defaultHandler
	}

	if s.HandleSubscribe == nil {
		s.HandleSubscribe = s.defaultHandler
	}

	if s.Config == nil {
		s.Config = &DefaultConfig
	}

	// Listen creates a server
	ln, err := Listen("udp", s.Addr, *s.Config)
	if err != nil {
		return err
	}

	defer ln.Close()

	s.ln = ln

	for {
		conn, mode, err := ln.Accept(s.HandleConnect)
		if err != nil {
			return err
		}

		if conn == nil {
			// rejected connection, ignore
			continue
		}

		if mode == PUBLISH {
			go s.HandlePublish(conn)
		} else {
			go s.HandleSubscribe(conn)
		}
	}
}

func (s *Server) Shutdown() {
	s.ln.Close()
}

func (s *Server) defaultHandler(conn Conn) {
	conn.Close()
}
