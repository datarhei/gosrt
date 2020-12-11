// Copyright 2020 FOSS GmbH. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

/*
Package net provides an interface for network I/O using the
SRT protocol (https://github.com/Haivision/srt).

The package gives access to the basic interface provided
by the Dial, Listen, and Accept functions and the associated
Conn and Listener interfaces.

The Dial function connects to a server:

	conn, err := srt.Dial("udp", "golang.org:6000", srt.Config{
		StreamId: "..."
	})
	if err != nil {
		// handle error
	}

	buffer := make([]byte, 2048)

	for {
		n, err := conn.Read(buffer)
		if err != nil {
			// handle error
		}

		// ...
	}

	// ...

The Listen function creates servers:

	ln, err := srt.Listen("udp", ":6000")
	if err != nil {
		// handle error
	}

	for {
		conn, mode, err := ln.Accept(handleConnect)
		if err != nil {
			// handle error
		}

		if mode == srt.PUBLISH {
			go handlePublish(conn)
		} else {
			go handleSubscribe(conn)
		}
	}

Check out the Server type that wraps the Listen and Accept into a
convenient framework for your own SRT server.
*/
package srt


