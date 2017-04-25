// Copyright 2017, The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE.md file.

package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

type tunnel struct {
	auth     []ssh.AuthMethod
	hostKeys ssh.HostKeyCallback
	mode     byte // '>' for forward, '<' for reverse
	user     string
	hostAddr string
	bindAddr string
	dialAddr string

	keepAlive KeepAliveConfig
}

func (t tunnel) String() string {
	var left, right string
	mode := "<?>"
	switch t.mode {
	case '>':
		left, mode, right = t.bindAddr, "->", t.dialAddr
	case '<':
		left, mode, right = t.dialAddr, "<-", t.bindAddr
	}
	return fmt.Sprintf("%s@%s | %s %s %s", t.user, t.hostAddr, left, mode, right)
}

var retryPeriod = 30 * time.Second

func bindTunnel(ctx context.Context, wg *sync.WaitGroup, tunn tunnel) {
	defer wg.Done()

	for {
		var once sync.Once // Only print errors once per session
		func() {
			// Connect to the server host via SSH.
			cl, err := ssh.Dial("tcp", tunn.hostAddr, &ssh.ClientConfig{
				User:            tunn.user,
				Auth:            tunn.auth,
				HostKeyCallback: tunn.hostKeys,
				Timeout:         5 * time.Second,
			})
			if err != nil {
				once.Do(func() { log.Printf("(%v) SSH dial error: %v", tunn, err) })
				return
			}
			wg.Add(1)
			go keepAliveMonitor(&once, wg, tunn, cl)
			defer cl.Close()

			// Attempt to bind to the inbound socket.
			var ln net.Listener
			switch tunn.mode {
			case '>':
				ln, err = net.Listen("tcp", tunn.bindAddr)
			case '<':
				ln, err = cl.Listen("tcp", tunn.bindAddr)
			}
			if err != nil {
				once.Do(func() { log.Printf("(%v) bind error: %v", tunn, err) })
				return
			}

			// The socket is binded. Make sure we close it eventually.
			bindCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			go func() {
				cl.Wait()
				cancel()
			}()
			go func() {
				<-bindCtx.Done()
				once.Do(func() {}) // Suppress future errors
				ln.Close()
			}()

			log.Printf("(%v) binded tunnel", tunn)
			defer log.Printf("(%v) collapsed tunnel", tunn)

			// Accept all incoming connections.
			for {
				cn1, err := ln.Accept()
				if err != nil {
					once.Do(func() { log.Printf("(%v) accept error: %v", tunn, err) })
					return
				}
				wg.Add(1)
				go dialTunnel(bindCtx, wg, tunn, cl, cn1)
			}
		}()

		select {
		case <-ctx.Done():
			return
		case <-time.After(retryPeriod):
			log.Printf("(%v) retrying...", tunn)
		}
	}
}

func dialTunnel(ctx context.Context, wg *sync.WaitGroup, tunn tunnel, client *ssh.Client, cn1 net.Conn) {
	defer wg.Done()

	// The inbound connection is established. Make sure we close it eventually.
	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-connCtx.Done()
		cn1.Close()
	}()

	// Establish the outbound connection.
	var cn2 net.Conn
	var err error
	switch tunn.mode {
	case '>':
		cn2, err = client.Dial("tcp", tunn.dialAddr)
	case '<':
		cn2, err = net.Dial("tcp", tunn.dialAddr)
	}
	if err != nil {
		log.Printf("(%v) dial error: %v", tunn, err)
		return
	}

	go func() {
		<-connCtx.Done()
		cn2.Close()
	}()

	log.Printf("(%v) connection established", tunn)
	defer log.Printf("(%v) connection closed", tunn)

	// Copy bytes from one connection to the other until one side closes.
	var once sync.Once
	var wg2 sync.WaitGroup
	wg2.Add(2)
	go func() {
		defer wg2.Done()
		defer cancel()
		if _, err := io.Copy(cn1, cn2); err != nil {
			once.Do(func() { log.Printf("(%v) connection error: %v", tunn, err) })
		}
		once.Do(func() {}) // Suppress future errors
	}()
	go func() {
		defer wg2.Done()
		defer cancel()
		if _, err := io.Copy(cn2, cn1); err != nil {
			once.Do(func() { log.Printf("(%v) connection error: %v", tunn, err) })
		}
		once.Do(func() {}) // Suppress future errors
	}()
	wg2.Wait()
}

// keepAliveMonitor periodically sends messages to invoke a response.
// If the server does not respond after some period of time,
// assume that the underlying net.Conn abruptly died.
func keepAliveMonitor(once *sync.Once, wg *sync.WaitGroup, tunn tunnel, client *ssh.Client) {
	defer wg.Done()
	if tunn.keepAlive.Interval == 0 || tunn.keepAlive.CountMax == 0 {
		return
	}

	// Detect when the SSH connection is closed.
	wait := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		wait <- client.Wait()
	}()

	// Repeatedly check if the remote server is still alive.
	var aliveCount int32
	ticker := time.NewTicker(time.Duration(tunn.keepAlive.Interval) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case err := <-wait:
			if err != nil && err != io.EOF {
				once.Do(func() { log.Printf("(%v) SSH error: %v", tunn, err) })
			}
			return
		case <-ticker.C:
			if n := atomic.AddInt32(&aliveCount, 1); n > int32(tunn.keepAlive.CountMax) {
				once.Do(func() { log.Printf("(%v) SSH keep-alive termination", tunn) })
				client.Close()
				return
			}
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
			if err == nil {
				atomic.StoreInt32(&aliveCount, 0)
			}
		}()
	}
}
