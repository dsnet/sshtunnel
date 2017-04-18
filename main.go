// Copyright 2016, The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE.md file.

// sshtunnel is daemon for setting up forward and reverse SSH tunnels.
//
// The daemon is started by executing sshtunnel with the path to a JSON
// configuration file. The configuration takes the following form:
//
//	{
//		"KeyFiles": ["/path/to/key.priv"],
//		"KnownHostFiles": ["/path/to/known_hosts"],
//		"Tunnels": [{
//			// Forward tunnel (locally binded socket proxies to remote target).
//			"Tunnel": "bind_address:port -> dial_address:port",
//			"Server": "user@host:port",
//		}, {
//			// Reverse tunnel (remotely binded socket proxies to local target).
//			"Tunnel": "dial_address:port <- bind_address:port",
//			"Server": "user@host:port",
//		}],
//	}
//
// See the TunnelConfig struct for more details.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"os/user"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/dsnet/golib/jsonutil"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type TunnelConfig struct {
	// LogFile is where the proxy daemon will direct its output log.
	// If the path is empty, then the server will output to os.Stderr.
	LogFile string

	// KeyFiles is a list of SSH private key files.
	KeyFiles []string

	// KnownHostFiles is a list of key database files for host public keys
	// in the OpenSSH known_hosts file format.
	KnownHostFiles []string

	// Tunnels is a list of tunnels to establish.
	// The same set of SSH keys will be used to authenticate the
	// SSH connection for each server.
	Tunnels []struct {
		// Tunnel is a pair of host:port endpoints that can be configured
		// to either operate as a forward tunnel or a reverse tunnel.
		//
		// The syntax of a forward tunnel is:
		//	"bind_address:port -> dial_address:port"
		//
		// A forward tunnel opens a listening TCP socket on the
		// local side (at bind_address:port) and proxies all traffic to a
		// socket on the remote side (at dial_address:port).
		//
		// The syntax of a reverse tunnel is:
		//	"dial_address:port <- bind_address:port"
		//
		// A reverse tunnel opens a listening TCP socket on the
		// remote side (at bind_address:port) and proxies all traffic to a
		// socket on the local side (at dial_address:port).
		Tunnel string

		// Server is a remote SSH host. It has the following syntax:
		//	"user@host:port"
		//
		// If the user is missing, then it defaults to the current process user.
		// If the port is missing, then it defaults to 22.
		Server string
	}
}

type tunnel struct {
	auth     []ssh.AuthMethod
	hostKeys ssh.HostKeyCallback
	mode     byte // '>' for forward, '<' for reverse
	user     string
	hostAddr string
	bindAddr string
	dialAddr string
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

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "\t%s CONFIG_PATH\n", os.Args[0])
		os.Exit(1)
	}
	tunns, closer := loadConfig(os.Args[1])
	defer closer()

	// Setup signal handler to initiate shutdown.
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		sigc := make(chan os.Signal, 1)
		signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
		log.Printf("received %v - initiating shutdown", <-sigc)
		cancel()
	}()

	// Start a bridge for each tunnel.
	var wg sync.WaitGroup
	log.Printf("%s starting", path.Base(os.Args[0]))
	defer log.Printf("%s shutdown", path.Base(os.Args[0]))
	for _, t := range tunns {
		wg.Add(1)
		go bindTunnel(ctx, &wg, t)
	}
	wg.Wait()
}

func loadConfig(conf string) (tunns []tunnel, closer func() error) {
	var logBuf bytes.Buffer
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	log.SetOutput(io.MultiWriter(os.Stderr, &logBuf))

	// Load configuration file.
	var config TunnelConfig
	c, err := ioutil.ReadFile(conf)
	if err != nil {
		log.Fatalf("unable to read config: %v", err)
	}
	c, _ = jsonutil.Minify(c)
	if err := json.Unmarshal(c, &config); err != nil {
		log.Fatalf("unable to decode config: %v", err)
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "\t")
	enc.Encode(&config)
	log.Printf("loaded config:\n%s", b.String())

	// Setup the log output.
	if config.LogFile == "" {
		log.SetOutput(os.Stderr)
		closer = func() error { return nil }
	} else {
		f, err := os.OpenFile(config.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0664)
		if err != nil {
			log.Fatalf("error opening log file: %v", err)
		}
		f.Write(logBuf.Bytes()) // Write log output prior to this point
		log.Printf("suppress stderr logging (redirected to %s)", f.Name())
		log.SetOutput(f)
		closer = f.Close
	}

	// Parse all of the private keys.
	var keys []ssh.Signer
	if len(config.KeyFiles) == 0 {
		log.Fatal("no private keys specified")
	}
	for _, kf := range config.KeyFiles {
		b, err := ioutil.ReadFile(kf)
		if err != nil {
			log.Fatalf("private key error: %v", err)
		}
		k, err := ssh.ParsePrivateKey(b)
		if err != nil {
			log.Fatalf("private key error: %v", err)
		}
		keys = append(keys, k)
	}
	auth := []ssh.AuthMethod{ssh.PublicKeys(keys...)}

	// Parse all of the host public keys.
	if len(config.KnownHostFiles) == 0 {
		log.Fatal("no host public keys specified")
	}
	hostKeys, err := knownhosts.New(config.KnownHostFiles...)
	if err != nil {
		log.Fatalf("public key error: %v", err)
	}

	// Parse all of the tunnels.
	for _, t := range config.Tunnels {
		var tunn tunnel
		tt := strings.Fields(t.Tunnel)
		if len(tt) != 3 {
			log.Fatalf("invalid tunnel syntax: %s", t.Tunnel)
		}

		// Parse for the tunnel endpoints.
		switch tt[1] {
		case "->":
			tunn.bindAddr, tunn.mode, tunn.dialAddr = tt[0], '>', tt[2]
		case "<-":
			tunn.dialAddr, tunn.mode, tunn.bindAddr = tt[0], '<', tt[2]
		default:
			log.Fatalf("invalid tunnel syntax: %s", t.Tunnel)
		}
		for _, addr := range []string{tunn.bindAddr, tunn.dialAddr} {
			if _, _, err := net.SplitHostPort(addr); err != nil {
				log.Fatalf("invalid endpoint: %s", addr)
			}
		}

		// Parse for the SSH target host.
		tunn.hostAddr = t.Server
		if i := strings.IndexByte(t.Server, '@'); i >= 0 {
			tunn.user = t.Server[:i]
			tunn.hostAddr = t.Server[i+1:]
		}
		if _, _, err := net.SplitHostPort(tunn.hostAddr); err != nil {
			tunn.hostAddr = net.JoinHostPort(tunn.hostAddr, "22")
		}
		if _, _, err := net.SplitHostPort(tunn.hostAddr); err != nil {
			log.Fatalf("invalid server: %s", t.Server)
		}

		// Parse for the SSH user.
		if tunn.user == "" {
			u, err := user.Current()
			if err != nil {
				log.Fatalf("unexpected error: %v", err)
			}
			tunn.user = u.Username
		}

		tunn.auth = auth
		tunn.hostKeys = hostKeys
		tunns = append(tunns, tunn)
	}

	return tunns, closer
}

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
		case <-time.After(30 * time.Second):
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
	const (
		aliveInterval = 30 * time.Second
		aliveCountMax = 4
	)

	// Detect when the SSH connection is closed.
	wait := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		wait <- client.Wait()
	}()

	// Repeatedly check if the remote server is still alive.
	var aliveCount int32
	ticker := time.NewTicker(aliveInterval)
	defer ticker.Stop()
	for {
		select {
		case err := <-wait:
			if err != nil && err != io.EOF {
				once.Do(func() { log.Printf("(%v) SSH error: %v", tunn, err) })
			}
			return
		case <-ticker.C:
			if n := atomic.AddInt32(&aliveCount, 1); n > aliveCountMax {
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
