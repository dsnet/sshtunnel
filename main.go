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
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

type TunnelConfig struct {
	// LogFile is where the proxy daemon will direct its output log.
	// If the path is empty, then the server will output to os.Stderr.
	LogFile string

	// KeyFiles is a list of SSH private key files.
	KeyFiles []string

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
	tunns := loadConfig(os.Args[1])

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

func loadConfig(conf string) []tunnel {
	var logBuf bytes.Buffer
	log.SetFlags(log.Ldate | log.Ltime)
	log.SetOutput(io.MultiWriter(os.Stderr, &logBuf))

	// Load configuration file.
	var config TunnelConfig
	c, err := ioutil.ReadFile(conf)
	if err != nil {
		log.Fatalf("unable to read config: %v", err)
	}
	c = stripJSON(c)
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
	} else {
		f, err := os.OpenFile(config.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0664)
		if err != nil {
			log.Fatalf("error opening log file: %v", err)
		}
		f.Write(logBuf.Bytes()) // Write log output prior to this point
		log.Printf("suppress stderr logging (redirected to %s)", f.Name())
		log.SetOutput(f)
	}

	// Parse all of the keys.
	var keys []ssh.Signer
	if len(config.KeyFiles) == 0 {
		log.Fatal("no keys specified")
	}
	for _, kf := range config.KeyFiles {
		b, err := ioutil.ReadFile(kf)
		if err != nil {
			log.Fatalf("key error: %v", err)
		}
		k, err := ssh.ParsePrivateKey(b)
		if err != nil {
			log.Fatalf("key error: %v", err)
		}
		keys = append(keys, k)
	}
	auth := []ssh.AuthMethod{ssh.PublicKeys(keys...)}

	// Parse all of the tunnels.
	var tunns []tunnel
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
		tunns = append(tunns, tunn)
	}

	return tunns
}

// stripJSON strips superfluous components from the input string to make it
// compliant with the JSON specification.
// If the input is valid JSON, the output is also guaranteed to be valid.
func stripJSON(s []byte) []byte {
	// TODO(dsnet): This is very basic stripping of "//" comments that are
	// always preceded by whitespace.
	// It does not handle "//" comments that contain quotes after valid JSON.
	// It does not handle "/*" and "*/" style comments.
	// Handling those requires a legitimate parser.
	reComment := regexp.MustCompile(`(^\s*//)|(\s*//[^"]*$)`)
	ss := bytes.Split(s, []byte{'\n'})
	for i, s := range ss {
		if j := reComment.FindIndex(s); j != nil {
			ss[i] = s[:j[0]]
		}
	}
	s = bytes.Join(ss, []byte{'\n'})

	// Strip trailing commas from last element in objects and arrays.
	reComma := regexp.MustCompile(`,(?:\s*\n(?:\n|\s)*(?:\}|\]))`)
	for _, i := range reComma.FindAllIndex(s, -1) {
		s[i[0]] = ' ' // Convert comma to space
	}
	return s
}

func bindTunnel(ctx context.Context, wg *sync.WaitGroup, tunn tunnel) {
	defer wg.Done()

	for {
		func() {
			// Connect to the server host via SSH.
			cl, err := ssh.Dial("tcp", tunn.hostAddr, &ssh.ClientConfig{
				User: tunn.user, Auth: tunn.auth, Timeout: 5 * time.Second,
			})
			if err != nil {
				log.Printf("(%v) SSH error: %v", tunn, err)
				return
			}
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
				log.Printf("(%v) bind error: %v", tunn, err)
				return
			}

			// The socket is binded. Make sure we close it eventually.
			bindCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			go func() {
				if err := cl.Wait(); err != nil {
					log.Printf("(%v) SSH error: %v", tunn, err)
				}
				cancel()
			}()
			go func() {
				<-bindCtx.Done()
				ln.Close()
			}()

			log.Printf("(%v) binded tunnel", tunn)
			defer log.Printf("(%v) collapsed tunnel", tunn)

			// Accept all incoming connections.
			for {
				cn1, err := ln.Accept()
				if err != nil {
					select {
					case <-bindCtx.Done():
						// Don't print accept errors upon closing.
					default:
						log.Printf("(%v) accept error: %v", tunn, err)
					}
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
	}()
	go func() {
		defer wg2.Done()
		defer cancel()
		if _, err := io.Copy(cn2, cn1); err != nil {
			once.Do(func() { log.Printf("(%v) connection error: %v", tunn, err) })
		}
	}()
	wg2.Wait()
}
