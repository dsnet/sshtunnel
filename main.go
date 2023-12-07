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
//		"AgentSocket": "/path/to/ssh_agent.sock",
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
	"crypto/sha256"
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
	"syscall"
	"time"

	"github.com/dsnet/golib/jsonfmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Version of the sshtunnel binary. May be set by linker when building.
var version string

type TunnelConfig struct {
	// LogFile is where the proxy daemon will direct its output log.
	// If the path is empty, then the server will output to os.Stderr.
	LogFile string `json:",omitempty"`

	// KeyFiles is a list of SSH private key files.
	KeyFiles []string

	// AgentSocket is the path to a unix socket from the SSH agent.
	// If the path is empty, then no agent is used.
	AgentSocket string `json:",omitempty"`

	// KnownHostFiles is a list of key database files for host public keys
	// in the OpenSSH known_hosts file format.
	KnownHostFiles []string

	// KeepAlive sets the keep alive settings for each SSH connection.
	// It is recommended that these values match the AliveInterval and
	// AliveCountMax parameters on the remote OpenSSH server.
	// If unset, then the default is an interval of 30s with 2 max counts.
	KeepAlive *KeepAliveConfig `json:",omitempty"`

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

		// KeepAlive is a tunnel-specific setting of the global KeepAlive.
		// If unspecified, it uses the global KeepAlive settings.
		KeepAlive *KeepAliveConfig `json:",omitempty"`
	}
}

type KeepAliveConfig struct {
	// Interval is the amount of time in seconds to wait before the
	// tunnel client will send a keep-alive message to ensure some minimum
	// traffic on the SSH connection.
	Interval uint

	// CountMax is the maximum number of consecutive failed responses to
	// keep-alive messages the client is willing to tolerate before considering
	// the SSH connection as dead.
	CountMax uint
}

func setupSSHAgent(socket string) ssh.AuthMethod {
	if len(socket) == 0 {
		return nil
	}

	conn, err := net.Dial("unix", socket)
	if err != nil {
		log.Fatalf("failed to dial SSH_AUTH_SOCK %s: %v\n", socket, err)
	}

	agentClient := agent.NewClient(conn)
	return ssh.PublicKeysCallback(agentClient.Signers)
}

func loadConfig(conf string) (tunns []tunnel, logger *log.Logger, closer func() error) {
	var logBuf bytes.Buffer
	logger = log.New(io.MultiWriter(os.Stderr, &logBuf), "", log.Ldate|log.Ltime|log.Lshortfile)

	var hash string
	if b, _ := ioutil.ReadFile(os.Args[0]); len(b) > 0 {
		hash = fmt.Sprintf("%x", sha256.Sum256(b))
	}

	// Load configuration file.
	var config TunnelConfig
	c, err := ioutil.ReadFile(conf)
	if err != nil {
		logger.Fatalf("unable to read config: %v", err)
	}
	if c, err = jsonfmt.Format(c, jsonfmt.Standardize()); err != nil {
		logger.Fatalf("unable to parse config: %v", err)
	}
	if err := json.Unmarshal(c, &config); err != nil {
		logger.Fatalf("unable to decode config: %v", err)
	}
	for _, t := range config.Tunnels {
		if config.KeepAlive == nil && t.KeepAlive == nil {
			config.KeepAlive = &KeepAliveConfig{Interval: 30, CountMax: 2}
			break
		}
	}

	// Print the configuration.
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "\t")
	enc.Encode(struct {
		TunnelConfig
		BinaryVersion string `json:",omitempty"`
		BinarySHA256  string `json:",omitempty"`
	}{config, version, hash})
	logger.Printf("loaded config:\n%s", b.String())

	// Setup the log output.
	if config.LogFile == "" {
		logger.SetOutput(os.Stderr)
		closer = func() error { return nil }
	} else {
		f, err := os.OpenFile(config.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0664)
		if err != nil {
			logger.Fatalf("error opening log file: %v", err)
		}
		f.Write(logBuf.Bytes()) // Write log output prior to this point
		logger.Printf("suppress stderr logging (redirected to %s)", f.Name())
		logger.SetOutput(f)
		closer = f.Close
	}

	var auth []ssh.AuthMethod

	// Parse all of the private keys.
	var keys []ssh.Signer
	for _, kf := range config.KeyFiles {
		b, err := ioutil.ReadFile(kf)
		if err != nil {
			logger.Fatalf("private key error: %v", err)
		}
		k, err := ssh.ParsePrivateKey(b)
		if err != nil {
			logger.Fatalf("private key error: %v", err)
		}
		keys = append(keys, k)
	}
	if len(keys) > 0 {
		auth = append(auth, ssh.PublicKeys(keys...))
	}

	agent := setupSSHAgent(config.AgentSocket)
	if agent != nil {
		auth = append(auth, agent)
	}

	if len(auth) == 0 {
		logger.Panic("no private keys and ssh-agent usable")
	}

	// Parse all of the host public keys.
	if len(config.KnownHostFiles) == 0 {
		logger.Fatal("no host public keys specified")
	}
	hostKeys, err := knownhosts.New(config.KnownHostFiles...)
	if err != nil {
		logger.Fatalf("public key error: %v", err)
	}

	// Parse all of the tunnels.
	for _, t := range config.Tunnels {
		var tunn tunnel
		tt := strings.Fields(t.Tunnel)
		if len(tt) != 3 {
			logger.Fatalf("invalid tunnel syntax: %s", t.Tunnel)
		}

		// Parse for the tunnel endpoints.
		switch tt[1] {
		case "->":
			tunn.bindAddr, tunn.mode, tunn.dialAddr = tt[0], '>', tt[2]
		case "<-":
			tunn.dialAddr, tunn.mode, tunn.bindAddr = tt[0], '<', tt[2]
		default:
			logger.Fatalf("invalid tunnel syntax: %s", t.Tunnel)
		}
		for _, addr := range []string{tunn.bindAddr, tunn.dialAddr} {
			if _, _, err := net.SplitHostPort(addr); err != nil {
				logger.Fatalf("invalid endpoint: %s", addr)
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
			logger.Fatalf("invalid server: %s", t.Server)
		}

		// Parse for the SSH user.
		if tunn.user == "" {
			u, err := user.Current()
			if err != nil {
				logger.Fatalf("unexpected error: %v", err)
			}
			tunn.user = u.Username
		}

		if t.KeepAlive == nil {
			tunn.keepAlive = *config.KeepAlive
		} else {
			tunn.keepAlive = *t.KeepAlive
		}
		tunn.retryInterval = 30 * time.Second
		tunn.auth = auth
		tunn.hostKeys = hostKeys
		tunn.log = logger
		tunns = append(tunns, tunn)
	}

	return tunns, logger, closer
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "\t%s CONFIG_PATH\n", os.Args[0])
		os.Exit(1)
	}
	tunns, logger, closer := loadConfig(os.Args[1])
	defer closer()

	// Setup signal handler to initiate shutdown.
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		sigc := make(chan os.Signal, 1)
		signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
		logger.Printf("received %v - initiating shutdown", <-sigc)
		cancel()
	}()

	// Start a bridge for each tunnel.
	var wg sync.WaitGroup
	logger.Printf("%s starting", path.Base(os.Args[0]))
	defer logger.Printf("%s shutdown", path.Base(os.Args[0]))
	for _, t := range tunns {
		wg.Add(1)
		go t.bindTunnel(ctx, &wg)
	}
	wg.Wait()
}
