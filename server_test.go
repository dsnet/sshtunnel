// Copyright 2017, The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE.md file.

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"reflect"
	"strconv"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// runServer starts an SSH server capable of handling forward and reverse
// TCP tunnels. This function blocks for the entire duration that the
// server is running and can be stopped by canceling the context.
//
// The server listens on the provided Listener and will present to clients
// a certificate from serverKey and will only accept users that match
// the provided clientKeys. Only users of the name "user%d" are allowed where
// the ID number is the index for the specified client key provided.
func runServer(t *testing.T, ctx context.Context, ln net.Listener, serverKey ssh.Signer, clientKeys ...ssh.PublicKey) {
	wg := new(sync.WaitGroup)
	defer wg.Wait()

	// Generate SSH server configuration.
	conf := ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			var uid int
			_, err := fmt.Sscanf(c.User(), "user%d", &uid)
			if err != nil || uid >= len(clientKeys) || !bytes.Equal(clientKeys[uid].Marshal(), pubKey.Marshal()) {
				return nil, fmt.Errorf("unknown public key for %q", c.User())
			}
			return nil, nil
		},
	}
	conf.AddHostKey(serverKey)

	// Handle every SSH client connection.
	for {
		tcpCn, err := ln.Accept()
		if err != nil {
			if !isDone(ctx) {
				t.Errorf("accept error: %v", err)
			}
			return
		}
		wg.Add(1)
		go handleServerConn(t, ctx, wg, tcpCn, &conf)
	}
}

// handleServerConn handles a single SSH connection.
func handleServerConn(t *testing.T, ctx context.Context, wg *sync.WaitGroup, tcpCn net.Conn, conf *ssh.ServerConfig) {
	defer wg.Done()
	go closeWhenDone(ctx, tcpCn)
	defer tcpCn.Close()

	sshCn, chans, reqs, err := ssh.NewServerConn(tcpCn, conf)
	if err != nil {
		t.Errorf("new connection error: %v", err)
		return
	}
	go closeWhenDone(ctx, sshCn)
	defer sshCn.Close()

	wg.Add(1)
	go handleServerChannels(t, ctx, wg, sshCn, chans)

	wg.Add(1)
	go handleServerRequests(t, ctx, wg, sshCn, reqs)

	if err := sshCn.Wait(); err != nil && err != io.EOF && !isDone(ctx) {
		t.Errorf("connection error: %v", err)
	}
}

// handleServerChannels handles new channels on a SSH connection.
// The client initiates a new channel when forwarding a TCP dial.
func handleServerChannels(t *testing.T, ctx context.Context, wg *sync.WaitGroup, sshCn ssh.Conn, chans <-chan ssh.NewChannel) {
	defer wg.Done()
	for nc := range chans {
		if nc.ChannelType() != "direct-tcpip" {
			nc.Reject(ssh.UnknownChannelType, "not implemented")
			continue
		}
		var args struct {
			DstHost string
			DstPort uint32
			SrcHost string
			SrcPort uint32
		}
		if !unmarshalData(nc.ExtraData(), &args) {
			nc.Reject(ssh.Prohibited, "invalid request")
			continue
		}

		// Open a connection for both sides.
		cn, err := net.Dial("tcp", net.JoinHostPort(args.DstHost, strconv.Itoa(int(args.DstPort))))
		if err != nil {
			nc.Reject(ssh.ConnectionFailed, err.Error())
			continue
		}
		ch, reqs, err := nc.Accept()
		if err != nil {
			t.Errorf("accept channel error: %v", err)
			cn.Close()
			continue
		}
		go ssh.DiscardRequests(reqs)

		wg.Add(1)
		go bidirCopyAndClose(t, ctx, wg, cn, ch)
	}
}

// handleServerRequests handles new requests on a SSH connection.
// The client initiates a new request for binding a local TCP socket.
func handleServerRequests(t *testing.T, ctx context.Context, wg *sync.WaitGroup, sshCn ssh.Conn, reqs <-chan *ssh.Request) {
	defer wg.Done()
	for r := range reqs {
		if !r.WantReply {
			continue
		}
		if r.Type != "tcpip-forward" {
			r.Reply(false, nil)
			continue
		}
		var args struct {
			Host string
			Port uint32
		}
		if !unmarshalData(r.Payload, &args) {
			r.Reply(false, nil)
			continue
		}
		ln, err := net.Listen("tcp", net.JoinHostPort(args.Host, strconv.Itoa(int(args.Port))))
		if err != nil {
			r.Reply(false, nil)
			continue
		}

		var resp struct{ Port uint32 }
		_, resp.Port = splitHostPort(ln.Addr().String())
		if err := r.Reply(true, marshalData(resp)); err != nil {
			t.Errorf("request reply error: %v", err)
			ln.Close()
			continue
		}

		wg.Add(1)
		go handleLocalListener(t, ctx, wg, sshCn, ln, args.Host)

	}
}

// handleLocalListener handles every new connection on the provided socket.
// All local connections will be forwarded to the client via a new channel.
func handleLocalListener(t *testing.T, ctx context.Context, wg *sync.WaitGroup, sshCn ssh.Conn, ln net.Listener, host string) {
	defer wg.Done()
	go closeWhenDone(ctx, ln)
	defer ln.Close()

	for {
		// Open a connection for both sides.
		cn, err := ln.Accept()
		if err != nil {
			if !isDone(ctx) {
				t.Errorf("accept error: %v", err)
			}
			return
		}
		var args struct {
			DstHost string
			DstPort uint32
			SrcHost string
			SrcPort uint32
		}
		args.DstHost, args.DstPort = splitHostPort(cn.LocalAddr().String())
		args.SrcHost, args.SrcPort = splitHostPort(cn.RemoteAddr().String())
		args.DstHost = host // This must match on client side!
		ch, reqs, err := sshCn.OpenChannel("forwarded-tcpip", marshalData(args))
		if err != nil {
			t.Errorf("open channel error: %v", err)
			cn.Close()
			continue
		}
		go ssh.DiscardRequests(reqs)

		wg.Add(1)
		go bidirCopyAndClose(t, ctx, wg, cn, ch)
	}
}

// bidirCopyAndClose performs a bi-directional copy on both connections
// until either side closes the connection or the context is canceled.
// This will close both connections before returning.
func bidirCopyAndClose(t *testing.T, ctx context.Context, wg *sync.WaitGroup, c1, c2 io.ReadWriteCloser) {
	defer wg.Done()
	go closeWhenDone(ctx, c1)
	go closeWhenDone(ctx, c2)
	defer c1.Close()
	defer c2.Close()

	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(c1, c2)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(c2, c1)
		errc <- err
	}()
	if err := <-errc; err != nil && err != io.EOF && !isDone(ctx) {
		t.Errorf("copy error: %v", err)
	}
}

// unmarshalData parses b into s, where s is a pointer to a struct.
// Only unexported fields of type uint32 or string are allowed.
func unmarshalData(b []byte, s interface{}) bool {
	v := reflect.ValueOf(s)
	if !v.IsValid() || v.Kind() != reflect.Ptr || v.Elem().Kind() != reflect.Struct {
		panic("destination must be pointer to struct")
	}
	v = v.Elem()
	for i := 0; i < v.NumField(); i++ {
		switch v.Type().Field(i).Type.Kind() {
		case reflect.Uint32:
			if len(b) < 4 {
				return false
			}
			v.Field(i).Set(reflect.ValueOf(binary.BigEndian.Uint32(b)))
			b = b[4:]
		case reflect.String:
			if len(b) < 4 {
				return false
			}
			n := binary.BigEndian.Uint32(b)
			b = b[4:]
			if uint64(len(b)) < uint64(n) {
				return false
			}
			v.Field(i).Set(reflect.ValueOf(string(b[:n])))
			b = b[n:]
		default:
			panic("invalid field type: " + v.Type().Field(i).Type.String())
		}
	}
	return len(b) == 0
}

// marshalData serializes s into b, where s is a struct (or a pointer to one).
// Only unexported fields of type uint32 or string are allowed.
func marshalData(s interface{}) (b []byte) {
	v := reflect.ValueOf(s)
	if v.IsValid() && v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if !v.IsValid() || v.Kind() != reflect.Struct {
		panic("source must be a struct")
	}
	var arr32 [4]byte
	for i := 0; i < v.NumField(); i++ {
		switch v.Type().Field(i).Type.Kind() {
		case reflect.Uint32:
			binary.BigEndian.PutUint32(arr32[:], uint32(v.Field(i).Uint()))
			b = append(b, arr32[:]...)
		case reflect.String:
			binary.BigEndian.PutUint32(arr32[:], uint32(v.Field(i).Len()))
			b = append(b, arr32[:]...)
			b = append(b, v.Field(i).String()...)
		default:
			panic("invalid field type: " + v.Type().Field(i).Type.String())
		}
	}
	return b

}

func splitHostPort(s string) (string, uint32) {
	host, port, _ := net.SplitHostPort(s)
	p, _ := strconv.Atoi(port)
	return host, uint32(p)
}

func closeWhenDone(ctx context.Context, c io.Closer) {
	<-ctx.Done()
	c.Close()
}

func isDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}
