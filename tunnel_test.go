// Copyright 2017, The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE.md file.

package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rsa"
	"encoding/binary"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type testLogger struct {
	*testing.T // Already has Fatalf method
}

func (t testLogger) Printf(f string, x ...interface{}) { t.Logf(f, x...) }

func TestTunnel(t *testing.T) {
	rootWG := new(sync.WaitGroup)
	defer rootWG.Wait()
	rootCtx, cancelAll := context.WithCancel(context.Background())
	defer cancelAll()

	// Open all of the TCP sockets needed for the test.
	tcpLn0 := openListener(t) // Start of the chain
	tcpLn1 := openListener(t) // Mid-point of the chain
	tcpLn2 := openListener(t) // End of the chain
	srvLn0 := openListener(t) // Socket for SSH server in reverse mode
	srvLn1 := openListener(t) // Socket for SSH server in forward mode

	tcpLn0.Close() // To be later binded by the reverse tunnel
	tcpLn1.Close() // To be later binded by the forward tunnel
	go closeWhenDone(rootCtx, tcpLn2)
	go closeWhenDone(rootCtx, srvLn0)
	go closeWhenDone(rootCtx, srvLn1)

	// Generate keys for both the servers and clients.
	clientPriv0, clientPub0 := generateKeys(t)
	clientPriv1, clientPub1 := generateKeys(t)
	serverPriv0, serverPub0 := generateKeys(t)
	serverPriv1, serverPub1 := generateKeys(t)

	// Start the SSH servers.
	rootWG.Add(2)
	go func() {
		defer rootWG.Done()
		runServer(t, rootCtx, srvLn0, serverPriv0, clientPub0, clientPub1)
	}()
	go func() {
		defer rootWG.Done()
		runServer(t, rootCtx, srvLn1, serverPriv1, clientPub0, clientPub1)
	}()

	wg := new(sync.WaitGroup)
	defer wg.Wait()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create the tunnel configurations.
	tn0 := tunnel{
		auth:     []ssh.AuthMethod{ssh.PublicKeys(clientPriv0)},
		hostKeys: ssh.FixedHostKey(serverPub0),
		mode:     '<', // Reverse tunnel
		user:     "user0",
		hostAddr: srvLn0.Addr().String(),
		bindAddr: tcpLn0.Addr().String(),
		dialAddr: tcpLn1.Addr().String(),
		log:      testLogger{t},
	}
	tn1 := tunnel{
		auth:     []ssh.AuthMethod{ssh.PublicKeys(clientPriv1)},
		hostKeys: ssh.FixedHostKey(serverPub1),
		mode:     '>', // Forward tunnel
		user:     "user1",
		hostAddr: srvLn1.Addr().String(),
		bindAddr: tcpLn1.Addr().String(),
		dialAddr: tcpLn2.Addr().String(),
		log:      testLogger{t},
	}

	// Start the SSH client tunnels.
	wg.Add(2)
	go tn0.bindTunnel(ctx, wg)
	go tn1.bindTunnel(ctx, wg)

	t.Log("test started")
	done := make(chan bool, 10)

	// Start all the transmitters.
	for i := 0; i < cap(done); i++ {
		i := i
		go func() {
			for {
				rnd := rand.New(rand.NewSource(int64(i)))
				hash := md5.New()
				size := uint32((1 << 10) + rnd.Intn(1<<20))
				buf4 := make([]byte, 4)
				binary.LittleEndian.PutUint32(buf4, size)

				cnStart, err := net.Dial("tcp", tcpLn0.Addr().String())
				if err != nil {
					time.Sleep(10 * time.Millisecond)
					continue
				}
				defer cnStart.Close()
				if _, err := cnStart.Write(buf4); err != nil {
					t.Errorf("write size error: %v", err)
					break
				}
				r := io.LimitReader(rnd, int64(size))
				w := io.MultiWriter(cnStart, hash)
				if _, err := io.Copy(w, r); err != nil {
					t.Errorf("copy error: %v", err)
					break
				}
				if _, err := cnStart.Write(hash.Sum(nil)); err != nil {
					t.Errorf("write hash error: %v", err)
					break
				}
				if err := cnStart.Close(); err != nil {
					t.Errorf("close error: %v", err)
					break
				}
				break
			}
		}()
	}

	// Start all the receivers.
	for i := 0; i < cap(done); i++ {
		go func() {
			for {
				hash := md5.New()
				buf4 := make([]byte, 4)

				cnEnd, err := tcpLn2.Accept()
				if err != nil {
					time.Sleep(10 * time.Millisecond)
					continue
				}
				defer cnEnd.Close()

				if _, err := io.ReadFull(cnEnd, buf4); err != nil {
					t.Errorf("read size error: %v", err)
					break
				}
				size := binary.LittleEndian.Uint32(buf4)
				r := io.LimitReader(cnEnd, int64(size))
				if _, err := io.Copy(hash, r); err != nil {
					t.Errorf("copy error: %v", err)
					break
				}
				wantHash, err := ioutil.ReadAll(cnEnd)
				if err != nil {
					t.Errorf("read hash error: %v", err)
					break
				}
				if err := cnEnd.Close(); err != nil {
					t.Errorf("close error: %v", err)
					break
				}

				if gotHash := hash.Sum(nil); !bytes.Equal(gotHash, wantHash) {
					t.Errorf("hash mismatch:\ngot  %x\nwant %x", gotHash, wantHash)
				}
				break
			}
			done <- true
		}()
	}

	for i := 0; i < cap(done); i++ {
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Errorf("timed out: %d remaining", cap(done)-i)
			return
		}
	}
	t.Log("test complete")
}

// generateKeys generates a random pair of SSH private and public keys.
func generateKeys(t *testing.T) (priv ssh.Signer, pub ssh.PublicKey) {
	rnd := rand.New(rand.NewSource(time.Now().Unix()))
	rsaKey, err := rsa.GenerateKey(rnd, 1024)
	if err != nil {
		t.Fatalf("unable to generate RSA key pair: %v", err)
	}
	priv, err = ssh.NewSignerFromKey(rsaKey)
	if err != nil {
		t.Fatalf("unable to generate signer: %v", err)
	}
	pub, err = ssh.NewPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("unable to generate public key: %v", err)
	}
	return priv, pub
}

func openListener(t *testing.T) net.Listener {
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("listen error: %v", err)
	}
	return ln
}
