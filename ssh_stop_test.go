package main

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestSSHStopDuringReconnect(t *testing.T) {
	backoff := make(chan struct{})
	var once sync.Once
	var calls atomic.Int64
	d := &sshDialer{cfg: sshDialerCfg{onStatus: func(st tunnelStatus) {
		if st.Retry > 0 {
			once.Do(func() { close(backoff) })
		}
	}}, connect: func(context.Context, sshDialerCfg) (*ssh.Client, string, syscall.RawConn, error) {
		calls.Add(1)
		return nil, "", nil, errors.New("test unavailable")
	}}
	done := make(chan struct{})
	go func() { d.monitor(); close(done) }()
	t.Cleanup(func() {
		d.stop()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("monitor retained after cleanup")
		}
	})
	<-backoff
	d.stop()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("stop did not interrupt reconnect delay")
	}
	if calls.Load() != 1 {
		t.Fatalf("dialed after stop: %d", calls.Load())
	}
}

func TestSSHStopDuringHandshake(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	hello, closed := make(chan struct{}), make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		accepted <- c
		if _, err := io.ReadFull(c, make([]byte, 1)); err == nil {
			close(hello)
		}
		io.Copy(io.Discard, c)
		close(closed)
	}()
	host, portString, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portString)
	d := &sshDialer{cfg: sshDialerCfg{host: host, port: port, user: "test", keyPath: writeTestKey(t), handshakeTimeout: time.Hour}}
	done := make(chan struct{})
	go func() { d.monitor(); close(done) }()
	peer := <-accepted
	t.Cleanup(func() {
		d.stop()
		peer.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("monitor retained after cleanup")
		}
	})
	<-hello
	d.stop()
	select {
	case <-closed:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("stop left SSH handshake socket open")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handshake monitor did not finish")
	}
	if d.Connected() {
		t.Fatal("client published after stop")
	}
}

func TestSSHStopWakesKeepalive(t *testing.T) {
	addr, signer := startTestSSHServer(t, "", true, true)
	c := connectTestSSHClient(t, addr, signer)
	d := &sshDialer{client: c, cfg: sshDialerCfg{keepalivePeriod: 2 * time.Second}}
	done := make(chan struct{})
	go func() { d.keepalive(d.lifetimeContext(), c); close(done) }()
	t.Cleanup(func() {
		d.stop()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("keepalive retained after cleanup")
		}
	})
	d.stop()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("stop waits for keepalive ticker")
	}
}

func TestSSHStopRejectsLateConnection(t *testing.T) {
	addr, signer := startTestSSHServer(t, "", true, true)
	c := connectTestSSHClient(t, addr, signer)
	connecting := make(chan struct{})
	d := &sshDialer{connect: func(ctx context.Context, _ sshDialerCfg) (*ssh.Client, string, syscall.RawConn, error) {
		close(connecting)
		<-ctx.Done()
		return c, "", nil, nil
	}}
	go d.monitor()
	<-connecting
	d.stop()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := d.waitStopped(ctx); err != nil {
		t.Fatal(err)
	}
	if d.Connected() {
		t.Fatal("late connection published after stop")
	}
	closed := make(chan struct{})
	go func() { c.Wait(); close(closed) }()
	select {
	case <-closed:
	case <-ctx.Done():
		t.Fatal("late successful transport not closed")
	}
}
