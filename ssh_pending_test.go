package main

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// The first channel is a working relay; subsequent opens remain unconfirmed.
func pendingSSH(t *testing.T) (*sshDialer, net.Conn, <-chan ssh.NewChannel) {
	t.Helper()
	pending := make(chan ssh.NewChannel, 1024)
	first := true
	addr, signer := startTestSSHServerWithChannelHandler(t, "", true, func(n ssh.NewChannel) error {
		if !first {
			pending <- n
			return nil
		}
		first = false
		c, reqs, err := n.Accept()
		if err == nil {
			go ssh.DiscardRequests(reqs)
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
		return err
	})
	d := &sshDialer{client: connectTestSSHClient(t, addr, signer)}
	t.Cleanup(d.stop)
	c, err := d.DialContext(context.Background(), "tcp", "192.0.2.1:80")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return d, c, pending
}

func cancelPendingSSH(t *testing.T, d *sshDialer, pending <-chan ssh.NewChannel, parent context.Context) ssh.NewChannel {
	t.Helper()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		c, err := d.DialContext(ctx, "tcp", "192.0.2.2:80")
		if c != nil {
			c.Close()
		}
		done <- err
	}()
	var n ssh.NewChannel
	select {
	case n = <-pending:
	case err := <-done:
		t.Fatalf("open rejected before cancellation: %v", err)
	case <-time.After(time.Second):
		t.Fatal("server did not receive open")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("dial: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("caller still waiting after cancellation")
	}
	return n
}

func checkSSHRelay(t *testing.T, c net.Conn) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		_, err := c.Write([]byte("alive"))
		if err == nil {
			b := make([]byte, 5)
			_, err = io.ReadFull(c, b)
			if err == nil && string(b) != "alive" {
				err = errors.New("corrupt relay")
			}
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("established relay stopped")
	}
}

func TestSSHPendingOpenBounded(t *testing.T) {
	d, live, pending := pendingSSH(t)
	for range 256 {
		cancelPendingSSH(t, d, pending, context.Background())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := d.DialContext(ctx, "tcp", "192.0.2.2:80")
	if err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("full pending pool must reject immediately, got %v", err)
	}
	select {
	case <-pending:
		t.Fatal("sent an open beyond the pending limit")
	default:
	}
	var limit *pendingOpenLimitError
	if !errors.As(err, &limit) || limit.limit != 256 {
		t.Fatalf("untyped overload: %v", err)
	}
	// Internal DNS retains its own capacity when all user slots are occupied.
	for range 32 {
		cancelPendingSSH(t, d, pending, ctxWithNoTrack(context.Background()))
	}
	for range 1000 {
		_, err := d.DialContext(ctxWithNoTrack(context.Background()), "tcp", "192.0.2.2:53")
		if !errors.As(err, &limit) || limit.limit != 32 {
			t.Fatalf("internal overload: %v", err)
		}
	}
	select {
	case <-pending:
		t.Fatal("overload sent another channel open")
	default:
	}
	if _, _, err := d.client.SendRequest("keepalive@openssh.com", true, nil); err != nil {
		t.Fatal(err)
	}
	checkSSHRelay(t, live)
}

func TestSSHPendingOpenStopAndReconnect(t *testing.T) {
	d, live, pending := pendingSSH(t)
	for range 256 {
		cancelPendingSSH(t, d, pending, context.Background())
	}
	checkSSHRelay(t, live)
	next, nextLive, nextPending := pendingSSH(t)
	old := d.client
	d.mu.Lock()
	d.client = next.client
	d.mu.Unlock()
	// Publishing another generation cannot create a new pool while old
	// operations have yet to return from their transport.
	_, err := d.DialContext(context.Background(), "tcp", "192.0.2.2:80")
	var limit *pendingOpenLimitError
	if !errors.As(err, &limit) {
		t.Fatalf("reconnect reset pending count: %v", err)
	}
	old.Close()
	waitPendingSSH(t, d, 0)
	n := cancelPendingSSH(t, d, nextPending, context.Background())
	c, reqs, err := n.Accept()
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-reqs:
	case <-time.After(time.Second):
		t.Fatal("late open not closed")
	}
	c.Close()
	waitPendingSSH(t, d, 0)
	checkSSHRelay(t, nextLive)
	cancelPendingSSH(t, d, nextPending, context.Background())
	d.stop()
	d.stop()
	stopped, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := d.waitStopped(stopped); err != nil {
		t.Fatalf("pending workers survived stop: %v", err)
	}
	waitPendingSSH(t, d, 0)
	if c, err := d.DialContext(context.Background(), "tcp", "192.0.2.2:80"); err == nil {
		c.Close()
		t.Fatal("stopped dialer accepted an open")
	}
	select {
	case <-nextPending:
		t.Fatal("open sent after stop")
	default:
	}
}

func waitPendingSSH(t *testing.T, d *sshDialer, want int) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		d.mu.Lock()
		n := len(d.pending)
		d.mu.Unlock()
		if n == want {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("pending opens=%d, want %d", n, want)
		case <-tick.C:
		}
	}
}

func TestSSHLateOpenClosed(t *testing.T) {
	d, live, pending := pendingSSH(t)
	n := cancelPendingSSH(t, d, pending, context.Background())
	c, requests, err := n.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	select {
	case _, ok := <-requests:
		if ok {
			t.Fatal("unexpected channel request")
		}
	case <-time.After(time.Second):
		t.Fatal("late successful channel not closed")
	}
	checkSSHRelay(t, live)
}

func TestSSHDialCancelResultRace(t *testing.T) {
	d, live, pending := pendingSSH(t)
	for range 50 {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan net.Conn, 1)
		go func() {
			c, err := d.DialContext(ctx, "tcp", "192.0.2.2:80")
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("dial: %v", err)
			}
			done <- c
		}()
		var n ssh.NewChannel
		select {
		case n = <-pending:
		case <-time.After(time.Second):
			t.Fatal("missing open")
		}
		go cancel()
		c, requests, err := n.Accept()
		if err != nil {
			t.Fatal(err)
		}
		select {
		case owned := <-done:
			if owned != nil {
				owned.Close()
			}
		case <-time.After(time.Second):
			t.Fatal("dial did not return")
		}
		select {
		case _, ok := <-requests:
			if ok {
				t.Fatal("unexpected channel request")
			}
		case <-time.After(time.Second):
			t.Fatal("unowned channel survived cancellation")
		}
		c.Close()
		cancel()
	}
	checkSSHRelay(t, live)
}
