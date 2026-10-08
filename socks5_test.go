package main

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// TestSOCKS5AssociateRejectedNoDial: UDP ASSOCIATE must be refused with
// RepCommandNotSupported (0x07) even when the associate target is dialable.
// The library default dials the target with plain net.Dial and raises a
// direct UDP relay — an unlogged route bypass — so a dialable target is
// exactly the case that must still come back rejected.
func TestSOCKS5AssociateRejectedNoDial(t *testing.T) {
	// A dialable associate target: before the fix the server would answer
	// 0x00 here and start relaying.
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("target listen: %v", err)
	}
	defer target.Close()
	tp := target.Addr().(*net.TCPAddr).Port

	s, err := NewSOCKS5Server("127.0.0.1:0", &Opener{})
	if err != nil {
		t.Fatalf("new socks5: %v", err)
	}
	s.Start()
	t.Cleanup(func() { _ = s.Shutdown(context.Background()) })

	conn, err := net.Dial("tcp", s.ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// greeting: no-auth
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("greeting write: %v", err)
	}
	greet := make([]byte, 2)
	if _, err := io.ReadFull(conn, greet); err != nil {
		t.Fatalf("greeting read: %v", err)
	}
	if greet[0] != 0x05 || greet[1] != 0x00 {
		t.Fatalf("greeting reply = %v, want [05 00]", greet)
	}

	// ASSOCIATE request: VER CMD=0x03 RSV ATYP=IPv4 127.0.0.1:<dialable port>
	req := []byte{0x05, 0x03, 0x00, 0x01, 127, 0, 0, 1, byte(tp >> 8), byte(tp)}
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("request write: %v", err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("request read: %v", err)
	}
	// statute.RepCommandNotSupported is 0x07 (RFC 1928 reply codes).
	if reply[1] != 0x07 {
		t.Fatalf("reply[1] = %#x, want 0x07 (command not supported)", reply[1])
	}
}

// TestSOCKS5ShutdownDrains: mirror of TestHTTPProxyShutdownDrains through a
// real SOCKS5 CONNECT relay. A held-open tunnel makes Shutdown with a 50 ms
// deadline return context.DeadlineExceeded only after the deadline; once the
// client closes, the library ends the relay and closes the logged upstream,
// so a repeat Shutdown drains and returns nil promptly.
func TestSOCKS5ShutdownDrains(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listener: %v", err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(c)
		}
	}()

	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatalf("NewRuleEngine: %v", err)
	}
	s, err := NewSOCKS5Server("127.0.0.1:0", &Opener{rules: rules, d: testDialer{}, family: FamilyBoth})
	if err != nil {
		t.Fatalf("NewSOCKS5Server: %v", err)
	}
	s.Start()
	t.Cleanup(func() { _ = s.Shutdown(context.Background()) })

	c, err := net.Dial("tcp", s.ln.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	greet := make([]byte, 2)
	if _, err := io.ReadFull(c, greet); err != nil || greet[1] != 0x00 {
		t.Fatalf("greeting reply: %v %x", err, greet)
	}

	// CONNECT to the echo server as an IPv4 literal: the empty rule set
	// routes the private address directly, no DNS involved.
	ep := echo.Addr().(*net.TCPAddr).Port
	req := []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, byte(ep >> 8), byte(ep)}
	if _, err := c.Write(req); err != nil {
		t.Fatalf("connect: %v", err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatalf("connect reply: %v", err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("connect reply code = %#x, want 0x00", reply[1])
	}
	// The relay is established and idle.
	c.SetDeadline(time.Time{})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = s.Shutdown(ctx)
	elapsed := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown with live relay = %v, want context.DeadlineExceeded", err)
	}
	if elapsed < 45*time.Millisecond {
		t.Fatalf("Shutdown returned after %v, want the full 50 ms deadline", elapsed)
	}

	// Closing the client ends the library relay, which closes the logged
	// upstream; the repeat Shutdown must then return nil promptly.
	c.Close()
	start = time.Now()
	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatalf("repeat Shutdown after client close = %v, want nil", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("repeat Shutdown took %v, want prompt drain", elapsed)
	}
}
