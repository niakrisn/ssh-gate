package main

import (
	"bufio"
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestKeepAliveListenerSetsKeepalive: accepted sockets must carry enabled
// SO_KEEPALIVE and an explicit 30 s idle period. Without the wrapper the
// socket keeps the Go runtime default (15 s idle), which the assertion on the
// idle period catches.
func TestKeepAliveListenerSetsKeepalive(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	kln := keepAliveListener{Listener: ln}

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := kln.Accept()
		if err == nil {
			accepted <- c
		}
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	var serverConn net.Conn
	select {
	case serverConn = <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("accept timed out")
	}
	defer serverConn.Close()

	tc, ok := serverConn.(*net.TCPConn)
	if !ok {
		t.Fatalf("accepted %T, want *net.TCPConn", serverConn)
	}

	rc, err := tc.SyscallConn()
	if err != nil {
		t.Fatalf("syscallconn: %v", err)
	}
	var on int
	var getErr error
	if err := rc.Control(func(fd uintptr) {
		on, getErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_KEEPALIVE)
	}); err != nil {
		t.Fatalf("control: %v", err)
	}
	if getErr != nil {
		t.Fatalf("getsockopt: %v", getErr)
	}
	// Enabled reads back as 1 on Linux, 8 on macOS (XNU so_options bit);
	// disabled reads 0 everywhere.
	if on == 0 {
		t.Fatalf("SO_KEEPALIVE = 0, want enabled")
	}
	// The idle-period option name differs per platform (Linux TCP_KEEPIDLE,
	// macOS TCP_KEEPALIVE), so the assert lives in a platform-specific file.
	assertKeepaliveIdle(t, rc)
}

// scriptedListener replays a script of Accept results (error → that error,
// net.Conn → that conn), then reports calls for assertions.
type scriptedListener struct {
	mu    sync.Mutex
	items []any
	calls int
}

func (l *scriptedListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls++
	if l.calls > len(l.items) {
		return nil, net.ErrClosed
	}
	switch v := l.items[l.calls-1].(type) {
	case error:
		return nil, v
	case net.Conn:
		return v, nil
	}
	panic("scriptedListener: unsupported script item")
}

func (l *scriptedListener) Close() error   { return nil }
func (l *scriptedListener) Addr() net.Addr { return &net.TCPAddr{} }

func (l *scriptedListener) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.calls
}

// TestResilientListenerRetriesTransient: transient accept errors (EMFILE
// storm) must be absorbed with backoff, not kill the accept loop; Close is
// idempotent (the socks5 library closes the listener itself); after Close,
// Accept reports net.ErrClosed without touching the underlying listener.
func TestResilientListenerRetriesTransient(t *testing.T) {
	conn, _ := net.Pipe()
	defer conn.Close()

	scripted := &scriptedListener{items: []any{
		syscall.EMFILE,
		syscall.EMFILE,
		conn,
	}}
	w := &resilientListener{Listener: scripted}

	start := time.Now()
	got, err := w.Accept()
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if got != conn {
		t.Fatalf("accept returned %v, want scripted conn", got)
	}
	if n := scripted.count(); n != 3 {
		t.Fatalf("underlying accepts = %d, want 3", n)
	}
	// Backoff slept 5 ms + 10 ms between the two retries.
	if elapsed < 10*time.Millisecond {
		t.Fatalf("elapsed = %v, want >= 10 ms (backoff)", elapsed)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("second close: %v, want nil (idempotent)", err)
	}

	before := scripted.count()
	if _, err := w.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("accept after close = %v, want net.ErrClosed", err)
	}
	if n := scripted.count(); n != before {
		t.Fatalf("accept after close hit underlying (%d -> %d)", before, n)
	}
}

// TestConnLimitRefusesOverLimit: past the limit a connection is closed at
// once, and a closed connection returns its slot.
func TestConnLimitRefusesOverLimit(t *testing.T) {
	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatalf("NewRuleEngine: %v", err)
	}
	s, err := NewHTTPProxyServer("127.0.0.1:0", newTestOpener(rules, testDialer{}))
	if err != nil {
		t.Fatalf("NewHTTPProxyServer: %v", err)
	}
	s.SetConnLimit(newConnLimiter(1))
	s.Start()
	t.Cleanup(func() { s.Shutdown(context.Background()) })
	addr := s.ln.Addr().String()

	// The first connection takes the only slot and holds it (no request).
	first, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial first: %v", err)
	}
	defer first.Close()

	second, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial second: %v", err)
	}
	defer second.Close()
	second.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := second.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("over-limit read err = %v, want the connection closed at once", err)
	}

	first.Close()
	// The slot comes back once the server sees the close; retry briefly.
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		c.SetDeadline(time.Now().Add(time.Second))
		c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
		line, err := bufio.NewReader(c).ReadString('\n')
		c.Close()
		if err == nil && strings.Contains(line, "400") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("slot not released after close: %q, %v", line, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestNewConnLimiterZeroIsUnlimited(t *testing.T) {
	if newConnLimiter(0) != nil || newConnLimiter(-1) != nil {
		t.Fatal("newConnLimiter(<=0) != nil, want nil (no limit)")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	if limitConns(ln, nil) != ln {
		t.Fatal("limitConns with nil limit wrapped the listener")
	}
}
