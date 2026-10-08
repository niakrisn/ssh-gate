package main

import (
	"errors"
	"net"
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
