//go:build darwin

package main

import (
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// assertKeepaliveIdle checks the accepted socket's idle period. macOS exposes
// it as the TCP_KEEPALIVE option; Go's SetKeepAlivePeriod writes it with
// seconds semantics and it reads back unchanged. Without the wrapper the
// socket carries the Go runtime default (15 s), so this assert is red
// pre-fix.
func assertKeepaliveIdle(t *testing.T, rc syscall.RawConn) {
	t.Helper()
	var idle int
	var getErr error
	if err := rc.Control(func(fd uintptr) {
		idle, getErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_KEEPALIVE)
	}); err != nil || getErr != nil {
		t.Fatalf("read TCP_KEEPALIVE: %v %v", err, getErr)
	}
	if idle != 30 {
		t.Fatalf("TCP_KEEPALIVE = %d, want 30", idle)
	}
}
