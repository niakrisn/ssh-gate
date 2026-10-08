//go:build linux

package main

import (
	"syscall"
	"testing"
)

// assertKeepaliveIdle checks the accepted socket's idle period. On Linux
// SetKeepAlivePeriod maps to TCP_KEEPIDLE in seconds. Without the wrapper the
// socket carries the Go runtime default (15 s), so this assert is red
// pre-fix.
func assertKeepaliveIdle(t *testing.T, rc syscall.RawConn) {
	t.Helper()
	var idle int
	var getErr error
	if err := rc.Control(func(fd uintptr) {
		idle, getErr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_KEEPIDLE)
	}); err != nil || getErr != nil {
		t.Fatalf("read TCP_KEEPIDLE: %v %v", err, getErr)
	}
	if idle != 30 {
		t.Fatalf("TCP_KEEPIDLE = %d, want 30", idle)
	}
}
