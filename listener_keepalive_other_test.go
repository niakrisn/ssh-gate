//go:build !linux && !darwin

package main

import (
	"syscall"
	"testing"
)

// assertKeepaliveIdle is a no-op off Linux and Darwin: the idle-period
// socket option name and unit differ per platform, so only SO_KEEPALIVE is
// asserted there.
func assertKeepaliveIdle(t *testing.T, rc syscall.RawConn) {
	t.Helper()
}
