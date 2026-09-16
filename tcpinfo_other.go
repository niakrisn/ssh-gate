//go:build !linux

package main

import "syscall"

// readTCPStats: SOL_TCP/TCP_INFO is a Linux option, so on other platforms
// (dev machines on macOS) the tunnel has no kernel counters to report.
func readTCPStats(rc syscall.RawConn) *tcpStats {
	return nil
}
