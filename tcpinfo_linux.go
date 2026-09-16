//go:build linux

package main

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// readTCPStats fetches SOL_TCP/TCP_INFO for the tunnel connection. The
// control function runs synchronously inside rc.Control; a closed fd fails
// the control call and yields nil. A half-open connection still reports
// counters — the last_*_recv fields expose the stall.
func readTCPStats(rc syscall.RawConn) *tcpStats {
	if rc == nil {
		return nil
	}

	var (
		info   *unix.TCPInfo
		ctlErr error
	)
	if err := rc.Control(func(fd uintptr) {
		var err error
		info, err = unix.GetsockoptTCPInfo(int(fd), unix.SOL_TCP, unix.TCP_INFO)
		ctlErr = err
	}); err != nil {
		return nil
	}
	if ctlErr != nil || info == nil {
		return nil
	}

	return &tcpStats{
		RTTMs:         float64(info.Rtt) / 1000,
		MinRTTMs:      float64(info.Min_rtt) / 1000,
		RTTVarMs:      float64(info.Rttvar) / 1000,
		TotalRetrans:  info.Total_retrans,
		Cwnd:          info.Snd_cwnd,
		BytesSent:     info.Bytes_sent,
		BytesReceived: info.Bytes_received,
		LastDataRecvS: float64(info.Last_data_recv) / 1e6,
		LastAckRecvS:  float64(info.Last_ack_recv) / 1e6,
	}
}
