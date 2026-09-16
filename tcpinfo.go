package main

// tcpStats holds the live tcp_info counters of the SSH tunnel connection,
// read on demand for /api/status (fresh value on every poll, no background
// loop). nil (JSON null) means the platform lacks tcp_info or the tunnel
// connection is absent.
// RTT fields are float milliseconds: the tunnel path can be
// sub-millisecond, and integer ms would truncate it to 0.
type tcpStats struct {
	RTTMs         float64 `json:"rtt_ms"`
	MinRTTMs      float64 `json:"min_rtt_ms"`
	RTTVarMs      float64 `json:"rttvar_ms"`
	TotalRetrans  uint32  `json:"total_retrans"`
	Cwnd          uint32  `json:"cwnd"`
	BytesSent     uint64  `json:"bytes_sent"`
	BytesReceived uint64  `json:"bytes_received"`
	LastDataRecvS float64 `json:"last_data_recv_s"`
	LastAckRecvS  float64 `json:"last_ack_recv_s"`
}

// tcpStatsProvider is implemented by dialers that can report tcp_info for
// the tunnel connection; /api/status uses a type assertion, so mock dialers
// without it simply yield "tcp": null.
type tcpStatsProvider interface {
	TunnelTCPStats() *tcpStats
}
