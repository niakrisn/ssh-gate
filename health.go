package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

// probeInterval is how often the SSH server port is probed in the
// background; probeTimeout bounds a single probe dial. 30 s keeps a dead
// SSH endpoint from spamming the access log once per ten seconds.
const (
	probeInterval = 30 * time.Second
	probeTimeout  = 3 * time.Second
)

// processStartedAt is when this process began; /api/status reports the
// elapsed time as uptime_s.
var processStartedAt = time.Now()

// sshProbe is the latest result of probing the SSH server port.
type sshProbe struct {
	reachable bool
	rttMs     int64
	at        time.Time
}

// HealthServer provides /healthz, /readyz, the Web UI and /api/status.
type HealthServer struct {
	mu      sync.Mutex
	dialer  dialer
	ln      net.Listener
	srv     http.Server
	started atomic.Bool

	tracker *ConnTracker
	sshHost string
	sshPort int

	probeMu   sync.Mutex
	probe     sshProbe
	done      chan struct{}
	closeOnce sync.Once
}

// NewHealthServer creates a new health server with the Web UI,
// /api/connections and /api/status attached to the same mux. sshHost/
// sshPort is the tunnel endpoint, probed in the background for /api/status.
func NewHealthServer(listen, sshHost string, sshPort int, d dialer, tracker *ConnTracker) (*HealthServer, error) {
	h := &HealthServer{
		dialer:  d,
		tracker: tracker,
		sshHost: sshHost,
		sshPort: sshPort,
		done:    make(chan struct{}),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", h.healthHandler)
	mux.HandleFunc("/readyz", h.readyHandler)
	mux.HandleFunc("/api/connections", handleConnections(tracker))
	mux.HandleFunc("/api/status", h.statusHandler)
	mux.HandleFunc("/", handleUI)

	h.srv.Handler = mux

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}
	h.ln = ln

	return h, nil
}

// Start begins serving health checks and probing the SSH server port.
func (h *HealthServer) Start() {
	if !h.started.CompareAndSwap(false, true) {
		return
	}
	go h.probeLoop()
	go func() {
		log.Info().Str("listen", h.ln.Addr().String()).Msg("health server starting")
		if err := h.srv.Serve(h.ln); err != nil {
			log.Warn().Err(err).Msg("health server stopped")
		}
	}()
}

// Shutdown gracefully stops the health server and the probe loop.
func (h *HealthServer) Shutdown(ctx context.Context) error {
	err := h.srv.Shutdown(ctx)
	h.closeOnce.Do(func() { close(h.done) })
	return err
}

// probeLoop dials the SSH server port in the background and caches the
// result, so /api/status never blocks on the dial.
func (h *HealthServer) probeLoop() {
	h.runProbe()
	ticker := time.NewTicker(probeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-h.done:
			return
		case <-ticker.C:
			h.runProbe()
		}
	}
}

// runProbe dials the SSH server port (IPv4 only, like the tunnel itself)
// and stores the reachability result and RTT.
func (h *HealthServer) runProbe() {
	addr := net.JoinHostPort(h.sshHost, strconv.Itoa(h.sshPort))
	start := time.Now()
	conn, err := net.DialTimeout("tcp4", addr, probeTimeout)
	result := sshProbe{at: time.Now()}
	if err == nil {
		conn.Close()
		result.reachable = true
		result.rttMs = time.Since(start).Milliseconds()
	}
	h.probeMu.Lock()
	h.probe = result
	h.probeMu.Unlock()
}

func (h *HealthServer) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func (h *HealthServer) readyHandler(w http.ResponseWriter, r *http.Request) {
	if h.dialer.Connected() {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("SSH not connected"))
	}
}

// statusHandler serves GET /api/status: the SSH tunnel endpoint, the current
// session state, the latest port probe, the live tcp_info tunnel counters
// (null when unavailable) and active connection counts per protocol.
func (h *HealthServer) statusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	h.probeMu.Lock()
	probe := h.probe
	h.probeMu.Unlock()

	var tcp *tcpStats
	if p, ok := h.dialer.(tcpStatsProvider); ok {
		tcp = p.TunnelTCPStats()
	}

	active := map[string]int{}
	if h.tracker != nil {
		active = h.tracker.ActiveByProto()
	}
	total := 0
	for _, n := range active {
		total += n
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"ssh": map[string]any{
			"host":       h.sshHost,
			"port":       h.sshPort,
			"connected":  h.dialer.Connected(),
			"reachable":  probe.reachable,
			"rtt_ms":     probe.rttMs,
			"checked_at": probe.at.Unix(),
			"tcp":        tcp,
		},
		"active":       active,
		"active_total": total,
		"uptime_s":     int64(time.Since(processStartedAt).Seconds()),
	}); err != nil {
		// client went away; nothing to report.
	}
}
