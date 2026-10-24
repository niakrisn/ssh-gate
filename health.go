package main

import (
	"context"
	"encoding/json"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

// probeInterval is how often the SSH server port is probed in the
// background; probeTimeout bounds a single probe dial. Probes only refresh
// the cached /api/status reachability result and log nothing; 30 s keeps a
// dead SSH endpoint from being dialed every few seconds.
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
	// fromSession marks a result taken from the live session instead of
	// a dial; the RTT then comes from tcp_info at request time.
	fromSession bool
}

// HealthServer provides /healthz, /readyz, the Web UI and /api/status.
type HealthServer struct {
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

	// allowedHosts are the Host header names (no port) the Web UI and the
	// API answer to; see uiGuard.
	allowedHosts map[string]bool
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
		allowedHosts: map[string]bool{
			"localhost": true,
			"127.0.0.1": true,
			"::1":       true,
		},
	}
	// A specific listen host is reachable under its own name too; an
	// unspecified one (0.0.0.0, ::, empty) names no host.
	if host, _, err := net.SplitHostPort(listen); err == nil && host != "" {
		if ip := net.ParseIP(host); ip == nil || !ip.IsUnspecified() {
			h.allowedHosts[normalizeHost(host)] = true
		}
	}

	// Health probes come from orchestrators under any Host; only the UI
	// and the API, which show connection history, are guarded.
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", h.healthHandler)
	mux.HandleFunc("/readyz", h.readyHandler)
	mux.Handle("/api/connections", h.uiGuard(handleConnections(tracker)))
	mux.Handle("/api/status", h.uiGuard(http.HandlerFunc(h.statusHandler)))
	mux.Handle("/", h.uiGuard(http.HandlerFunc(handleUI)))

	h.srv.Handler = mux

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}
	h.ln = ln

	return h, nil
}

// AllowHosts adds Host header names (no port) the Web UI answers to, for
// access under a LAN name or address (UI_ALLOWED_HOSTS). Call before Start.
func (h *HealthServer) AllowHosts(hosts []string) {
	for _, host := range hosts {
		h.allowedHosts[normalizeHost(host)] = true
	}
}

// uiGuard rejects requests whose Host header is not an allowed name. The
// UI has no authentication and relies on a loopback bind, which DNS
// rebinding defeats: a page in a local browser points its own name at
// 127.0.0.1 and reads the API same-origin. Rebinding cannot change the
// Host header, so checking it closes that hole. It also sets headers that
// keep the pages from being framed or content-sniffed.
func (h *HealthServer) uiGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if hh, _, err := net.SplitHostPort(host); err == nil {
			host = hh
		}
		host = normalizeHost(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]"))
		if !h.allowedHosts[host] {
			log.Warn().Str("host", r.Host).Str("src", r.RemoteAddr).Msg("web ui: Host not allowed")
			http.Error(w, "Host not allowed; add it to UI_ALLOWED_HOSTS", http.StatusForbidden)
			return
		}
		hdr := w.Header()
		hdr.Set("X-Content-Type-Options", "nosniff")
		hdr.Set("X-Frame-Options", "DENY")
		hdr.Set("Referrer-Policy", "no-referrer")
		hdr.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// Start begins serving health checks and probing the SSH server port. An
// empty sshHost (not configured) has no port to probe.
func (h *HealthServer) Start() {
	if !h.started.CompareAndSwap(false, true) {
		return
	}
	if h.sshHost != "" {
		go h.probeLoop()
	}
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

// liveSessionStats returns the tunnel tcp_info when the SSH session is up
// and the dialer reports it, nil otherwise.
func (h *HealthServer) liveSessionStats() *tcpStats {
	if !h.dialer.Connected() {
		return nil
	}
	if p, ok := h.dialer.(tcpStatsProvider); ok {
		return p.TunnelTCPStats()
	}
	return nil
}

// runProbe dials the SSH server port (IPv4 only, like the tunnel itself)
// and stores the reachability result and RTT. While the session is up and
// reports tcp_info it does not dial: the live session already proves the
// server reachable and carries the RTT, and every probe is an
// unauthenticated connection that sshd logs as [preauth] and that
// fail2ban-style tools may count against the client address.
func (h *HealthServer) runProbe() {
	if h.liveSessionStats() != nil {
		h.probeMu.Lock()
		h.probe = sshProbe{reachable: true, at: time.Now(), fromSession: true}
		h.probeMu.Unlock()
		return
	}
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
		return
	}
	w.WriteHeader(http.StatusServiceUnavailable)
	if st := h.tunnelStatus(); st.State == stateNotConfigured {
		w.Write([]byte("not configured: SSH_HOST and SSH_USER are required"))
	} else {
		w.Write([]byte("SSH not connected: " + st.State))
	}
}

// tunnelStatus returns the dialer's tunnel state. A dialer without a state
// (test fakes) is connected or connecting by Connected().
func (h *HealthServer) tunnelStatus() tunnelStatus {
	if p, ok := h.dialer.(statusProvider); ok {
		if st := p.Status(); st.State != "" {
			return st
		}
	}
	if h.dialer.Connected() {
		return tunnelStatus{State: stateConnected}
	}
	return tunnelStatus{State: stateConnecting}
}

// statusHandler serves GET /api/status: the SSH tunnel endpoint, the current
// session state (state, plus the last connect error in a failure state),
// the latest port probe, the live tcp_info tunnel counters
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
	if probe.fromSession && tcp != nil {
		probe.rttMs = int64(math.Round(tcp.RTTMs))
	}

	active := map[string]int{}
	if h.tracker != nil {
		active = h.tracker.ActiveByProto()
	}
	total := 0
	for _, n := range active {
		total += n
	}

	// No probe has run yet, or none runs (not configured): report 0, not
	// the Unix time of the zero time.
	var checkedAt int64
	if !probe.at.IsZero() {
		checkedAt = probe.at.Unix()
	}

	st := h.tunnelStatus()
	errText := ""
	if st.Err != nil {
		errText = st.Err.Error()
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"ssh": map[string]any{
			"host":       h.sshHost,
			"port":       h.sshPort,
			"connected":  h.dialer.Connected(),
			"state":      st.State,
			"error":      errText,
			"reachable":  probe.reachable,
			"rtt_ms":     probe.rttMs,
			"checked_at": checkedAt,
			"tcp":        tcp,
		},
		"active":       active,
		"active_total": total,
		"uptime_s":     int64(time.Since(processStartedAt).Seconds()),
	}); err != nil {
		// client went away; nothing to report.
	}
}
