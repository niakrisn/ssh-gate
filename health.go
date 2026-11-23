package main

import (
	"context"
	"encoding/json"
	"errors"
	stdlog "log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

// processStartedAt is when this process began; /api/status reports the
// elapsed time as uptime_s.
var processStartedAt = time.Now()

// HealthServer provides /healthz, /readyz, the Web UI and /api/status.
type HealthServer struct {
	dialer  dialer
	ln      net.Listener
	srv     http.Server
	started atomic.Bool
	ready   atomic.Bool

	tracker *ConnTracker
	// dnsStatus reports the tunnel resolvers; nil while the proxies are off.
	dnsStatus func() dnsStatus

	closeOnce sync.Once

	// allowedHosts are the Host header names (no port) the Web UI and the
	// API answer to; see uiGuard.
	allowedHosts map[string]bool
}

// NewHealthServer creates the health server and Web UI.
func NewHealthServer(listen string, d dialer, tracker *ConnTracker) (*HealthServer, error) {
	h := &HealthServer{
		dialer:  d,
		tracker: tracker,
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
	h.srv.ErrorLog = stdlog.New(httpLogWriter{}, "", 0)
	h.srv.ReadHeaderTimeout = 5 * time.Second
	h.srv.ReadTimeout = 5 * time.Second
	h.srv.WriteTimeout = 5 * time.Second
	h.srv.IdleTimeout = 30 * time.Second
	h.srv.MaxHeaderBytes = 64 << 10

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}
	h.ln = limitConns(ln, newConnLimiter(128))

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

// Start begins serving health and status endpoints.
func (h *HealthServer) Start() {
	if !h.started.CompareAndSwap(false, true) {
		return
	}
	h.ready.Store(true)
	go func() {
		log.Info().Str("listen", h.ln.Addr().String()).Msg("health server starting")
		if err := h.srv.Serve(h.ln); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			log.Warn().Err(err).Msg("health server stopped")
		}
	}()
}

func (h *HealthServer) StopAccept() error {
	var err error
	h.ready.Store(false)
	h.closeOnce.Do(func() { err = h.ln.Close() })
	return err
}

func (h *HealthServer) Drain(ctx context.Context) error {
	err := h.srv.Shutdown(ctx)
	if errors.Is(err, net.ErrClosed) {
		err = nil
	}
	return err
}

func (h *HealthServer) ForceClose() { _ = h.srv.Close() }

func (h *HealthServer) Shutdown(ctx context.Context) error {
	if err := h.StopAccept(); err != nil {
		return err
	}
	if err := h.Drain(ctx); err != nil {
		h.ForceClose()
		return err
	}
	return nil
}

func (h *HealthServer) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func (h *HealthServer) readyHandler(w http.ResponseWriter, r *http.Request) {
	if h.ready.Load() {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
		return
	}
	w.WriteHeader(http.StatusServiceUnavailable)
	w.Write([]byte("listeners not ready"))
}

func (h *HealthServer) SetReady(ready bool) { h.ready.Store(ready) }

// SetDNSStatus sets the source of the dns field of /api/status. Call it
// before Start.
func (h *HealthServer) SetDNSStatus(f func() dnsStatus) {
	h.dnsStatus = f
}

// statusHandler serves GET /api/status: the SSH tunnel endpoint, the current
// session state (state, plus the last connect error in a failure state),
// the latest port probe, the live tcp_info tunnel counters
// (null when unavailable), the tunnel resolvers (null when the proxies are
// off) and active connection counts per protocol.
func (h *HealthServer) statusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var serverViews []sshServerStatus
	if p, ok := h.dialer.(sshServersProvider); ok {
		serverViews = p.SSHServersStatus()
	}
	if serverViews == nil {
		serverViews = []sshServerStatus{}
	}
	eligible := false
	for _, server := range serverViews {
		eligible = eligible || server.Eligible
	}

	active := map[string]int{}
	if h.tracker != nil {
		active = h.tracker.ActiveByProto()
	}
	total := 0
	for _, n := range active {
		total += n
	}

	var dns *dnsStatus
	if h.dnsStatus != nil {
		s := h.dnsStatus()
		dns = &s
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"ssh": map[string]any{
			"connected": h.dialer.Connected(),
			"eligible":  eligible,
			"servers":   serverViews,
		},
		"dns":          dns,
		"active":       active,
		"active_total": total,
		"uptime_s":     int64(time.Since(processStartedAt).Seconds()),
	}); err != nil {
		// client went away; nothing to report.
	}
}
