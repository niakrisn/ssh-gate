package main

import (
	"context"
	"net"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/rs/zerolog/log"
)

// HealthServer provides /healthz and /readyz endpoints.
type HealthServer struct {
	mu      sync.Mutex
	dialer  dialer
	ln      net.Listener
	srv     http.Server
	started atomic.Bool
}

// NewHealthServer creates a new health server.
func NewHealthServer(listen string, d dialer) (*HealthServer, error) {
	h := &HealthServer{
		dialer: d,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", h.healthHandler)
	mux.HandleFunc("/readyz", h.readyHandler)

	h.srv.Handler = mux

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}
	h.ln = ln

	return h, nil
}

// Start begins serving health checks.
func (h *HealthServer) Start() {
	if !h.started.CompareAndSwap(false, true) {
		return
	}
	go func() {
		log.Info().Str("listen", h.ln.Addr().String()).Msg("health server starting")
		if err := h.srv.Serve(h.ln); err != nil {
			log.Warn().Err(err).Msg("health server stopped")
		}
	}()
}

// Shutdown gracefully stops the health server.
func (h *HealthServer) Shutdown(ctx context.Context) error {
	return h.srv.Shutdown(ctx)
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
