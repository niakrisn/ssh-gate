package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"github.com/rs/zerolog/log"
)

func checkServerHTTPS(ctx context.Context, pool *sshTransportPool, rules *RuleEngine, target string) error {
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return fmt.Errorf("invalid HTTPS health URL %q", target)
	}
	if !pool.Connected() {
		return errors.New("no connected SSH transport")
	}

	host := normalizeHost(u.Hostname())
	ctx = contextWithDialer(ctx, pool)
	addrs, err := rules.dns.resolveTunnelFresh(ctx, host)
	if err != nil {
		return fmt.Errorf("resolve probe host %s: %w", host, err)
	}
	var ip netip.Addr
	for _, addr := range addrs {
		if !rules.isPrivate(addr) {
			ip = addr.Unmap()
			break
		}
	}
	if !ip.IsValid() {
		return fmt.Errorf("probe host %s has no public address", host)
	}

	port := u.Port()
	if port == "" {
		port = "443"
	}
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 3 * time.Second,
		DisableKeepAlives:   true,
		DialContext: func(dialCtx context.Context, network, _ string) (net.Conn, error) {
			dialCtx = ctxWithNoTrack(dialCtx)
			return pool.DialContext(dialCtx, network, net.JoinHostPort(ip.String(), port))
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return fmt.Errorf("create health request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTPS request: %w", err)
	}
	_, readErr := io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	closeErr := resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("health URL returned HTTP %d", resp.StatusCode)
	}
	if readErr != nil {
		return fmt.Errorf("read health response: %w", readErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close health response: %w", closeErr)
	}
	return nil
}

func (p *sshTransportPool) recordHealthProbe(err error) {
	if p.health == nil {
		return
	}
	if errors.Is(err, context.Canceled) {
		return
	}
	var quotaErr *pendingOpenLimitError
	if errors.As(err, &quotaErr) {
		log.Warn().Str("server_id", p.id).Err(err).Msg("SSH server HTTPS health check skipped because service open quota is full")
		return
	}
	p.health.mu.Lock()
	wasAllowed := p.health.probeAllowed
	p.health.probeCheckedAt = time.Now()
	if err != nil {
		p.health.probeLastError = err.Error()
	} else {
		p.health.probeLastError = ""
	}
	p.health.mu.Unlock()
	p.health.recordProbe(err == nil)
	p.health.mu.Lock()
	allowed := p.health.probeAllowed
	p.health.mu.Unlock()
	if err != nil {
		log.Warn().Str("server_id", p.id).Err(err).Msg("SSH server HTTPS health check failed")
		if wasAllowed && !allowed {
			log.Warn().Str("server_id", p.id).Msg("SSH server excluded after failed HTTPS health checks")
		}
		return
	}
	if allowed && !wasAllowed {
		log.Info().Str("server_id", p.id).Msg("SSH server admitted after successful HTTPS health checks")
	}
}

type sshServerStatus struct {
	ID             string                `json:"id"`
	Address        string                `json:"address"`
	State          string                `json:"state"`
	Reason         string                `json:"reason"`
	CheckedAt      int64                 `json:"checked_at"`
	Eligible       bool                  `json:"eligible"`
	ActiveChannels int64                 `json:"active_channels"`
	Limits         serverLimitStatus     `json:"limits"`
	Health         serverHealthStatus    `json:"health"`
	Transports     []transportStatusView `json:"transports"`
}

type serverLimitStatus struct {
	ClientTunnels      int `json:"client_tunnels"`
	ClientTunnelsInUse int `json:"client_tunnels_in_use"`
	PendingOpens       int `json:"pending_opens"`
	PendingOpensInUse  int `json:"pending_opens_in_use"`
	ServiceOpens       int `json:"service_opens"`
	ServiceOpensInUse  int `json:"service_opens_in_use"`
}

type serverHealthStatus struct {
	URL           string `json:"url"`
	Failures      int    `json:"failures"`
	Successes     int    `json:"successes"`
	MaxFailures   int    `json:"max_failures"`
	SuccessLimit  int    `json:"success_limit"`
	LastError     string `json:"last_error"`
	ExcludedUntil int64  `json:"excluded_until"`
}

type transportStatusView struct {
	Slot           int       `json:"slot"`
	State          string    `json:"state"`
	Connected      bool      `json:"connected"`
	Error          string    `json:"error"`
	Attempt        int       `json:"attempt"`
	RetryMs        int64     `json:"retry_ms"`
	ActiveChannels int64     `json:"active_channels"`
	TCP            *tcpStats `json:"tcp"`
}

func (p *sshTransportPool) status() sshServerStatus {
	now := time.Now()
	status := sshServerStatus{
		ID:         p.id,
		Address:    net.JoinHostPort(p.host, fmt.Sprint(p.port)),
		State:      "checking",
		Transports: make([]transportStatusView, 0, len(p.slots)),
	}
	if p.user != "" {
		status.Address = p.user + "@" + status.Address
	}
	connected := false
	transportReason := ""
	for _, slot := range p.slots {
		view := transportStatusView{Slot: slot.index, State: stateConnecting, Connected: slot.dialer != nil && slot.dialer.Connected(), ActiveChannels: slot.load.Load()}
		if view.Connected {
			connected = true
		}
		if provider, ok := slot.dialer.(statusProvider); ok {
			st := provider.Status()
			view.State = st.State
			view.Attempt = st.Attempt
			view.RetryMs = st.Retry.Milliseconds()
			if st.Err != nil {
				view.Error = st.Err.Error()
				if transportReason == "" {
					transportReason = view.Error
				}
			}
		}
		if provider, ok := slot.dialer.(tcpStatsProvider); ok {
			view.TCP = provider.TunnelTCPStats()
		}
		status.ActiveChannels += view.ActiveChannels
		status.Transports = append(status.Transports, view)
	}
	status.Eligible = p.eligible()
	switch {
	case status.Eligible:
		status.State = "healthy"
	case !connected:
		status.State = "disconnected"
		status.Reason = "no connected SSH transport"
		if transportReason != "" {
			status.Reason = transportReason
		}
	default:
		status.State = "checking"
		status.Reason = "waiting for successful HTTPS health checks"
	}
	if p.health != nil {
		p.health.mu.Lock()
		status.Health = serverHealthStatus{
			URL:      p.healthURL,
			Failures: p.health.probeFailures, Successes: p.health.probeSuccesses,
			MaxFailures: p.health.probeMaxFailures, SuccessLimit: p.health.probeSuccessLimit,
			LastError: p.health.probeLastError,
		}
		if !p.health.probeCheckedAt.IsZero() {
			status.CheckedAt = p.health.probeCheckedAt.Unix()
		}
		if !p.health.excludedUntil.IsZero() {
			status.Health.ExcludedUntil = p.health.excludedUntil.Unix()
			if now.Before(p.health.excludedUntil) {
				status.State = "excluded"
				status.Reason = "passive failure threshold reached"
			}
		}
		if p.health.probeFailures >= p.health.probeMaxFailures && !p.health.probeAllowed && status.State != "excluded" {
			status.State = "excluded"
			status.Reason = "HTTPS health check failure threshold reached"
		}
		if !p.health.probeAllowed && p.health.probeLastError != "" && status.State != "excluded" {
			status.Reason = p.health.probeLastError
		}
		p.health.mu.Unlock()
	}
	if p.quota != nil {
		status.Limits = serverLimitStatus{
			ClientTunnels: cap(p.quota.clientTunnels), ClientTunnelsInUse: len(p.quota.clientTunnels),
			PendingOpens: cap(p.quota.pendingOpens), PendingOpensInUse: len(p.quota.pendingOpens),
			ServiceOpens: cap(p.quota.serviceOpens), ServiceOpensInUse: len(p.quota.serviceOpens),
		}
	}
	return status
}
