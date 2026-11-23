package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
)

type transportSlot struct {
	dialer dialer
	index  int
	load   atomic.Int64
}

type sshTransportPool struct {
	id        string
	host      string
	port      int
	user      string
	healthURL string
	// pickMu serializes "read the slot loads, book one open on the winner";
	// without it a burst reads the same loads and books the same idle slot.
	pickMu sync.Mutex
	slots  []*transportSlot
	quota  *serverQuota
	health *serverHealth
}

type serverHealth struct {
	mu                sync.Mutex
	failures          []time.Time
	excludedUntil     time.Time
	maxFails          int
	failTimeout       time.Duration
	unhealthyPeriod   time.Duration
	probeFailures     int
	probeSuccesses    int
	probeMaxFailures  int
	probeSuccessLimit int
	probeAllowed      bool
	probeCheckedAt    time.Time
	probeLastError    string
}

func newServerHealth(maxFails int, failTimeout, unhealthyPeriod time.Duration, probeMaxFailures, probeSuccessLimit int) *serverHealth {
	return &serverHealth{maxFails: maxFails, failTimeout: failTimeout, unhealthyPeriod: unhealthyPeriod, probeMaxFailures: probeMaxFailures, probeSuccessLimit: probeSuccessLimit}
}
func (h *serverHealth) eligible(now time.Time) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.probeAllowed {
		return false
	}
	if now.Before(h.excludedUntil) {
		return false
	}
	if !h.excludedUntil.IsZero() {
		h.excludedUntil = time.Time{}
		h.failures = nil
	}
	return true
}
func (h *serverHealth) recordProbe(success bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if success {
		h.probeFailures = 0
		if h.probeSuccesses < h.probeSuccessLimit {
			h.probeSuccesses++
		}
		if h.probeSuccesses >= h.probeSuccessLimit {
			h.probeAllowed = true
		}
		return
	}
	h.probeSuccesses = 0
	h.probeFailures++
	if h.probeFailures >= h.probeMaxFailures {
		h.probeAllowed = false
	}
}
func (h *serverHealth) confirmedFailure(now time.Time) (bool, int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	cutoff := now.Add(-h.failTimeout)
	kept := h.failures[:0]
	for _, at := range h.failures {
		if !at.Before(cutoff) {
			kept = append(kept, at)
		}
	}
	h.failures = append(kept, now)
	if len(h.failures) < h.maxFails {
		return false, len(h.failures)
	}
	h.excludedUntil = now.Add(h.unhealthyPeriod)
	h.failures = nil
	h.probeAllowed = false
	h.probeSuccesses = 0
	return true, h.maxFails
}
func (p *sshTransportPool) transportFailed(slot int) {
	if p.health == nil {
		return
	}
	excluded, recent := p.health.confirmedFailure(time.Now())
	if !p.Connected() {
		p.health.requireProbe()
	}
	event := log.Warn().Str("server_id", p.id).Int("slot", slot).Int("recent_failures", recent)
	if excluded {
		event.Dur("unhealthy_for", p.health.unhealthyPeriod).Msg("SSH server excluded after confirmed transport failures")
		return
	}
	event.Msg("SSH transport lost")
}

func (h *serverHealth) requireProbe() {
	h.mu.Lock()
	h.probeAllowed = false
	h.probeSuccesses = 0
	h.mu.Unlock()
}
func (p *sshTransportPool) eligible() bool {
	return p.Connected() && (p.health == nil || p.health.eligible(time.Now()))
}

type serverQuota struct {
	clientTunnels chan struct{}
	pendingOpens  chan struct{}
	serviceOpens  chan struct{}
}

func newServerQuota(tunnels, opens, serviceOpens int) *serverQuota {
	return &serverQuota{clientTunnels: make(chan struct{}, tunnels), pendingOpens: make(chan struct{}, opens), serviceOpens: make(chan struct{}, serviceOpens)}
}
func (q *serverQuota) reserveTunnel() (func(), error) {
	select {
	case q.clientTunnels <- struct{}{}:
		var released atomic.Bool
		return func() {
			if released.CompareAndSwap(false, true) {
				<-q.clientTunnels
			}
		}, nil
	default:
		return nil, &clientTunnelLimitError{limit: cap(q.clientTunnels)}
	}
}
func (q *serverQuota) acquireOpen(service bool) (chan struct{}, error) {
	pool := q.pendingOpens
	if service {
		pool = q.serviceOpens
	}
	select {
	case pool <- struct{}{}:
		return pool, nil
	default:
		return nil, &pendingOpenLimitError{limit: cap(pool)}
	}
}

type clientTunnelLimitError struct{ limit int }

func (e *clientTunnelLimitError) Error() string {
	return fmt.Sprintf("SSH client tunnel limit reached (%d)", e.limit)
}

func newSSHTransportPool(dialers ...dialer) *sshTransportPool {
	p := &sshTransportPool{slots: make([]*transportSlot, 0, len(dialers))}
	for _, d := range dialers {
		p.slots = append(p.slots, &transportSlot{dialer: d})
	}
	return p
}

// DialContext opens a channel on the least loaded live transport. One open can
// fail on a slot that still reports Connected() - the transport dies between
// the check and the channel open - so the next live slot of the same server is
// tried before the request fails. A server-wide limit or an explicit failure
// to connect to the destination stops retries on this IP.
func (p *sshTransportPool) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	var skipped []*transportSlot
	var last error
	for {
		slot := p.reserve(skipped)
		if slot == nil {
			if last != nil {
				return nil, last
			}
			return nil, errors.New("no connected SSH transport")
		}
		conn, err := slot.dialer.DialContext(contextWithTransport(ctx, p.id, slot.index), network, addr)
		if err == nil {
			return &leaseConn{Conn: conn, release: func() { slot.load.Add(-1) }}, nil
		}
		slot.load.Add(-1)
		if errors.Is(err, errSSHOpenBudgetExhausted) && last != nil {
			return nil, last
		}
		last = err
		if ctx.Err() != nil || !slotRetryable(err) {
			return nil, err
		}
		skipped = append(skipped, slot)
	}
}

// reserve books one open on the least loaded connected slot not in skipped,
// and returns it, or nil when none is left. Reading the loads and booking the
// open share pickMu, so the next caller already sees this slot busy.
func (p *sshTransportPool) reserve(skipped []*transportSlot) *transportSlot {
	p.pickMu.Lock()
	defer p.pickMu.Unlock()
	var best *transportSlot
	for _, slot := range p.slots {
		if slot.dialer == nil || !slot.dialer.Connected() || slices.Contains(skipped, slot) {
			continue
		}
		if best == nil || slot.load.Load() < best.load.Load() {
			best = slot
		}
	}
	if best == nil {
		return nil
	}
	best.load.Add(1)
	return best
}

func slotRetryable(err error) bool {
	var refused *ssh.OpenChannelError
	if errors.As(err, &refused) && refused.Reason == ssh.ConnectionFailed {
		return false
	}
	return !sshQuotaExhausted(err) && !errors.Is(err, errSSHOpenBudgetExhausted)
}

func sshQuotaExhausted(err error) bool {
	var pending *pendingOpenLimitError
	var tunnels *clientTunnelLimitError
	return errors.As(err, &pending) || errors.As(err, &tunnels)
}

func (p *sshTransportPool) Connected() bool {
	for _, slot := range p.slots {
		if slot.dialer != nil && slot.dialer.Connected() {
			return true
		}
	}
	return false
}
func (p *sshTransportPool) stop() {
	for _, slot := range p.slots {
		if slot.dialer != nil {
			slot.dialer.stop()
		}
	}
}

type sshDialerSet struct {
	pools        []*sshTransportPool
	next         atomic.Uint64
	healthCancel context.CancelFunc
	healthDone   chan struct{}
}

type selectedDialerKey struct{}
type selectedTransportKey struct{}

type selectedTransport struct {
	serverID string
	slot     int
}

func dialerForContext(ctx context.Context, fallback dialer) dialer {
	if d, ok := ctx.Value(selectedDialerKey{}).(dialer); ok && d != nil {
		return d
	}
	return fallback
}

func contextWithDialer(ctx context.Context, d dialer) context.Context {
	return context.WithValue(ctx, selectedDialerKey{}, d)
}

func contextWithTransport(ctx context.Context, serverID string, slot int) context.Context {
	return context.WithValue(ctx, selectedTransportKey{}, selectedTransport{serverID: serverID, slot: slot})
}

func transportFromContext(ctx context.Context) (selectedTransport, bool) {
	t, ok := ctx.Value(selectedTransportKey{}).(selectedTransport)
	return t, ok
}

func selectedServerKey(ctx context.Context) string {
	if pool, ok := ctx.Value(selectedDialerKey{}).(*sshTransportPool); ok && pool != nil {
		return pool.id
	}
	return ""
}

func (s *sshDialerSet) selectPool(src, destination, hashKey string) *sshTransportPool {
	pools := s.rankedPools(src, destination, hashKey)
	if len(pools) == 0 {
		return nil
	}
	return pools[0]
}

func (s *sshDialerSet) rankedPools(src, destination, hashKey string) []*sshTransportPool {
	client := src
	if host, _, err := net.SplitHostPort(src); err == nil {
		client = host
	}
	if ip, err := netip.ParseAddr(strings.Trim(client, "[]")); err == nil {
		client = ip.Unmap().String()
	} else {
		client = strings.ToLower(client)
	}
	if ip, err := netip.ParseAddr(strings.Trim(destination, "[]")); err == nil {
		destination = ip.Unmap().String()
	} else {
		destination = normalizeHost(destination)
	}
	key := client
	if hashKey != "client_ip" {
		key += "\x00" + destination
	}
	type scoredPool struct {
		pool  *sshTransportPool
		score [32]byte
	}
	var scored []scoredPool
	for _, pool := range s.pools {
		if !pool.eligible() {
			continue
		}
		score := sha256.Sum256([]byte(key + "\x00" + pool.id))
		scored = append(scored, scoredPool{pool: pool, score: score})
	}
	sort.Slice(scored, func(i, j int) bool {
		return strings.Compare(string(scored[i].score[:]), string(scored[j].score[:])) > 0
	})
	out := make([]*sshTransportPool, 0, len(scored))
	for _, item := range scored {
		out = append(out, item.pool)
	}
	return out
}

func (s *sshDialerSet) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if len(s.pools) == 0 {
		return nil, errors.New("no SSH servers configured")
	}
	start := int(s.next.Add(1)-1) % len(s.pools)
	var last error
	for i := 0; i < len(s.pools); i++ {
		p := s.pools[(start+i)%len(s.pools)]
		if !p.Connected() {
			continue
		}
		c, err := p.DialContext(ctx, network, addr)
		if err == nil {
			return c, nil
		}
		if sshQuotaExhausted(err) {
			return nil, err
		}
		last = err
	}
	if last != nil {
		return nil, last
	}
	return nil, errors.New("no connected SSH server")
}
func (s *sshDialerSet) Connected() bool {
	for _, p := range s.pools {
		if p.Connected() {
			return true
		}
	}
	return false
}

func (s *sshDialerSet) Eligible() bool {
	for _, p := range s.pools {
		if p.eligible() {
			return true
		}
	}
	return false
}

func (s *sshDialerSet) Status() tunnelStatus {
	if len(s.pools) == 0 {
		return tunnelStatus{State: stateNotConfigured}
	}
	if s.Eligible() {
		return tunnelStatus{State: stateConnected}
	}
	if s.Connected() {
		return tunnelStatus{State: stateConnecting}
	}
	for _, p := range s.pools {
		for _, slot := range p.slots {
			if provider, ok := slot.dialer.(statusProvider); ok {
				st := provider.Status()
				if st.Err != nil {
					return st
				}
			}
		}
	}
	return tunnelStatus{State: stateUnreachable, Err: errors.New("no connected SSH transport")}
}

type sshServersProvider interface {
	SSHServersStatus() []sshServerStatus
}

func (s *sshDialerSet) SSHServersStatus() []sshServerStatus {
	servers := make([]sshServerStatus, 0, len(s.pools))
	for _, p := range s.pools {
		servers = append(servers, p.status())
	}
	return servers
}
func (s *sshDialerSet) stop() {
	if s.healthCancel != nil {
		s.healthCancel()
	}
	for _, p := range s.pools {
		p.stop()
	}
}

func (s *sshDialerSet) waitStopped(ctx context.Context) error {
	for _, p := range s.pools {
		for _, slot := range p.slots {
			if owner, ok := slot.dialer.(interface{ waitStopped(context.Context) error }); ok {
				if err := owner.waitStopped(ctx); err != nil {
					return err
				}
			}
		}
	}
	if s.healthDone != nil {
		select {
		case <-s.healthDone:
			return nil
		default:
		}
		select {
		case <-s.healthDone:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (s *sshDialerSet) startHealthChecks(ctx context.Context, rules *RuleEngine, target string, interval, timeout time.Duration) {
	if interval <= 0 || timeout <= 0 || rules == nil {
		return
	}
	healthCtx, cancel := context.WithCancel(ctx)
	s.healthCancel = cancel
	done := make(chan struct{})
	s.healthDone = done
	var workers sync.WaitGroup
	for _, pool := range s.pools {
		workers.Go(func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				checkCtx, stop := context.WithTimeout(healthCtx, timeout)
				err := checkServerHTTPS(checkCtx, pool, rules, target)
				stop()
				pool.recordHealthProbe(err)
				select {
				case <-healthCtx.Done():
					return
				case <-ticker.C:
				}
			}
		})
	}
	go func() {
		workers.Wait()
		close(done)
	}()
}
