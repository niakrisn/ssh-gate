package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

// Opener is the single entry point for every upstream connection: it decides
// the route, resolves the destination per the route's policy, and dials.
// Both the HTTP proxy and the SOCKS5 server open connections through it, so
// the route/resolve policy exists exactly once: direct destinations resolve
// through the local resolver (independent of any tunnel resolver, including
// its NXDOMAINs), tunnel destinations resolve through the tunnel resolvers.
type Opener struct {
	rules       *RuleEngine
	d           dialer
	family      IPFamily
	dialTimeout time.Duration
	hashKey     string
	maxAttempts int
}

type destination struct {
	host   string
	port   int
	route  Route
	reason string
	addrs  []netip.Addr
}

// prepare resolves once per required policy. Its result is local to one
// request, so zero-TTL answers and failures are reused without caching them.
func (o *Opener) prepare(ctx context.Context, host string, port int) (destination, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return destination{}, err
	}
	route, reason := o.rules.decideHost(host)
	dst := destination{host: host, port: port, route: route, reason: reason}

	var addrs []netip.Addr
	var err error
	if route == RouteDirect {
		addrs, err = o.rules.dns.localResolveAll(ctx, host)
	} else {
		addrs, _, err = o.rules.dns.resolveTunnel(ctx, host)
		if err == nil {
			if reason := o.rules.matchCIDR(addrs); reason != "" {
				dst.route, dst.reason = RouteDirect, reason
				// The tunnel answer selects the rule; only local policy may
				// supply addresses for the resulting direct connection.
				addrs, err = o.rules.dns.localResolveAll(ctx, host)
			}
		}
	}
	if err != nil {
		return dst, err
	}

	if dst.route == RouteTunnel {
		// A public name may resolve to a private or loopback address (DNS
		// rebinding, nip.io-style names). Through the tunnel the VPS would
		// dial it in its own network: its localhost, the cloud metadata
		// service, the provider's internal network. Such addresses never go
		// to the tunnel.
		public := addrs[:0:0]
		for _, a := range addrs {
			if !o.rules.isPrivate(a) {
				public = append(public, a)
			}
		}
		if len(public) > 0 {
			head, err := pickTunnelAddr(public)
			if err != nil {
				return dst, err
			}
			out := make([]netip.Addr, 0, len(public))
			out = append(out, head)
			for _, a := range public {
				if a != head {
					out = append(out, a)
				}
			}
			dst.addrs = out
			return dst, nil
		}

		return dst, fmt.Errorf("resolve %s: only private addresses (%s), refused through the tunnel; add a direct rule to reach it directly", host, addrs[0])
	}

	var out []netip.Addr
	for _, a := range addrs {
		if familyMatches(o.family, a.AsSlice()) {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return dst, fmt.Errorf("resolve %s: no %s addresses", host, o.family)
	}
	dst.addrs = out
	return dst, nil
}

// Open decides the route, resolves per policy, and dials the destination,
// falling through the resolved addresses until one connects. It returns the
// connection, the dialed address (for access logs), the route, and its
// reason. Tunnel dials carry ConnMeta on the dial context. On total failure
// the error is the first dial's, or the overall deadline, with the attempt count.
func (o *Opener) Open(ctx context.Context, src, proto, host string, port int) (net.Conn, string, Route, string, error) {
	budget := o.dialTimeout
	if budget <= 0 {
		budget = 30 * time.Second
	}
	maxAttempts := o.maxAttempts
	if maxAttempts <= 0 {
		maxAttempts = 3
	}
	initialRoute, initialReason := o.rules.decideHost(host)
	if initialRoute == RouteTunnel {
		if selector, ok := o.d.(*sshDialerSet); ok {
			deadlineCtx, cancel := context.WithTimeout(ctx, budget)
			defer cancel()
			pools := selector.rankedPools(src, host, o.hashKey)
			if len(pools) == 0 {
				return nil, "", RouteTunnel, initialReason, NewNetworkError("SSH dial", host, errors.New("no eligible SSH server"))
			}
			openBudget := &sshOpenBudget{limit: int64(maxAttempts)}
			var lastErr error
			var lastIP netip.Addr
			lastRoute, lastReason := RouteTunnel, initialReason
			for poolIndex, pool := range pools {
				if err := deadlineCtx.Err(); err != nil {
					lastErr = err
					break
				}
				// Moving to another server costs one attempt. The remaining
				// budget covers client channel opens across all IPs and slots.
				if poolIndex > 0 {
					openBudget.take()
				}
				remaining := openBudget.remaining()
				if remaining == 0 {
					break
				}
				var release func()
				if pool.quota != nil {
					var err error
					release, err = pool.quota.reserveTunnel()
					if err != nil {
						log.Warn().Str("server_id", pool.id).Str("limit_type", "client_tunnels").Err(err).Msg("SSH server quota exhausted")
						return nil, "", RouteTunnel, initialReason, NewNetworkError("SSH dial", host, err)
					}
				}
				poolCtx := contextWithDialer(deadlineCtx, pool)
				dst, err := o.prepare(poolCtx, host, port)
				lastRoute, lastReason = dst.route, dst.reason
				if err != nil {
					if release != nil {
						release()
					}
					lastErr = err
					if errors.Is(err, errNotFound) || sshQuotaExhausted(err) {
						return nil, "", dst.route, dst.reason, err
					}
					continue
				}
				if dst.route == RouteDirect {
					if release != nil {
						release()
						release = nil
					}
					conn, ip, n, err := o.dialPrepared(poolCtx, src, proto, host, port, dst, o.d, remaining)
					if err != nil {
						return nil, "", dst.route, dst.reason, fmt.Errorf("direct dial to %s:%d failed: %w", host, port, withAttempts(err, n))
					}
					return conn, ip.String(), dst.route, dst.reason, nil
				}
				dialCtx := context.WithValue(poolCtx, sshOpenBudgetKey{}, openBudget)
				conn, ip, _, err := o.dialPrepared(dialCtx, src, proto, host, port, dst, pool, remaining)
				if err == nil {
					if release != nil {
						conn = &leaseConn{Conn: conn, release: release}
						release = nil
					}
					return conn, ip.String(), dst.route, dst.reason, nil
				}
				if release != nil {
					release()
				}
				lastErr, lastIP = err, ip
				if sshQuotaExhausted(err) || errors.Is(err, context.DeadlineExceeded) || deadlineCtx.Err() != nil || openBudget.remaining() == 0 {
					break
				}
			}
			if lastErr == nil {
				lastErr = errSSHOpenBudgetExhausted
			}
			addr := host
			if lastIP.IsValid() {
				addr = lastIP.String()
			}
			err := error(NewNetworkError("SSH dial", net.JoinHostPort(addr, strconv.Itoa(port)), lastErr))
			if attempts := maxAttempts - openBudget.remaining(); attempts > 1 {
				err = fmt.Errorf("%w (%d attempts)", err, attempts)
			}
			return nil, "", lastRoute, lastReason, err
		}
	}

	dst, err := o.prepare(ctx, host, port)
	if err != nil {
		var dnsErr *DNSError
		if !errors.As(err, &dnsErr) {
			err = NewDNSError(host, err)
		}
		return nil, "", dst.route, dst.reason, err
	}
	conn, ip, attempts, err := o.dialPrepared(ctx, src, proto, host, port, dst, o.d, maxAttempts)
	if err != nil {
		if dst.route == RouteDirect {
			err = fmt.Errorf("direct dial to %s:%d failed: %w", host, port, withAttempts(err, attempts))
		} else {
			addr := host
			if ip.IsValid() {
				addr = ip.String()
			}
			err = withAttempts(NewNetworkError("SSH dial", net.JoinHostPort(addr, strconv.Itoa(port)), err), attempts)
		}
		return nil, "", dst.route, dst.reason, err
	}
	return conn, ip.String(), dst.route, dst.reason, nil
}

type sshOpenBudgetKey struct{}

// sshOpenBudget is shared by the parallel IP attempts of a single request.
type sshOpenBudget struct {
	limit int64
	used  atomic.Int64
}

var errSSHOpenBudgetExhausted = errors.New("SSH retries exhausted")

func (b *sshOpenBudget) remaining() int {
	return int(b.limit - b.used.Load())
}

func (b *sshOpenBudget) take() bool {
	for used := b.used.Load(); used < b.limit; used = b.used.Load() {
		if b.used.CompareAndSwap(used, used+1) {
			return true
		}
	}
	return false
}

func (o *Opener) dialPrepared(ctx context.Context, src, proto, host string, port int, dst destination, d dialer, maxAttempts int) (net.Conn, netip.Addr, int, error) {
	ctx = ctxWithConnMeta(ctx, ConnMeta{Proto: proto, Src: src, Host: host})
	budget := o.dialTimeout
	if budget <= 0 {
		budget = 30 * time.Second
	}
	delay := 250 * time.Millisecond
	dial := func(ctx context.Context, ip netip.Addr) (net.Conn, error) {
		return d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
	}
	if dst.route == RouteDirect {
		budget = 5 * time.Second
		delay = 0
		dial = func(ctx context.Context, ip netip.Addr) (net.Conn, error) {
			return dialDirectIP(ctx, ip, port, o.family)
		}
	}
	return dialCandidatesLimit(ctx, dst.addrs, budget, delay, maxAttempts, dial)
}

type leaseConn struct {
	net.Conn
	release func()
	closed  atomic.Bool
}

func (c *leaseConn) Close() error {
	err := c.Conn.Close()
	if c.closed.CompareAndSwap(false, true) && c.release != nil {
		c.release()
	}
	return err
}

func (c *leaseConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// dialCandidates owns one deadline and at most two waiting attempts.
// SSH opens that outlive an attempt stay in sshDialer's bounded pending pool.
func dialCandidates(ctx context.Context, addrs []netip.Addr, budget, delay time.Duration, dial func(context.Context, netip.Addr) (net.Conn, error)) (net.Conn, netip.Addr, int, error) {
	return dialCandidatesLimit(ctx, addrs, budget, delay, len(addrs), dial)
}

func dialCandidatesLimit(ctx context.Context, addrs []netip.Addr, budget, delay time.Duration, maxAttempts int, dial func(context.Context, netip.Addr) (net.Conn, error)) (net.Conn, netip.Addr, int, error) {
	ctx, timeout := context.WithTimeout(ctx, budget)
	defer timeout()
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	requestErr := func() error {
		if cause := context.Cause(ctx); sshQuotaExhausted(cause) {
			return cause
		}
		return ctx.Err()
	}
	unique := make([]netip.Addr, 0, len(addrs))
	seen := make(map[netip.Addr]bool, len(addrs))
	for _, ip := range addrs {
		if !seen[ip] {
			seen[ip] = true
			unique = append(unique, ip)
		}
	}
	if len(unique) == 0 {
		return nil, netip.Addr{}, 0, errors.New("no destination addresses")
	}
	if maxAttempts < 1 {
		return nil, netip.Addr{}, 0, errors.New("attempt limit must be positive")
	}
	if len(unique) > maxAttempts {
		unique = unique[:maxAttempts]
	}
	attemptBudget := max(2*time.Second, budget/time.Duration((len(unique)+1)/2))
	type result struct {
		conn net.Conn
		ip   netip.Addr
		err  error
	}
	results := make(chan result)
	attempts, active := 0, 0
	timer := time.NewTimer(delay)
	defer timer.Stop()
	var next <-chan time.Time
	var firstErr error
	var firstIP netip.Addr
	launch := func() {
		if ctx.Err() != nil {
			return
		}
		ip := unique[attempts]
		attempts++
		active++
		go func() {
			attempt, stop := context.WithTimeout(ctx, attemptBudget)
			defer stop()
			var conn net.Conn
			err := attempt.Err()
			if err == nil {
				conn, err = dial(attempt, ip)
			}
			if sshQuotaExhausted(err) {
				cancel(err)
			} else if attempt.Err() != nil {
				err = attempt.Err()
			}
			if err != nil && conn != nil {
				conn.Close()
				conn = nil
			}
			select {
			case results <- result{conn, ip, err}:
				// The receiver owns the connection, including cancellation races.
			case <-ctx.Done():
				if conn != nil {
					conn.Close()
				}
			}
		}()
	}
	for {
		if err := requestErr(); err != nil {
			return nil, firstIP, attempts, err
		}
		if active == 0 && attempts < len(unique) {
			launch()
		}
		if active == 0 {
			if err := requestErr(); err != nil {
				return nil, firstIP, attempts, err
			}
			return nil, firstIP, attempts, firstErr
		}
		if active < 2 && attempts < len(unique) {
			timer.Reset(delay)
			next = timer.C
		} else {
			next = nil
		}
		select {
		case <-ctx.Done():
			return nil, firstIP, attempts, requestErr()
		case <-next:
			if ctx.Err() == nil {
				launch()
			}
		case r := <-results:
			active--
			if err := requestErr(); err != nil {
				if r.conn != nil {
					r.conn.Close()
				}
				return nil, firstIP, attempts, err
			}
			if r.err == nil {
				return r.conn, r.ip, attempts, nil
			}
			if firstErr == nil || errors.Is(firstErr, errSSHOpenBudgetExhausted) {
				firstErr, firstIP = r.err, r.ip
			}
			// A refusal frees a slot immediately; it does not add another delay.
			if attempts < len(unique) {
				launch()
			}
		}
	}
}

// withAttempts annotates a total dial failure with how many addresses were
// tried, so the log distinguishes "one address, refused" from "whole
// record set down".
func withAttempts(err error, attempts int) error {
	if attempts > 1 {
		return fmt.Errorf("%w (%d addresses tried)", err, attempts)
	}
	return err
}
