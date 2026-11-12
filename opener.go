package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
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
	var localDirect bool
	var err error
	if route == RouteDirect {
		addrs, err = o.rules.dns.localResolveAll(ctx, host)
	} else {
		addrs, localDirect, err = o.rules.dns.resolveTunnel(ctx, host)
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

		// With localOnNXDomain a private answer of the local resolver is an
		// intranet name, for example behind a VPN that overrides DNS: it
		// goes direct. Loopback and link-local stay refused, or a page could
		// point its own name at them by DNS rebinding.
		reachable := dropHostLocal(addrs)
		if !localDirect || len(reachable) == 0 {
			return dst, fmt.Errorf("resolve %s: only private addresses (%s), refused through the tunnel; add a direct rule to reach it directly", host, addrs[0])
		}
		addrs, dst.route, dst.reason = reachable, RouteDirect, "local-private"
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
	dst, err := o.prepare(ctx, host, port)
	addrs, route, reason := dst.addrs, dst.route, dst.reason
	if err != nil {
		// Preserve the failure stage for protocol replies and access logs.
		var dnsErr *DNSError
		if !errors.As(err, &dnsErr) {
			err = NewDNSError(host, err)
		}
		return nil, "", route, reason, err
	}
	log.Debug().Str("host", host).Str("route", route.String()).Int("addresses", len(addrs)).Msg("dial resolve")

	budget := o.dialTimeout
	if budget <= 0 {
		budget = 30 * time.Second
	}
	ctx = ctxWithConnMeta(ctx, ConnMeta{Proto: proto, Src: src, Host: host})
	dial := func(ctx context.Context, ip netip.Addr) (net.Conn, error) {
		return o.d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
	}
	if route == RouteDirect {
		budget = 5 * time.Second
		dial = func(ctx context.Context, ip netip.Addr) (net.Conn, error) {
			return dialDirectIP(ctx, ip, port, o.family)
		}
	}
	conn, ip, attempts, err := dialCandidates(ctx, addrs, budget, 250*time.Millisecond, dial)
	if err == nil {
		return conn, ip.String(), route, reason, nil
	}
	if route == RouteDirect {
		err = fmt.Errorf("direct dial to %s:%d failed: %w", host, port, err)
	} else {
		addr := host
		if ip.IsValid() {
			addr = ip.String()
		}
		err = NewNetworkError("SSH dial", net.JoinHostPort(addr, strconv.Itoa(port)), err)
	}
	return nil, "", route, reason, withAttempts(err, attempts)
}

// dialCandidates owns one deadline and at most two waiting attempts.
// SSH opens that outlive an attempt stay in sshDialer's bounded pending pool.
func dialCandidates(ctx context.Context, addrs []netip.Addr, budget, delay time.Duration, dial func(context.Context, netip.Addr) (net.Conn, error)) (net.Conn, netip.Addr, int, error) {
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
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
			if attempt.Err() != nil {
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
		if err := ctx.Err(); err != nil {
			return nil, firstIP, attempts, err
		}
		if active == 0 && attempts < len(unique) {
			launch()
		}
		if active == 0 {
			if err := ctx.Err(); err != nil {
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
			return nil, firstIP, attempts, ctx.Err()
		case <-next:
			if ctx.Err() == nil {
				launch()
			}
		case r := <-results:
			active--
			if err := ctx.Err(); err != nil {
				if r.conn != nil {
					r.conn.Close()
				}
				return nil, firstIP, attempts, err
			}
			if r.err == nil {
				return r.conn, r.ip, attempts, nil
			}
			if firstErr == nil {
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
