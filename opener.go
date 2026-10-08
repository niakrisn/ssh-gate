package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/rs/zerolog/log"
)

// Opener is the single entry point for every upstream connection: it decides
// the route, resolves the destination per the route's policy, and dials.
// Both the HTTP proxy and the SOCKS5 server open connections through it, so
// the route/resolve policy exists exactly once: direct destinations resolve
// through the local resolver (independent of any DoH configuration,
// including DoH NXDOMAINs), tunnel destinations resolve through the
// in-tunnel DoH endpoint.
type Opener struct {
	rules  *RuleEngine
	d      dialer
	family IPFamily
}

// Resolve applies the route policy to host and returns one dialable address
// along with the route it implies. Rules do not depend on the port, so port
// may be 0 (the SOCKS5 handshake resolver only knows the name).
func (o *Opener) Resolve(ctx context.Context, host string, port int) (net.IP, Route, string, error) {
	ip, route, reason, err := o.resolveAddr(ctx, host, port)
	if err != nil {
		return nil, route, reason, err
	}
	return ip.AsSlice(), route, reason, nil
}

// resolveAddr is Resolve's internal form returning a netip.Addr. It keeps
// single-address semantics: the head of the candidates list.
func (o *Opener) resolveAddr(ctx context.Context, host string, port int) (netip.Addr, Route, string, error) {
	addrs, route, reason, err := o.candidates(ctx, host, port)
	if err != nil {
		return netip.Addr{}, route, reason, err
	}
	return addrs[0], route, reason, nil
}

// candidates applies the route policy to host and returns every dialable
// address in dial order: direct routes keep all family-matching addresses
// in resolver order; tunnel routes lead with pickTunnelAddr's choice (first
// IPv4, IPv6 fallback) followed by the rest. Open dials down this list, so
// one dead address (a stale A record) no longer kills the connect.
func (o *Opener) candidates(ctx context.Context, host string, port int) ([]netip.Addr, Route, string, error) {
	route, reason := o.rules.Decide(ctx, host, port)

	var addrs []netip.Addr
	var err error
	if route == RouteDirect {
		addrs, err = o.rules.dns.localResolveAll(ctx, host)
	} else {
		addrs, err = o.rules.dns.ResolveAll(ctx, host)
	}
	if err != nil {
		return nil, route, reason, err
	}

	if route == RouteDirect {
		var out []netip.Addr
		for _, a := range addrs {
			if familyMatches(o.family, a.AsSlice()) {
				out = append(out, a)
			}
		}
		if len(out) == 0 {
			return nil, route, reason, fmt.Errorf("resolve %s: no %s addresses", host, o.family)
		}
		return out, route, reason, nil
	}

	head, err := pickTunnelAddr(addrs)
	if err != nil {
		return nil, route, reason, err
	}
	out := make([]netip.Addr, 0, len(addrs))
	out = append(out, head)
	for _, a := range addrs {
		if a != head {
			out = append(out, a)
		}
	}
	return out, route, reason, nil
}

// Open decides the route, resolves per policy, and dials the destination,
// falling through the resolved addresses until one connects. It returns the
// connection, the dialed address (for access logs), the route, and its
// reason. Tunnel dials carry ConnMeta on the dial context. On total failure
// the error is the first dial's, annotated with the attempt count.
func (o *Opener) Open(ctx context.Context, src, proto, host string, port int) (net.Conn, string, Route, string, error) {
	addrs, route, reason, err := o.candidates(ctx, host, port)
	if err != nil {
		return nil, "", route, reason, err
	}
	log.Debug().Str("host", host).Str("route", route.String()).Int("addresses", len(addrs)).Msg("dial resolve")

	if route == RouteDirect {
		var firstErr error
		for _, ip := range addrs {
			conn, derr := dialDirectIP(ctx, ip, port, o.family)
			if derr == nil {
				return conn, ip.String(), route, reason, nil
			}
			if firstErr == nil {
				firstErr = derr
			}
			log.Debug().Str("host", host).Str("ip", ip.String()).Err(derr).Msg("direct dial failed, trying next address")
		}
		return nil, "", route, reason, withAttempts(fmt.Errorf("direct dial to %s:%d failed: %w", host, port, firstErr), len(addrs))
	}

	ctx = ctxWithConnMeta(ctx, ConnMeta{Proto: proto, Src: src, Host: host})
	var firstErr error
	var firstAddr string
	for _, ip := range addrs {
		addr := net.JoinHostPort(ip.String(), strconv.Itoa(port))
		conn, derr := o.d.DialContext(ctx, "tcp", addr)
		if derr == nil {
			return conn, ip.String(), route, reason, nil
		}
		if firstErr == nil {
			firstErr, firstAddr = derr, addr
		}
		log.Debug().Str("host", host).Str("ip", ip.String()).Err(derr).Msg("tunnel dial failed, trying next address")
	}
	return nil, "", route, reason, withAttempts(NewNetworkError("SSH dial", firstAddr, firstErr), len(addrs))
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
