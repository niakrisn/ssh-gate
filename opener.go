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

// resolveAddr is Resolve's internal form returning a netip.Addr.
func (o *Opener) resolveAddr(ctx context.Context, host string, port int) (netip.Addr, Route, string, error) {
	route, reason := o.rules.Decide(ctx, host, port)

	var addrs []netip.Addr
	var err error
	if route == RouteDirect {
		addrs, err = o.rules.dns.localResolveAll(ctx, host)
	} else {
		addrs, err = o.rules.dns.ResolveAll(ctx, host)
	}
	if err != nil {
		return netip.Addr{}, route, reason, err
	}

	var ip netip.Addr
	if route == RouteDirect {
		for _, a := range addrs {
			if familyMatches(o.family, a.AsSlice()) {
				ip = a
				break
			}
		}
		if ip.IsUnspecified() {
			return netip.Addr{}, route, reason, fmt.Errorf("resolve %s: no %s addresses", host, o.family)
		}
	} else {
		ip, err = pickTunnelAddr(addrs)
		if err != nil {
			return netip.Addr{}, route, reason, err
		}
	}
	return ip, route, reason, nil
}

// Open decides the route, resolves per policy, and dials the destination.
// It returns the connection, the dialed address (for access logs), the
// route, and its reason. Tunnel dials carry ConnMeta on the dial context.
func (o *Opener) Open(ctx context.Context, src, proto, host string, port int) (net.Conn, string, Route, string, error) {
	ip, route, reason, err := o.resolveAddr(ctx, host, port)
	if err != nil {
		return nil, "", route, reason, err
	}
	addr := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	log.Debug().Str("host", host).Str("route", route.String()).Str("ip", ip.String()).Msg("dial resolve")

	if route == RouteDirect {
		conn, err := dialDirectIP(ctx, ip, port, o.family)
		return conn, ip.String(), route, reason, err
	}

	ctx = ctxWithConnMeta(ctx, ConnMeta{Proto: proto, Src: src, Host: host})
	conn, err := o.d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, "", route, reason, NewNetworkError("SSH dial", addr, err)
	}
	return conn, ip.String(), route, reason, nil
}
