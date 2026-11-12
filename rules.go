package main

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Route int

const (
	RouteDirect Route = iota
	RouteTunnel
)

func (r Route) String() string {
	if r == RouteDirect {
		return "direct"
	}
	return "tunnel"
}

type ruleEntry struct {
	raw      string
	ipPrefix *netip.Prefix
	re       *regexp.Regexp
	domain   string
}

// hostLocalV4 is the IPv4 "this network" range; 0.0.0.0 dials localhost.
var hostLocalV4 = netip.MustParsePrefix("0.0.0.0/8")

type RuleEngine struct {
	rules   []ruleEntry
	dns     *dnsCache
	private []netip.Prefix
	started atomic.Bool
}

// Start launches background maintenance for the DNS cache purge goroutine.
// Idempotent; safe from any goroutine (the flag is atomic).
func (e *RuleEngine) Start(ctx context.Context) {
	if !e.started.CompareAndSwap(false, true) {
		return
	}
	e.dns.startPurge(ctx)
}

// Stop cleans up DNS cache state.
func (e *RuleEngine) Stop() {
	e.dns.stop()
}

func NewRuleEngine(direct string) (*RuleEngine, error) {
	ctx, cancel := context.WithCancel(context.Background())
	e := &RuleEngine{
		dns: &dnsCache{
			mu:          sync.Mutex{},
			cache:       make(map[string]cacheEntry),
			ttl:         dnsCacheTTL,
			negativeTTL: dnsNegativeTTL,
			ctx:         ctx,
			cancel:      cancel,
			stopped:     make(chan struct{}),
			now:         time.Now,
		},
		private: []netip.Prefix{
			mustPrefix("0.0.0.0/8"), // "this network"; 0.0.0.0 dials localhost
			mustPrefix("10.0.0.0/8"),
			mustPrefix("100.64.0.0/10"), // CGNAT, also Tailscale-style overlays
			mustPrefix("172.16.0.0/12"),
			mustPrefix("192.168.0.0/16"),
			mustPrefix("127.0.0.0/8"),
			mustPrefix("::/128"),
			mustPrefix("::1/128"),
			mustPrefix("169.254.0.0/16"),
			mustPrefix("fc00::/7"), // unique local
			mustPrefix("fe80::/10"),
		},
	}

	// ip: rules go last: the others need no lookup, so a name listed in
	// DIRECT_RULES never reaches the tunnel resolver, whatever the order of
	// the rules. Every rule leads to direct, so this changes only the reason.
	var ipRules []ruleEntry
	if direct != "" {
		for _, entry := range strings.Split(direct, ",") {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			r, err := parseRuleEntry(entry)
			if err != nil {
				return nil, err
			}
			if r.ipPrefix != nil {
				ipRules = append(ipRules, r)
			} else {
				e.rules = append(e.rules, r)
			}
		}
	}
	e.rules = append(e.rules, ipRules...)

	return e, nil
}

// normalizeHost canonicalizes a hostname for policy decisions and cache
// keys: DNS names are case-insensitive and a trailing dot (root label) is
// cosmetic, yet clients and middles legitimately send both spellings.
// Without it a direct rule silently misses for EXAMPLE.COM or example.com.
// and one host keeps two cache entries and two lookups. User-facing
// display (access log, tracker, ConnMeta.Host) keeps the raw spelling.
func normalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

// decideHost applies rules that need no DNS. CIDRs use the one prepared
// tunnel-policy answer in matchCIDR.
func (e *RuleEngine) decideHost(host string) (Route, string) {
	host = normalizeHost(host)
	// 1. RFC 1918 / loopback / link-local — always direct
	if ip, err := netip.ParseAddr(host); err == nil && e.isPrivate(ip) {
		return RouteDirect, "private"
	}

	// 2. Check direct rules
	for _, r := range e.rules {
		if r.matchesHost(host) {
			return RouteDirect, "direct:" + r.raw
		}
	}

	// 3. Fallback: tunnel
	return RouteTunnel, "fallback"
}

func (e *RuleEngine) matchCIDR(addrs []netip.Addr) string {
	for _, r := range e.rules {
		if r.ipPrefix == nil {
			continue
		}
		for _, a := range addrs {
			if r.ipPrefix.Contains(a) {
				return "direct:" + r.raw
			}
		}
	}
	return ""
}

// ResolveAll resolves host through the engine's cached resolver,
// sharing the rule-matching cache (up to 30 s, 5 s lookup timeout).
// Returns all IPv4 and IPv6 addresses; IP literals are returned as-is.
func (e *RuleEngine) ResolveAll(ctx context.Context, host string) ([]netip.Addr, error) {
	return e.dns.ResolveAll(ctx, host)
}

// pickTunnelAddr picks the address the VPS should dial for a tunneled
// connection: the first IPv4 if present (IPv4 egress is the baseline),
// otherwise the first IPv6 so v6-only destinations still resolve.
func pickTunnelAddr(addrs []netip.Addr) (netip.Addr, error) {
	for _, a := range addrs {
		if a.Is4() {
			return a, nil
		}
	}
	if len(addrs) == 0 {
		return netip.Addr{}, fmt.Errorf("no address")
	}
	return addrs[0], nil
}

// dropHostLocal removes loopback, unspecified and link-local addresses: a DNS
// answer must never send a connection there by itself. Reaching such an
// address is the job of an IP literal or a direct rule.
func dropHostLocal(addrs []netip.Addr) []netip.Addr {
	out := addrs[:0:0]
	for _, a := range addrs {
		a = a.Unmap().WithZone("")
		if !a.IsLoopback() && !a.IsLinkLocalUnicast() && !hostLocalV4.Contains(a) && a != netip.IPv6Unspecified() {
			out = append(out, a)
		}
	}
	return out
}

// isPrivate reports whether ip is in a private, loopback, link-local or
// otherwise local range. The address is unmapped and its zone dropped
// first: netip.Prefix.Contains never matches an IPv4-mapped address against
// an IPv4 prefix or an address with a zone, so ::ffff:127.0.0.1 and
// fe80::1%eth0 would otherwise pass as public.
func (e *RuleEngine) isPrivate(ip netip.Addr) bool {
	ip = ip.Unmap().WithZone("")
	for _, p := range e.private {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func (r ruleEntry) matchesHost(host string) bool {
	if r.re != nil {
		return r.re.MatchString(host)
	}
	if r.domain != "" {
		return host == r.domain || strings.HasSuffix(host, "."+r.domain)
	}
	return false
}

func parseRuleEntry(raw string) (ruleEntry, error) {
	if strings.HasPrefix(raw, "ip:") {
		prefix, err := netip.ParsePrefix(raw[3:])
		if err != nil {
			return ruleEntry{}, fmt.Errorf("invalid CIDR %q: %w", raw[3:], err)
		}
		return ruleEntry{raw: raw, ipPrefix: &prefix}, nil
	}
	if strings.HasPrefix(raw, "re:") {
		if raw[3:] == "" {
			// An empty pattern compiles and matches everything - it would
			// silently route ALL traffic direct instead of filtering.
			return ruleEntry{}, fmt.Errorf("empty regex pattern %q", raw)
		}
		re, err := regexp.Compile(raw[3:])
		if err != nil {
			return ruleEntry{}, fmt.Errorf("invalid regex %q: %w", raw[3:], err)
		}
		return ruleEntry{raw: raw, re: re}, nil
	}
	// Match canonical against canonical: the request host is normalized by
	// decideHost, so the rule must be too - a mixed-case or root-dotted entry
	// means the same name to the operator. raw keeps the config spelling
	// for logs.
	domain := normalizeHost(strings.TrimPrefix(raw, "."))
	if domain == "" {
		return ruleEntry{}, fmt.Errorf("rule %q contains no domain", raw)
	}
	return ruleEntry{raw: raw, domain: domain}, nil
}

func mustPrefix(s string) netip.Prefix {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		panic(err)
	}
	return p
}
