package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
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

const (
	dnsCacheMaxSize = 1000
	dnsCacheTTL     = 30 * time.Second
	// dohMaxResponse bounds a single DoH answer body against a misbehaving
	// endpoint returning an unreasonably large response.
	dohMaxResponse = 1 << 20
)

type RuleEngine struct {
	rules   []ruleEntry
	dns     *dnsCache
	private []netip.Prefix
	started bool
}

// Start launches background maintenance for the DNS cache purge goroutine.
func (e *RuleEngine) Start(ctx context.Context) {
	if e.started {
		return
	}
	e.started = true
	e.dns.startPurge(ctx)
}

// Stop cleans up DNS cache state.
func (e *RuleEngine) Stop() {
	e.dns.stop()
}

// SetDOH makes cached resolution query the given DNS-over-HTTPS endpoint
// (https://host/dns-query, RFC 8484) through the SSH dialer, so DNS traffic
// stays inside the encrypted tunnel and cannot be poisoned on the client
// side. A definitive DoH answer (including NXDOMAIN) is authoritative; the
// local resolver is used only when the DoH endpoint is unreachable.
// Direct destinations keep using local DNS.
func (e *RuleEngine) SetDOH(host string, d dialer) {
	e.dns.dohHost = host
	e.dns.dohClient = tunnelHTTPClient(d, 0, nil)
}

func NewRuleEngine(direct string) (*RuleEngine, error) {
	e := &RuleEngine{
		dns: &dnsCache{
			mu:    sync.Mutex{},
			cache: make(map[string]cacheEntry),
			ttl:   dnsCacheTTL,
			done:  make(chan struct{}),
		},
		private: []netip.Prefix{
			mustPrefix("10.0.0.0/8"),
			mustPrefix("172.16.0.0/12"),
			mustPrefix("192.168.0.0/16"),
			mustPrefix("127.0.0.0/8"),
			mustPrefix("::1/128"),
			mustPrefix("169.254.0.0/16"),
			mustPrefix("fe80::/10"),
		},
	}

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
			e.rules = append(e.rules, r)
		}
	}

	return e, nil
}

func (e *RuleEngine) Route(ctx context.Context, host string, port int) Route {
	r, _ := e.Decide(ctx, host, port)
	return r
}

func (e *RuleEngine) Decide(ctx context.Context, host string, port int) (Route, string) {
	// 1. RFC 1918 / loopback / link-local — always direct
	if ip, err := netip.ParseAddr(host); err == nil && e.isPrivate(ip) {
		log.Debug().Str("host", host).Int("port", port).Str("reason", "private").Msg("route")
		return RouteDirect, "private"
	}

	// 2. Check direct rules
	for _, r := range e.rules {
		if r.matches(ctx, host, e.dns) {
			log.Debug().Str("host", host).Int("port", port).Str("reason", "direct:"+r.raw).Msg("route")
			return RouteDirect, "direct:" + r.raw
		}
	}

	// 3. Fallback: tunnel
	log.Debug().Str("host", host).Int("port", port).Str("reason", "fallback").Msg("route")
	return RouteTunnel, "fallback"
}

// ResolveAll resolves host through the engine's cached resolver,
// sharing the rule-matching cache (TTL 30 s, 5 s lookup timeout).
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

// ResolveTunnel resolves host and picks the tunnel address (v4 first, v6
// fallback) for client-side dialing through the SSH tunnel.
func (e *RuleEngine) ResolveTunnel(ctx context.Context, host string) (netip.Addr, error) {
	addrs, err := e.ResolveAll(ctx, host)
	if err != nil {
		return netip.Addr{}, err
	}
	return pickTunnelAddr(addrs)
}

func (e *RuleEngine) isPrivate(ip netip.Addr) bool {
	for _, p := range e.private {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func (r ruleEntry) matches(ctx context.Context, host string, dns *dnsCache) bool {
	if r.ipPrefix != nil {
		addrs, err := dns.ResolveAll(ctx, host)
		if err != nil {
			return false
		}
		for _, a := range addrs {
			if r.ipPrefix.Contains(a) {
				return true
			}
		}
		return false
	}
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
		re, err := regexp.Compile(raw[3:])
		if err != nil {
			return ruleEntry{}, fmt.Errorf("invalid regex %q: %w", raw[3:], err)
		}
		return ruleEntry{raw: raw, re: re}, nil
	}
	domain := strings.TrimPrefix(raw, ".")
	return ruleEntry{raw: raw, domain: domain}, nil
}

// dnsCache caches DNS resolution with TTL.
type dnsCache struct {
	mu        sync.Mutex
	cache     map[string]cacheEntry
	ttl       time.Duration
	done      chan struct{}
	closeOnce sync.Once
	// lookups counts real resolver queries (cache hits and IP literals
	// excluded); tests use it to assert caching without timing tricks.
	lookups   atomic.Int64
	dohHost   string
	dohClient *http.Client
}

// startPurge launches a background goroutine that purges expired entries every TTL.
func (c *dnsCache) startPurge(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(c.ttl)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				c.closeOnce.Do(func() { close(c.done) })
				return
			case <-c.done:
				return
			case <-ticker.C:
				c.purge()
			}
		}
	}()
}

func (c *dnsCache) stop() {
	c.closeOnce.Do(func() { close(c.done) })
}

func (c *dnsCache) purge() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for k, v := range c.cache {
		if now.After(v.expires) {
			delete(c.cache, k)
		}
	}
}

type cacheEntry struct {
	addrs   []netip.Addr
	expires time.Time
}

// ResolveAll resolves host to all of its IPv4 and IPv6 addresses. IP
// literals are returned as-is without touching the resolver or the cache.
func (c *dnsCache) ResolveAll(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip.Unmap()}, nil
	}

	c.mu.Lock()
	if entry, ok := c.cache[host]; ok && time.Now().Before(entry.expires) {
		c.mu.Unlock()
		return entry.addrs, nil
	}
	c.mu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	c.lookups.Add(1)

	// Both lookup sources return unmapped addresses.
	addrs, err := c.lookup(ctx, host)
	if err != nil {
		return nil, NewDNSError(host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no address for %s", host)
	}

	c.mu.Lock()
	if len(c.cache) >= dnsCacheMaxSize {
		// Evict oldest entries to make room
		var oldestKey string
		var oldestTime time.Time
		for k, v := range c.cache {
			if oldestKey == "" || v.expires.Before(oldestTime) {
				oldestKey = k
				oldestTime = v.expires
			}
		}
		if oldestKey != "" {
			delete(c.cache, oldestKey)
		}
	}
	c.cache[host] = cacheEntry{addrs: addrs, expires: time.Now().Add(c.ttl)}
	c.mu.Unlock()
	return addrs, nil
}

// errDohNotFound marks a definitive not-found from the DoH endpoint
// (NXDOMAIN or an empty answer); it must not fall back to the local
// resolver.
var errDohNotFound = errors.New("no answer")

// lookup resolves host through the configured DoH endpoint when set and
// falls back to the local resolver only on DoH transport failure.
func (c *dnsCache) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if c.dohClient != nil {
		addrs, err := c.dohLookup(ctx, host)
		if err == nil || errors.Is(err, errDohNotFound) {
			return addrs, err
		}
		// DoH endpoint unreachable: fall back to the local resolver. The
		// warning is the only signal that resolution degraded to local DNS.
		log.Warn().Str("host", host).Err(err).Msg("DoH lookup failed, falling back to the local resolver")
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if ip, ok := netip.AddrFromSlice(a.IP); ok {
			out = append(out, ip.Unmap())
		}
	}
	return out, nil
}

// dohResponse is an RFC 8484 dns-json answer subset.
type dohResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Type int    `json:"Type"`
		Data string `json:"Data"`
	} `json:"Answer"`
}

// dohQuery pairs a DNS record type with how it is addressed in a dns-json
// query (the "type" URL parameter) and how it is matched in answers.
type dohQuery struct {
	name string
	want int
}

var (
	dohQueryA    = dohQuery{name: "A", want: 1}
	dohQueryAAAA = dohQuery{name: "AAAA", want: 28}
)

// dohJSONQuery performs one dns-json DoH query (RFC 8484 GET) on the
// endpoint and returns the addresses of the wanted record type, unmapped.
// errDohNotFound marks a definitive NXDOMAIN; any other error is a
// transport or protocol failure.
func dohJSONQuery(ctx context.Context, client *http.Client, endpoint, host string, q dohQuery) ([]netip.Addr, error) {
	u := "https://" + endpoint + "/dns-query?" + url.Values{"name": {host}, "type": {q.name}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	var d dohResponse
	err = json.NewDecoder(io.LimitReader(resp.Body, dohMaxResponse)).Decode(&d)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	if d.Status == 3 { // NXDOMAIN
		return nil, errDohNotFound
	}
	if resp.StatusCode != http.StatusOK || d.Status != 0 {
		return nil, fmt.Errorf("doh: status %d/%d", resp.StatusCode, d.Status)
	}
	var out []netip.Addr
	for _, a := range d.Answer {
		if a.Type != q.want {
			continue
		}
		if ip, perr := netip.ParseAddr(a.Data); perr == nil {
			out = append(out, ip.Unmap())
		}
	}
	return out, nil
}

// dohLookup queries the DoH endpoint for A and AAAA records.
func (c *dnsCache) dohLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, q := range [2]dohQuery{dohQueryA, dohQueryAAAA} {
		addrs, err := dohJSONQuery(ctx, c.dohClient, c.dohHost, host, q)
		if err != nil {
			return nil, err
		}
		out = append(out, addrs...)
	}
	if len(out) == 0 {
		return nil, errDohNotFound
	}
	return out, nil
}

func mustPrefix(s string) netip.Prefix {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		panic(err)
	}
	return p
}
