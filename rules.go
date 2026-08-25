package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"sync"
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

const dnsCacheMaxSize = 1000

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

func NewRuleEngine(direct string) (*RuleEngine, error) {
	e := &RuleEngine{
		dns: &dnsCache{
			mu:    sync.Mutex{},
			cache: make(map[string]cacheEntry),
			ttl:   30 * time.Second,
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
		if ip, err := netip.ParseAddr(host); err == nil && r.ipPrefix.Contains(ip) {
			return true
		}
		if resolved, err := dns.Resolve(ctx, host); err == nil && r.ipPrefix.Contains(resolved) {
			return true
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
	ip      netip.Addr
	expires time.Time
}

func (c *dnsCache) Resolve(ctx context.Context, host string) (netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip, nil
	}

	c.mu.Lock()
	if entry, ok := c.cache[host]; ok && time.Now().Before(entry.expires) {
		c.mu.Unlock()
		return entry.ip, nil
	}
	c.mu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return netip.Addr{}, err
	}

	for _, a := range addrs {
		if ip, ok := netip.AddrFromSlice(a.IP); ok && ip.Is4() {
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
			c.cache[host] = cacheEntry{ip: ip, expires: time.Now().Add(c.ttl)}
			c.mu.Unlock()
			return ip, nil
		}
	}

	return netip.Addr{}, fmt.Errorf("no IPv4 address for %s", host)
}

func mustPrefix(s string) netip.Prefix {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		panic(err)
	}
	return p
}
