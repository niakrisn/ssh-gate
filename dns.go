package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sync/singleflight"
)

const (
	dnsCacheMaxSize = 1000
	dnsCacheTTL     = 30 * time.Second
	// dnsNegativeTTL bounds how long an authoritative NXDOMAIN is cached —
	// short enough that a freshly registered name recovers quickly.
	dnsNegativeTTL = 10 * time.Second
	// dohMaxResponse bounds a single DoH answer body against a misbehaving
	// endpoint returning an unreasonably large response.
	dohMaxResponse = 1 << 20
	// tunnelLookupTimeout bounds the tunnel step of a lookup, so a silent
	// server leaves the local resolver the rest of the 5 s lookup bound.
	tunnelLookupTimeout = 3 * time.Second
	// upstreamPause is how long lookups skip a tunnel resolver no channel
	// could be opened to. A silent port 53 must not cost every connection the
	// tunnel step, and each timed-out dial leaves a pending channel on sshd
	// (see sshDialerCfg).
	upstreamPause = 10 * time.Second
	// dnsDegradedWindow is how long a fallback to the local resolver keeps
	// the DNS status degraded.
	dnsDegradedWindow = time.Minute
)

// SetDOH makes cached resolution query the given DNS-over-HTTPS endpoint
// (https://host/dns-query, RFC 8484) through the SSH dialer. It protects the
// way from the VPS to the DNS server too; otherwise it works like
// SetTunnelDNS.
func (e *RuleEngine) SetDOH(host string, d dialer) {
	e.dns.dohHost = host
	e.dns.dohClient = tunnelHTTPClient(e.dns.ctx, d, 0, nil)
	e.dns.dohClient.CheckRedirect = checkDoHRedirect
	e.dns.tunnel = []*upstream{{name: host, lookup: e.dns.dohLookup}}
	e.dns.tunnelUp = d.Connected
}

// SetTunnelDNS makes cached resolution query the given DNS servers (host:port)
// over TCP through the SSH dialer, so DNS traffic stays inside the encrypted
// tunnel and cannot be poisoned on the client side. A definitive answer
// (including NXDOMAIN) is authoritative; the local resolver is used only when
// no server answers. Direct destinations keep using local DNS.
func (e *RuleEngine) SetTunnelDNS(servers []string, d dialer) {
	e.dns.tunnel = make([]*upstream, 0, len(servers))
	for _, server := range servers {
		name := server
		if host, port, err := net.SplitHostPort(server); err == nil && port == "53" {
			name = host
		}
		lookup := dnsServerLookup(d, server)
		e.dns.tunnel = append(e.dns.tunnel, &upstream{name: name, lookup: func(ctx context.Context, host string) ([]netip.Addr, time.Time, error) {
			addrs, err := lookup(ctx, host)
			return addrs, time.Time{}, err
		}})
	}
	e.dns.tunnelUp = d.Connected
}

// dnsCache caches DNS resolution with TTL.
type dnsCache struct {
	mu          sync.Mutex
	cache       map[string]cacheEntry
	ttl         time.Duration
	negativeTTL time.Duration
	ctx         context.Context
	cancel      context.CancelFunc
	closeOnce   sync.Once
	stopped     chan struct{}
	workers     sync.WaitGroup
	// lookups counts real resolver queries (cache hits and IP literals
	// excluded); tests use it to assert caching without timing tricks.
	lookups   atomic.Int64
	dohHost   string
	dohClient *http.Client
	// tunnel holds the resolvers reached through the SSH tunnel, tried in
	// order.
	tunnel []*upstream
	// tunnelUp reports the SSH tunnel state: with the tunnel down a failed
	// query says nothing about the server.
	tunnelUp func() bool
	// localOnNXDomain asks the local resolver after a tunnel not-found.
	localOnNXDomain bool
	// fallbacks counts lookups no tunnel resolver answered; lastFallback is
	// the Unix time in nanoseconds of the last one.
	fallbacks    atomic.Int64
	lastFallback atomic.Int64
	// now is time.Now, replaced in tests of the pause.
	now func() time.Time
	// localLookup replaces net.DefaultResolver in tests; nil means the
	// system resolver.
	localLookup func(ctx context.Context, host string) ([]net.IPAddr, error)
	// sf coalesces concurrent cache misses for one key into a single
	// resolver round-trip (see cachedLookup).
	sf singleflight.Group
}

// startPurge launches a background goroutine that purges expired entries every TTL.
func (c *dnsCache) startPurge(ctx context.Context) {
	if !c.beginWork() {
		return
	}
	go func() {
		defer c.workers.Done()
		ticker := time.NewTicker(c.ttl)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-c.ctx.Done():
				return
			case <-ticker.C:
				c.purge()
			}
		}
	}()
}

// Admission and stop share the mutex so no worker can enter after Wait starts.
func (c *dnsCache) beginWork() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ctx.Err() != nil {
		return false
	}
	c.workers.Add(1)
	return true
}

func (c *dnsCache) stop() {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.cancel()
		c.mu.Unlock()
		// Closing an SSH channel can wait on the shared transport writer.
		// Do not prevent the caller from stopping that transport next.
		go func() {
			if c.dohClient != nil {
				c.dohClient.CloseIdleConnections()
			}
			c.workers.Wait()
			close(c.stopped)
		}()
	})
}

func (c *dnsCache) waitStopped(ctx context.Context) error {
	select {
	case <-c.stopped:
		return nil
	default:
	}
	select {
	case <-c.stopped:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
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
	// neg marks a cached authoritative NXDOMAIN: repeats within the
	// negative TTL fail fast without touching the network.
	neg bool
	// localDirect is lookupResult.localDirect.
	localDirect bool
}

// ResolveAll resolves host to all of its IPv4 and IPv6 addresses. IP
// literals are returned as-is without touching the resolver or the cache.
// The host is normalized (see normalizeHost) so every spelling of one name
// shares one cache entry.
func (c *dnsCache) ResolveAll(ctx context.Context, host string) ([]netip.Addr, error) {
	addrs, _, err := c.resolveTunnel(ctx, host)
	return addrs, err
}

// resolveTunnel is ResolveAll that also reports lookupResult.localDirect.
func (c *dnsCache) resolveTunnel(ctx context.Context, host string) ([]netip.Addr, bool, error) {
	host = normalizeHost(host)
	res, err := c.cachedLookup(ctx, host, host, c.lookup)
	return res.addrs, res.localDirect, err
}

// localResolveAll resolves host through the local resolver only, never a
// tunnel resolver: direct-routed destinations keep their resolution local.
// Results are cached under a separate key space so the two policies cannot
// shadow each other.
func (c *dnsCache) localResolveAll(ctx context.Context, host string) ([]netip.Addr, error) {
	host = normalizeHost(host)
	res, err := c.cachedLookup(ctx, "local:"+host, host, func(ctx context.Context, h string) (lookupResult, error) {
		addrs, err := c.lookupLocal(ctx, h)
		return lookupResult{addrs: addrs, authoritative: true}, err // local DNS IS the policy for this key space
	})
	return res.addrs, err
}

// cachedLookup serves key from the cache or runs lookup and stores the
// result. lookup must return unmapped addresses; its authoritative field
// reports whether the answer is authoritative for the key's policy (see
// lookupResult) — only authoritative answers are cached, so a degraded answer
// degrades one connection instead of poisoning the whole TTL. Negative entries
// use negativeTTL. Both cache lifetimes are capped by validUntil when supplied.
// Concurrent misses of the same key share one lookup through singleflight.
func (c *dnsCache) cachedLookup(ctx context.Context, key, host string, lookup func(context.Context, string) (lookupResult, error)) (lookupResult, error) {
	if err := ctx.Err(); err != nil {
		return lookupResult{}, err
	}
	if err := c.ctx.Err(); err != nil {
		return lookupResult{}, err
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return lookupResult{addrs: []netip.Addr{ip.Unmap()}}, nil
	}

	c.mu.Lock()
	if entry, ok := c.cache[key]; ok && time.Now().Before(entry.expires) {
		c.mu.Unlock()
		if entry.neg {
			return lookupResult{}, NewDNSError(host, errNotFound)
		}
		return lookupResult{addrs: entry.addrs, authoritative: true, localDirect: entry.localDirect}, nil
	}
	c.mu.Unlock()

	result := c.sf.DoChan(key, func() (any, error) {
		if !c.beginWork() {
			return lookupResult{}, c.ctx.Err()
		}
		defer c.workers.Done()
		// The shared lookup runs on a context detached from the caller
		// that happened to win the race — one caller hanging up must not
		// kill the lookup the others are waiting on. It keeps the same
		// 5 s bound.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		stop := context.AfterFunc(c.ctx, cancel)
		defer stop()
		if err := c.ctx.Err(); err != nil {
			return lookupResult{}, err
		}
		c.lookups.Add(1)

		res, err := lookup(ctx, host)
		if ctx.Err() != nil {
			return lookupResult{}, ctx.Err()
		}
		if err == nil && len(res.addrs) == 0 {
			return lookupResult{}, fmt.Errorf("no address for %s", host)
		}
		negative := errors.Is(err, errNotFound)
		if res.authoritative && (err == nil || negative) {
			ttl := c.ttl
			if negative {
				ttl = c.negativeTTL
			}
			now := time.Now()
			expires := now.Add(ttl)
			if !res.validUntil.IsZero() && res.validUntil.Before(expires) {
				expires = res.validUntil
			}
			if now.Before(expires) {
				c.store(key, cacheEntry{addrs: res.addrs, localDirect: res.localDirect, expires: expires, neg: negative})
			}
		}
		if err != nil {
			return lookupResult{}, NewDNSError(host, err)
		}
		return res, nil
	})
	select {
	case <-ctx.Done():
		return lookupResult{}, ctx.Err()
	case <-c.ctx.Done():
		return lookupResult{}, c.ctx.Err()
	case r := <-result:
		if err := ctx.Err(); err != nil {
			return lookupResult{}, err
		}
		if err := c.ctx.Err(); err != nil {
			return lookupResult{}, err
		}
		if r.Err != nil {
			return lookupResult{}, r.Err
		}
		return r.Val.(lookupResult), nil
	}
}

// store writes entry under key, evicting the oldest entry when full.
func (c *dnsCache) store(key string, entry cacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.cache) >= dnsCacheMaxSize {
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
	c.cache[key] = entry
}

// errNotFound marks a definitive not-found from a tunnel resolver (NXDOMAIN
// or an empty answer); unlike a failure it does not try the next server.
var errNotFound = errors.New("no answer")

// errUnreachable marks a tunnel resolver no channel could be opened to. sshd
// confirms a channel only once it has connected, so this is about the server.
// Anything after that, SERVFAIL or silence, may be about the one name: a web
// page must not be able to switch the tunnel resolvers off by asking for a
// broken domain.
var errUnreachable = errors.New("server unreachable")

// lookupResult is one resolver answer. authoritative marks it for the key
// space: tunnel resolver answers are; the fallback when no resolver answers is
// not — it must not be cached under the tunnel key or it would route tunnel
// destinations by home DNS for the whole TTL. localDirect marks a local answer
// whose private addresses may go direct (see notFound and lookup).
type lookupResult struct {
	addrs         []netip.Addr
	validUntil    time.Time // Zero leaves the cache's fixed TTL in effect.
	authoritative bool
	localDirect   bool
}

// upstream is one tunnel resolver: a DNS server or the DoH endpoint.
type upstream struct {
	name   string
	lookup func(context.Context, string) ([]netip.Addr, time.Time, error)

	mu sync.Mutex
	// pausedUntil is when lookups may use this resolver again, the zero time
	// when it is reachable. probing is set while the one lookup allowed after
	// a pause is out, so a burst of new names does not pile up on a resolver
	// that is still dead.
	pausedUntil time.Time
	probing     bool
	ok, fail    int64 // real lookups since the process start
	lastOKAt    time.Time
	lastRTT     time.Duration
	lastFailed  bool
	lastErr     string
}

// dnsServerStatus is the /api/status view of one tunnel resolver.
type dnsServerStatus struct {
	Name       string `json:"name"`
	OK         int64  `json:"ok"`
	Fail       int64  `json:"fail"`
	RTTMs      int64  `json:"rtt_ms"`
	LastOKAt   int64  `json:"last_ok_at"`
	LastFailed bool   `json:"last_failed"`
	Paused     bool   `json:"paused"`
	Error      string `json:"error"`
}

// dnsStatus is the /api/status view of the tunnel resolvers.
type dnsStatus struct {
	Mode           string            `json:"mode"`
	Degraded       bool              `json:"degraded"`
	LocalFallbacks int64             `json:"local_fallbacks"`
	LastFallbackAt int64             `json:"last_fallback_at"`
	Servers        []dnsServerStatus `json:"servers"`
}

// claim reports whether a lookup may use the resolver now.
func (u *upstream) claim(now time.Time) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.pausedUntil.IsZero() {
		return true
	}
	if u.probing || now.Before(u.pausedUntil) {
		return false
	}
	u.probing = true
	return true
}

// releaseProbes ends the probes of a finished lookup.
func releaseProbes(claimed []*upstream) {
	for _, u := range claimed {
		u.mu.Lock()
		u.probing = false
		u.mu.Unlock()
	}
}

func (u *upstream) status(now time.Time) dnsServerStatus {
	u.mu.Lock()
	defer u.mu.Unlock()
	st := dnsServerStatus{
		Name:       u.name,
		OK:         u.ok,
		Fail:       u.fail,
		RTTMs:      u.lastRTT.Milliseconds(),
		LastFailed: u.lastFailed,
		Paused:     u.pausedUntil.After(now),
		Error:      u.lastErr,
	}
	if !u.lastOKAt.IsZero() {
		st.LastOKAt = u.lastOKAt.Unix()
	}
	return st
}

// DNSStatus reports the tunnel resolvers: any answer, NXDOMAIN too, counts as
// a success; cache hits and skipped resolvers count as nothing. Degraded means
// a resolver is paused or names reached the local resolver in the last minute.
// A failed last lookup does not: it may be about one name, and a spare server
// that nothing uses would stay failed for good.
func (e *RuleEngine) DNSStatus() dnsStatus {
	c := e.dns
	now := c.now()
	st := dnsStatus{Mode: "servers", LocalFallbacks: c.fallbacks.Load()}
	if c.dohClient != nil {
		st.Mode = "doh"
	}
	if last := c.lastFallback.Load(); last != 0 {
		at := time.Unix(0, last)
		st.LastFallbackAt = at.Unix()
		st.Degraded = now.Sub(at) < dnsDegradedWindow
	}
	for _, u := range c.tunnel {
		s := u.status(now)
		st.Degraded = st.Degraded || s.Paused
		st.Servers = append(st.Servers, s)
	}
	return st
}

// lookup resolves host through the tunnel resolvers in order, skipping the
// paused ones, and falls back to the local resolver only when none answers.
// That answer may go direct only while the tunnel is down: with the tunnel up,
// a private address from a resolver of the provider may be a block page, and
// a tunnel destination must not go there in the clear.
func (c *dnsCache) lookup(ctx context.Context, host string) (lookupResult, error) {
	var active []*upstream
	now := c.now()
	for _, u := range c.tunnel {
		if u.claim(now) {
			active = append(active, u)
		}
	}
	defer releaseProbes(active)

	tunnelCtx, cancel := context.WithTimeout(ctx, tunnelLookupTimeout)
	defer cancel()
	deadline, _ := tunnelCtx.Deadline()
	for i, u := range active {
		// An equal share of what is left, so a silent first server leaves
		// the next one the same time.
		uctx, ucancel := context.WithTimeout(tunnelCtx, time.Until(deadline)/time.Duration(len(active)-i))
		start := time.Now()
		addrs, validUntil, err := u.lookup(uctx, host)
		rtt := time.Since(start)
		ucancel()
		if err == nil {
			c.upstreamAnswered(u, rtt)
			return lookupResult{addrs: addrs, validUntil: validUntil, authoritative: true}, nil
		}
		if errors.Is(err, errNotFound) {
			c.upstreamAnswered(u, rtt)
			return c.notFound(ctx, host, validUntil)
		}
		c.upstreamFailed(u, err)
	}

	c.fallbacks.Add(1)
	c.lastFallback.Store(c.now().UnixNano())
	addrs, err := c.lookupLocal(ctx, host)
	return lookupResult{addrs: addrs, localDirect: c.localOnNXDomain && !c.tunnelUp()}, err
}

// notFound handles a definitive not-found from a tunnel resolver: it stands,
// unless localOnNXDomain lets the local resolver answer for names public DNS
// does not know. Asking was a policy choice, so that answer is authoritative,
// and a local failure leaves the name not found.
func (c *dnsCache) notFound(ctx context.Context, host string, validUntil time.Time) (lookupResult, error) {
	if c.localOnNXDomain {
		if addrs, err := c.lookupLocal(ctx, host); err == nil {
			return lookupResult{addrs: addrs, authoritative: true, localDirect: true}, nil
		}
	}
	return lookupResult{validUntil: validUntil, authoritative: true}, errNotFound
}

// upstreamAnswered records an answer of a resolver.
func (c *dnsCache) upstreamAnswered(u *upstream, rtt time.Duration) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.pausedUntil = time.Time{}
	u.ok++
	u.lastOKAt = c.now()
	u.lastRTT = rtt
	u.lastFailed = false
}

// upstreamFailed records a failed lookup and pauses a resolver that cannot be
// reached. With the tunnel down the failure is instant and says nothing about
// the server.
func (c *dnsCache) upstreamFailed(u *upstream, err error) {
	if !c.tunnelUp() {
		return
	}
	reachable := !errors.Is(err, errUnreachable)
	u.mu.Lock()
	u.fail++
	u.lastFailed = true
	u.lastErr = err.Error()
	if reachable {
		u.pausedUntil = time.Time{}
		u.mu.Unlock()
		return
	}
	u.pausedUntil = c.now().Add(upstreamPause)
	name := u.name
	u.mu.Unlock()
	log.Warn().Str("resolver", name).Err(err).Dur("pause", upstreamPause).Msg("tunnel DNS unreachable, pausing the resolver")
}

// lookupLocal resolves host through the local resolver. Unlike lookup it
// never touches a tunnel resolver: its NXDOMAIN is authoritative for tunnel
// destinations but must not affect direct ones, whose names are often unknown
// to public DNS.
func (c *dnsCache) lookupLocal(ctx context.Context, host string) ([]netip.Addr, error) {
	lookup := net.DefaultResolver.LookupIPAddr
	if c.localLookup != nil {
		lookup = c.localLookup
	}
	addrs, err := lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	return toNetip(addrs), nil
}

// toNetip converts resolver results to unmapped netip addresses.
func toNetip(addrs []net.IPAddr) []netip.Addr {
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if ip, ok := netip.AddrFromSlice(a.IP); ok {
			out = append(out, ip.Unmap())
		}
	}
	return out
}

// dohResponse is the subset used by the legacy JSON API.
type dohResponse struct {
	Status *int `json:"Status"`
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

// dohJSONQuery queries the legacy JSON API for one record type.
// errNotFound marks a definitive NXDOMAIN; any other error is a
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
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, dohHTTPStatus(resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, dohMaxResponse+1))
	if err != nil {
		return nil, err
	}
	if len(body) > dohMaxResponse {
		return nil, errors.New("doh: JSON response exceeds 1 MiB")
	}
	var d dohResponse
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, err
	}
	if d.Status == nil {
		return nil, errors.New("doh: JSON response has no Status")
	}
	if *d.Status == 3 { // NXDOMAIN
		return nil, errNotFound
	}
	if *d.Status != 0 {
		return nil, fmt.Errorf("doh: JSON DNS status %d", *d.Status)
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

// dohLookup selects a format for this lookup using the first A query.
func (c *dnsCache) dohLookup(ctx context.Context, host string) ([]netip.Addr, time.Time, error) {
	a, err := newDoHWireQuestion(host, dnsmessage.TypeA)
	if err != nil {
		return nil, time.Time{}, err
	}
	aaaa, err := newDoHWireQuestion(host, dnsmessage.TypeAAAA)
	if err != nil {
		return nil, time.Time{}, err
	}
	var connected atomic.Bool
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(httptrace.GotConnInfo) { connected.Store(true) },
	})
	first, err := dohWireQuery(ctx, c.dohClient, c.dohHost, a)
	if status, ok := err.(dohHTTPStatus); ok && ctx.Err() == nil {
		switch status {
		case http.StatusBadRequest, http.StatusNotAcceptable, http.StatusUnsupportedMediaType:
			addrs, jsonErr := c.lookupDoHJSON(ctx, host)
			if jsonErr != nil && !errors.Is(jsonErr, errNotFound) {
				jsonErr = fmt.Errorf("%v, JSON retry: %w", status, jsonErr)
			}
			return addrs, time.Time{}, jsonErr
		}
	}
	if err != nil {
		if !connected.Load() && !errors.Is(err, errNotFound) {
			err = fmt.Errorf("%w: %v", errUnreachable, err)
		}
		return nil, first.validUntil, err
	}
	second, err := dohWireQuery(ctx, c.dohClient, c.dohHost, aaaa)
	if err != nil {
		return nil, second.validUntil, err
	}
	validUntil := first.validUntil
	if second.validUntil.Before(validUntil) {
		validUntil = second.validUntil
	}
	addrs := append(first.addrs, second.addrs...)
	if len(addrs) == 0 {
		return nil, validUntil, errNotFound
	}
	return addrs, validUntil, nil
}

func (c *dnsCache) lookupDoHJSON(ctx context.Context, host string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, q := range [2]dohQuery{dohQueryA, dohQueryAAAA} {
		addrs, err := dohJSONQuery(ctx, c.dohClient, c.dohHost, host, q)
		if err != nil {
			return nil, err
		}
		out = append(out, addrs...)
	}
	if len(out) == 0 {
		return nil, errNotFound
	}
	return out, nil
}

// dnsServerLookup returns a lookup that asks one DNS server over TCP through
// the SSH tunnel. The Go resolver gets host as a rooted name, so the search
// domains and /etc/hosts of this machine stay out of it, and it picks TCP
// framing by itself: an SSH channel is no PacketConn. An SSH channel has no
// deadlines either and the resolver ignores that error, so the channel is
// closed with the context; otherwise a silent server would keep it and its
// reader goroutine forever.
func dnsServerLookup(d dialer, server string) func(context.Context, string) ([]netip.Addr, error) {
	return func(ctx context.Context, host string) ([]netip.Addr, error) {
		var opened atomic.Bool
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			conn, err := d.DialContext(ctxWithNoTrack(ctx), "tcp", server)
			if err != nil {
				return nil, err
			}
			opened.Store(true)
			context.AfterFunc(ctx, func() { conn.Close() })
			return conn, nil
		}}
		addrs, err := r.LookupIPAddr(ctx, host+".")
		if err != nil {
			var dnsErr *net.DNSError
			if !errors.As(err, &dnsErr) {
				return nil, err
			}
			if dnsErr.IsNotFound {
				return nil, errNotFound
			}
			// Not dnsErr.Error(): it names the server from the local
			// resolv.conf, which this query never went to.
			if !opened.Load() {
				return nil, fmt.Errorf("%w: %s", errUnreachable, dnsErr.Err)
			}
			return nil, errors.New(dnsErr.Err)
		}
		return toNetip(addrs), nil
	}
}
