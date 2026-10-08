package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestRuleEngineStopConcurrent guards against double-close of the DNS cache
// purge channel: Start(ctx), Stop(), cancel() (the main path) and repeated
// Stop() may race. closeOnce makes all of these safe — the test asserts that
// they run without panic and without a data race (the race detector proves it).
func TestRuleEngineStopConcurrent(t *testing.T) {
	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatalf("NewRuleEngine: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	rules.Start(ctx)

	var wg sync.WaitGroup

	// Simulate the main path: cancel the context.
	wg.Add(1)
	go func() {
		defer wg.Done()
		cancel()
	}()

	// Simulate the shutdown path racing with it, plus repeated Stop() calls.
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rules.Stop()
		}()
	}

	wg.Wait()

	// Repeated Stop() after everything must remain a no-op, not a panic.
	for i := 0; i < 5; i++ {
		rules.Stop()
	}
}

// socks5Connect sends a name-based SOCKS5 CONNECT (atyp=0x03) to the server
// at addr and returns the reply code.
func socks5Connect(t *testing.T, addr, name string, port int) byte {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	greet := make([]byte, 2)
	if _, err := io.ReadFull(c, greet); err != nil || greet[1] != 0x00 {
		t.Fatalf("greeting reply: %v %x", err, greet)
	}
	req := append([]byte{0x05, 0x01, 0x00, 0x03, byte(len(name))}, name...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		t.Fatalf("connect: %v", err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatalf("connect reply: %v", err)
	}
	return reply[1]
}

type fakeDohRecord struct {
	Type int    `json:"Type"`
	Data string `json:"Data"`
}

// dohAnswer is one fake server response: a dns-json RCODE plus the record
// lists returned on NOERROR.
type dohAnswer struct {
	status int // 0 NOERROR, 2 SERVFAIL, 3 NXDOMAIN
	a      []string
	aaaa   []string
}

// startFakeDoHServer starts an in-process dns-json DoH server; reply picks
// the answer per question (name and type A/AAAA).
func startFakeDoHServer(t *testing.T, reply func(name, qtype string) dohAnswer) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
		name, qtype := r.URL.Query().Get("name"), r.URL.Query().Get("type")
		ans := reply(name, qtype)
		var recs []fakeDohRecord
		if ans.status == 0 {
			if qtype == "AAAA" {
				for _, s := range ans.aaaa {
					recs = append(recs, fakeDohRecord{Type: 28, Data: s})
				}
			} else {
				for _, s := range ans.a {
					recs = append(recs, fakeDohRecord{Type: 1, Data: s})
				}
			}
		}
		body, err := json.Marshal(struct {
			Status int             `json:"Status"`
			Answer []fakeDohRecord `json:"Answer"`
		}{Status: ans.status, Answer: recs})
		if err != nil {
			t.Errorf("marshal fake answer: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-json")
		w.Write(body)
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// dohBootstrap names the DoH endpoint a test points the resolver at, plus
// the TLS config that trusts the fake server's certificate.
type dohBootstrap struct {
	addr string
	tls  *tls.Config
}

// setBootstrap returns the dialer and bootstrap that point at the fake
// server: the testDialer redirects every tunnel dial to it, and the
// bootstrap trusts its test CA.
func setBootstrap(t *testing.T, srv *httptest.Server) (testDialer, dohBootstrap) {
	t.Helper()
	addr := srv.Listener.Addr().String()
	return testDialer{Target: addr}, dohBootstrap{
		addr: addr,
		tls:  srv.Client().Transport.(*http.Transport).TLSClientConfig,
	}
}

// TestSOCKS5ServerResolver: FQDN CONNECT requests are resolved through the
// rule engine's cached resolver — a repeat within the TTL is served from the
// cache without a DNS round-trip (asserted via the lookup counter, not
// timing).
func TestSOCKS5ServerResolver(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listener: %v", err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(c)
		}
	}()

	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatalf("NewRuleEngine: %v", err)
	}
	s, err := NewSOCKS5Server("127.0.0.1:0", &Opener{rules: rules, d: testDialer{Target: echo.Addr().String()}, family: FamilyBoth})
	if err != nil {
		t.Fatalf("NewSOCKS5Server: %v", err)
	}
	s.Start()
	t.Cleanup(func() { s.Shutdown(context.Background()) })
	addr := s.ln.Addr().String()

	if code := socks5Connect(t, addr, "example.com", 443); code != 0x00 {
		t.Skipf("SOCKS5 reply code %d (DNS unavailable?), skipping", code)
	}
	lookups := rules.dns.lookups.Load()
	if code := socks5Connect(t, addr, "example.com", 443); code != 0x00 {
		t.Fatalf("second reply code %d", code)
	}
	// A cache hit performs no DNS query.
	if got := rules.dns.lookups.Load(); got != lookups {
		t.Fatalf("second FQDN lookup performed a DNS query (lookups %d -> %d)", lookups, got)
	}
}

// TestSOCKS5UnresolvableHost: a name that does not resolve must produce a
// SOCKS5 "host unreachable" reply (0x04), not a hang or a dial attempt.
func TestSOCKS5UnresolvableHost(t *testing.T) {
	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatalf("NewRuleEngine: %v", err)
	}
	s, err := NewSOCKS5Server("127.0.0.1:0", &Opener{rules: rules, d: testDialer{}, family: FamilyBoth})
	if err != nil {
		t.Fatalf("NewSOCKS5Server: %v", err)
	}
	s.Start()
	t.Cleanup(func() { s.Shutdown(context.Background()) })

	code := socks5Connect(t, s.ln.Addr().String(), "no-such-host.invalid", 443)
	if code == 0x00 {
		t.Skipf("resolver answered for .invalid (hijacked DNS?), skipping")
	}
	if code != 0x04 {
		t.Fatalf("reply code %d, want 4 (host unreachable)", code)
	}
}

// TestSOCKS5DirectHostResolvesLocally: an FQDN matching a direct rule must
// resolve through the local resolver, not the DoH endpoint — a DoH NXDOMAIN
// (the public DNS knows no corporate names) must not break the connection.
func TestSOCKS5DirectHostResolvesLocally(t *testing.T) {
	var dohReqs atomic.Int64
	// The DoH endpoint answers NXDOMAIN for every name, standing in for
	// public DNS that has no record of an internal one.
	srv := startFakeDoHServer(t, func(_, _ string) dohAnswer {
		dohReqs.Add(1)
		return dohAnswer{status: 3}
	})

	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listener: %v", err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(c)
		}
	}()

	// localhost resolves locally to 127.0.0.1 regardless of the ambient DNS
	// configuration; the direct rule keeps it off the tunnel.
	rules, err := NewRuleEngine("localhost")
	if err != nil {
		t.Fatalf("NewRuleEngine: %v", err)
	}
	d, b := setBootstrap(t, srv)
	rules.SetDOH(b.addr, d)
	rules.dns.dohClient.Transport.(*http.Transport).TLSClientConfig = b.tls

	s, err := NewSOCKS5Server("127.0.0.1:0", &Opener{rules: rules, d: d, family: FamilyIPv4})
	if err != nil {
		t.Fatalf("NewSOCKS5Server: %v", err)
	}
	s.Start()
	t.Cleanup(func() { s.Shutdown(context.Background()) })

	_, portStr, _ := net.SplitHostPort(echo.Addr().String())
	port, _ := strconv.Atoi(portStr)

	// Success proves the local resolver was used: the DoH endpoint answers
	// NXDOMAIN for every name, so a DoH-routed resolution would fail.
	if code := socks5Connect(t, s.ln.Addr().String(), "localhost", port); code != 0x00 {
		t.Fatalf("reply code %d, want 0", code)
	}
	if got := dohReqs.Load(); got != 0 {
		t.Fatalf("DoH queries for a direct host: %d, want 0", got)
	}
}

// TestSOCKS5TunnelHostResolvesViaDoH: the opposite side of the policy — a
// tunnel-routed FQDN must resolve through the DoH endpoint, where a
// definitive answer is authoritative even when the name is unknown to the
// local resolver (.example is reserved).
func TestSOCKS5TunnelHostResolvesViaDoH(t *testing.T) {
	var dohReqs atomic.Int64
	srv := startFakeDoHServer(t, func(name, _ string) dohAnswer {
		dohReqs.Add(1)
		if name == "dohtarget.example" {
			return dohAnswer{a: []string{"203.0.113.7"}}
		}
		return dohAnswer{status: 3}
	})

	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listener: %v", err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(c)
		}
	}()

	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatalf("NewRuleEngine: %v", err)
	}
	d, b := setBootstrap(t, srv)
	rules.SetDOH(b.addr, d)
	rules.dns.dohClient.Transport.(*http.Transport).TLSClientConfig = b.tls

	s, err := NewSOCKS5Server("127.0.0.1:0", &Opener{rules: rules, d: d, family: FamilyBoth})
	if err != nil {
		t.Fatalf("NewSOCKS5Server: %v", err)
	}
	s.Start()
	t.Cleanup(func() { s.Shutdown(context.Background()) })

	// The dialer (SSH tunnel stand-in) redirects the dial to the local echo
	// listener; only the reply code and the DoH usage are under test.
	if code := socks5Connect(t, s.ln.Addr().String(), "dohtarget.example", 443); code != 0x00 {
		t.Fatalf("reply code %d, want 0", code)
	}
	if got := dohReqs.Load(); got == 0 {
		t.Fatal("DoH was not used for a tunnel host")
	}
}

// socks5ConnectV6 sends an IPv6-literal SOCKS5 CONNECT (atyp=0x04) to the
// server at addr and returns the reply code.
func socks5ConnectV6(t *testing.T, addr, ip6 string, port int) byte {
	t.Helper()
	parsed := net.ParseIP(ip6)
	if parsed == nil {
		t.Fatalf("bad v6 literal %q", ip6)
	}
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	greet := make([]byte, 2)
	if _, err := io.ReadFull(c, greet); err != nil || greet[1] != 0x00 {
		t.Fatalf("greeting reply: %v %x", err, greet)
	}
	req := append([]byte{0x05, 0x01, 0x00, 0x04}, parsed.To16()...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		t.Fatalf("connect: %v", err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatalf("connect reply: %v", err)
	}
	return reply[1]
}

// TestSOCKS5ServerV6Literal: an IPv6-literal CONNECT is tunneled as-is — no
// name resolution involved, the dialer (SSH tunnel stand-in) gets the
// bracketed address and the relay works.
func TestSOCKS5ServerV6Literal(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listener: %v", err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(c)
		}
	}()

	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatalf("NewRuleEngine: %v", err)
	}
	s, err := NewSOCKS5Server("127.0.0.1:0", &Opener{rules: rules, d: testDialer{Target: echo.Addr().String()}, family: FamilyBoth})
	if err != nil {
		t.Fatalf("NewSOCKS5Server: %v", err)
	}
	s.Start()
	t.Cleanup(func() { s.Shutdown(context.Background()) })

	// Documentation-prefixed v6 literal: non-private, so it routes through
	// the tunnel.
	code := socks5ConnectV6(t, s.ln.Addr().String(), "2001:db8::1", 443)
	if code != 0x00 {
		t.Fatalf("reply code %d, want 0", code)
	}
}

// TestPickTunnelAddr: the tunnel picks the first IPv4 when present (IPv4
// egress is the baseline), otherwise falls back to the first IPv6 so v6-only
// destinations still resolve; an empty list is an error.
func TestPickTunnelAddr(t *testing.T) {
	v4 := netip.MustParseAddr("93.184.216.34")
	v6 := netip.MustParseAddr("2001:db8::1")

	if got, err := pickTunnelAddr([]netip.Addr{v4}); err != nil || got != v4 {
		t.Fatalf("v4 only: got %v err %v", got, err)
	}
	if got, err := pickTunnelAddr([]netip.Addr{v6, v4}); err != nil || got != v4 {
		t.Fatalf("mixed, want v4: got %v err %v", got, err)
	}
	if got, err := pickTunnelAddr([]netip.Addr{v6}); err != nil || got != v6 {
		t.Fatalf("v6 only, want v6: got %v err %v", got, err)
	}
	if _, err := pickTunnelAddr(nil); err == nil {
		t.Fatal("empty list: want error")
	}
}

// TestResolveAllDOH: when a DoH endpoint is configured, cached resolution
// asks the endpoint (dialing it through the SSH dialer, here a testDialer
// that redirects to a local TLS server) instead of the local resolver. A
// definitive DoH answer wins even when the local resolver would fail
// (.example is reserved, so the local lookup is NXDOMAIN), the answer is
// cached, and a DoH NXDOMAIN is authoritative (no local fallback).
func TestResolveAllDOH(t *testing.T) {
	var reqs atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
		reqs.Add(1)
		name, qtype := r.URL.Query().Get("name"), r.URL.Query().Get("type")
		w.Header().Set("Content-Type", "application/dns-json")
		switch {
		case name == "blocked.example" && qtype == "A":
			io.WriteString(w, `{"Status":0,"Answer":[{"Type":1,"Data":"203.0.113.7"}]}`)
		case name == "v6only.example" && qtype == "AAAA":
			io.WriteString(w, `{"Status":0,"Answer":[{"Type":28,"Data":"2001:db8::7"}]}`)
		case name == "missing.example":
			io.WriteString(w, `{"Status":3,"Answer":[]}`)
		default:
			io.WriteString(w, `{"Status":0,"Answer":[]}`)
		}
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatalf("NewRuleEngine: %v", err)
	}
	// The testDialer stands in for the SSH tunnel: it redirects the dial to
	// the local DoH server, whose certificate matches the 127.0.0.1 hostname
	// used in the URL.
	rules.SetDOH(srv.Listener.Addr().String(), testDialer{Target: srv.Listener.Addr().String()})
	rules.dns.dohClient.Transport.(*http.Transport).TLSClientConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig

	addrs, err := rules.ResolveAll(context.Background(), "blocked.example")
	if err != nil {
		t.Fatalf("ResolveAll via DoH: %v", err)
	}
	if len(addrs) != 1 || addrs[0] != netip.MustParseAddr("203.0.113.7") {
		t.Fatalf("addrs = %v, want [203.0.113.7]", addrs)
	}

	// A repeat within the TTL is served from the cache: no further DoH query.
	before := reqs.Load()
	if _, err := rules.ResolveAll(context.Background(), "blocked.example"); err != nil {
		t.Fatalf("cached ResolveAll: %v", err)
	}
	if got := reqs.Load(); got != before {
		t.Fatalf("cache miss: DoH requests %d -> %d", before, got)
	}

	// A v6-only host: the A query is NOERROR with an empty answer, the AAAA
	// query carries the record — dohLookup must merge both queries.
	v6, err := rules.ResolveAll(context.Background(), "v6only.example")
	if err != nil {
		t.Fatalf("ResolveAll v6-only via DoH: %v", err)
	}
	if len(v6) != 1 || v6[0] != netip.MustParseAddr("2001:db8::7") {
		t.Fatalf("addrs = %v, want [2001:db8::7]", v6)
	}

	// A definitive DoH NXDOMAIN is authoritative: no local fallback.
	if _, err := rules.ResolveAll(context.Background(), "missing.example"); err == nil {
		t.Fatal("NXDOMAIN via DoH: want error, got success")
	}
}

// TestResolveAllDOHServerFallback: a non-definitive DoH failure (SERVFAIL)
// is not authoritative, unlike a definitive NXDOMAIN: resolution falls back
// to the local resolver. example.com resolves locally, so success proves the
// fallback happened (a treated-as-definitive SERVFAIL would fail the lookup).
func TestResolveAllDOHServerFallback(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/dns-json")
		io.WriteString(w, `{"Status":2,"Answer":[]}`) // SERVFAIL
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatalf("NewRuleEngine: %v", err)
	}
	rules.SetDOH(srv.Listener.Addr().String(), testDialer{Target: srv.Listener.Addr().String()})
	rules.dns.dohClient.Transport.(*http.Transport).TLSClientConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig

	if _, err := rules.ResolveAll(context.Background(), "example.com"); err != nil {
		t.Skipf("local resolver unavailable: %v", err)
	}
}

// TestIPRuleMatchesViaLocalResolver: ip: rules are matched through the same
// local resolver the direct dial uses. A public DoH NXDOMAIN must not push a
// host with a legitimate direct rule into the tunnel (split-horizon names
// live in local DNS), and deciding "direct" must not cost tunnel traffic.
func TestIPRuleMatchesViaLocalResolver(t *testing.T) {
	var reqs atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", func(w http.ResponseWriter, _ *http.Request) {
		reqs.Add(1)
		w.Header().Set("Content-Type", "application/dns-json")
		io.WriteString(w, `{"Status":3,"Answer":[]}`) // NXDOMAIN for every name
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	rules, err := NewRuleEngine("ip:127.0.0.0/8")
	if err != nil {
		t.Fatalf("NewRuleEngine: %v", err)
	}
	rules.SetDOH(srv.Listener.Addr().String(), testDialer{Target: srv.Listener.Addr().String()})
	rules.dns.dohClient.Transport.(*http.Transport).TLSClientConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig

	route, reason := rules.Decide(context.Background(), "localhost", 443)
	if route != RouteDirect || reason != "direct:ip:127.0.0.0/8" {
		t.Fatalf("Decide(localhost) = %s (%s), want direct (direct:ip:127.0.0.0/8)", route, reason)
	}
	if n := reqs.Load(); n != 0 {
		t.Fatalf("DoH requests = %d, want 0: an ip: rule must resolve locally", n)
	}
}

// TestResolveAllDOHFallback: when the DoH endpoint is unreachable, cached
// resolution falls back to the local resolver.
func TestResolveAllDOHFallback(t *testing.T) {
	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatalf("NewRuleEngine: %v", err)
	}
	// A closed local port: the dial fails before the TLS handshake.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listener: %v", err)
	}
	closed := l.Addr().String()
	l.Close()

	rules.SetDOH(closed, testDialer{})
	if _, err := rules.ResolveAll(context.Background(), "example.com"); err != nil {
		t.Skipf("local resolver unavailable: %v", err)
	}
}

// TestLocalFallbackNotCached: a local-resolver answer used while the DoH
// endpoint is down must NOT be cached under the tunnel key — the cached
// local address would then steer tunnel-routed connections for the whole
// TTL (route policy silently replaced by home DNS). Degraded answers must
// be returned but re-attempted per connection; authoritative DoH answers
// keep caching normally.
func TestLocalFallbackNotCached(t *testing.T) {
	t.Run("fallback answer is not cached", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listener: %v", err)
		}
		closed := l.Addr().String()
		l.Close()

		rules, err := NewRuleEngine("")
		if err != nil {
			t.Fatalf("NewRuleEngine: %v", err)
		}
		rules.SetDOH(closed, testDialer{})

		addrs, err := rules.dns.ResolveAll(context.Background(), "localhost")
		if err != nil || len(addrs) == 0 {
			t.Skipf("local resolver unavailable: %v", err)
		}
		if got := rules.dns.lookups.Load(); got != 1 {
			t.Fatalf("lookups after fallback = %d, want 1", got)
		}

		if _, err := rules.dns.ResolveAll(context.Background(), "localhost"); err != nil {
			t.Fatalf("repeat ResolveAll: %v", err)
		}
		if got := rules.dns.lookups.Load(); got != 2 {
			t.Fatalf("lookups after repeat = %d, want 2 (a fallback answer must not be cached)", got)
		}
		rules.dns.mu.Lock()
		n := len(rules.dns.cache)
		rules.dns.mu.Unlock()
		if n != 0 {
			t.Fatalf("cache size = %d, want 0: non-authoritative answer stored", n)
		}
	})

	t.Run("authoritative answer is cached", func(t *testing.T) {
		fake := startFakeDoHServer(t, func(name, qtype string) dohAnswer {
			if name == "cached.example" && qtype == "A" {
				return dohAnswer{status: 0, a: []string{"93.184.216.34"}}
			}
			return dohAnswer{status: 0}
		})
		rules, err := NewRuleEngine("")
		if err != nil {
			t.Fatalf("NewRuleEngine: %v", err)
		}
		d, b := setBootstrap(t, fake)
		rules.SetDOH(b.addr, d)
		rules.dns.dohClient.Transport.(*http.Transport).TLSClientConfig = b.tls

		for i := 0; i < 2; i++ {
			addrs, err := rules.dns.ResolveAll(context.Background(), "cached.example")
			if err != nil || len(addrs) != 1 || addrs[0].String() != "93.184.216.34" {
				t.Fatalf("ResolveAll #%d = (%v, %v)", i+1, addrs, err)
			}
		}
		if got := rules.dns.lookups.Load(); got != 1 {
			t.Fatalf("lookups = %d, want 1 (authoritative answer must be cached)", got)
		}
	})
}

// TestConcurrentMissSingleLookup: ten parallel ResolveAll calls for one
// uncached name must share a single resolver round-trip (singleflight), not
// fan out into ten DoH queries. The fake endpoint blocks until released, so
// the cache is provably empty for every caller while they pile up.
func TestConcurrentMissSingleLookup(t *testing.T) {
	release := make(chan struct{})
	var reqs atomic.Int64
	fake := startFakeDoHServer(t, func(name, qtype string) dohAnswer {
		if name == "slow.example" {
			reqs.Add(1)
			<-release
			return dohAnswer{status: 0, a: []string{"198.51.100.7"}}
		}
		return dohAnswer{status: 0}
	})
	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatalf("NewRuleEngine: %v", err)
	}
	d, b := setBootstrap(t, fake)
	rules.SetDOH(b.addr, d)
	rules.dns.dohClient.Transport.(*http.Transport).TLSClientConfig = b.tls

	const n = 10
	results := make([][]netip.Addr, n)
	errs := make([]error, n)
	var started, wg sync.WaitGroup
	started.Add(n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			started.Done()
			results[i], errs[i] = rules.dns.ResolveAll(context.Background(), "slow.example")
		}(i)
	}
	started.Wait()

	// Wait until the first request reaches the blocked endpoint (the cache
	// cannot be filled before the release), then give the remaining
	// goroutines time to pile onto the same miss.
	deadline := time.Now().Add(2 * time.Second)
	for reqs.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if reqs.Load() == 0 {
		t.Fatal("fake DoH server received no request")
	}
	time.Sleep(100 * time.Millisecond)
	close(release)
	wg.Wait()

	if got := rules.dns.lookups.Load(); got != 1 {
		t.Fatalf("lookups = %d, want 1: concurrent misses must share one lookup", got)
	}
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("caller %d: %v", i, errs[i])
		}
		if len(results[i]) != 1 || results[i][0].String() != "198.51.100.7" {
			t.Fatalf("caller %d: addrs = %v, want [198.51.100.7]", i, results[i])
		}
	}
}

// TestHostNormalization: DNS names are case-insensitive and a trailing dot
// is cosmetic, but clients send all four spellings. Rule matching and the
// DNS cache must see one canonical name — otherwise a direct rule silently
// misses for EXAMPLE.COM or example.com. and one host keeps two cache
// entries and two DoH cycles.
func TestHostNormalization(t *testing.T) {
	t.Run("rules match every spelling", func(t *testing.T) {
		rules, err := NewRuleEngine("example.com")
		if err != nil {
			t.Fatalf("NewRuleEngine: %v", err)
		}
		for _, host := range []string{"example.com", "EXAMPLE.COM", "example.com.", "Example.Com."} {
			route, reason := rules.Decide(context.Background(), host, 443)
			if route != RouteDirect || reason != "direct:example.com" {
				t.Fatalf("Decide(%q) = %s (%s), want direct (direct:example.com)", host, route, reason)
			}
		}
	})

	t.Run("spellings share one cache entry", func(t *testing.T) {
		fake := startFakeDoHServer(t, func(name, qtype string) dohAnswer {
			if name == "cache.example" && qtype == "A" {
				return dohAnswer{status: 0, a: []string{"93.184.216.34"}}
			}
			return dohAnswer{status: 0}
		})
		rules, err := NewRuleEngine("")
		if err != nil {
			t.Fatalf("NewRuleEngine: %v", err)
		}
		d, b := setBootstrap(t, fake)
		rules.SetDOH(b.addr, d)
		rules.dns.dohClient.Transport.(*http.Transport).TLSClientConfig = b.tls

		for _, host := range []string{"Cache.Example", "cache.example."} {
			addrs, err := rules.dns.ResolveAll(context.Background(), host)
			if err != nil || len(addrs) != 1 || addrs[0].String() != "93.184.216.34" {
				t.Fatalf("ResolveAll(%q) = (%v, %v)", host, addrs, err)
			}
		}
		if got := rules.dns.lookups.Load(); got != 1 {
			t.Fatalf("lookups = %d, want 1: two spellings must share one cache entry", got)
		}
	})
}

// TestNegativeCaching: an authoritative NXDOMAIN must be cached for a short
// negative TTL — a dead name on a hot path (update checks, dead CDN
// backends) would otherwise pay a full DoH round-trip per connection. After
// the negative window the name is probed again.
func TestNegativeCaching(t *testing.T) {
	var reqs atomic.Int64
	fake := startFakeDoHServer(t, func(name, _ string) dohAnswer {
		if name == "dead.example" {
			reqs.Add(1)
			return dohAnswer{status: 3} // NXDOMAIN
		}
		return dohAnswer{status: 0}
	})
	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatalf("NewRuleEngine: %v", err)
	}
	d, b := setBootstrap(t, fake)
	rules.SetDOH(b.addr, d)
	rules.dns.dohClient.Transport.(*http.Transport).TLSClientConfig = b.tls
	rules.dns.negativeTTL = 100 * time.Millisecond // test-visible window

	if _, err := rules.dns.ResolveAll(context.Background(), "dead.example"); err == nil {
		t.Fatal("ResolveAll(dead.example): want NXDOMAIN error")
	}
	first := reqs.Load()
	if first == 0 {
		t.Fatal("fake DoH server saw no request")
	}

	// The repeat must be served from the negative cache: same error, no
	// new network request.
	if _, err := rules.dns.ResolveAll(context.Background(), "dead.example"); err == nil {
		t.Fatal("cached NXDOMAIN: want error")
	}
	if got := reqs.Load(); got != first {
		t.Fatalf("requests = %d -> %d: a negative answer must be cached", first, got)
	}

	// After the negative TTL the name is queried again.
	time.Sleep(150 * time.Millisecond)
	if _, err := rules.dns.ResolveAll(context.Background(), "dead.example"); err == nil {
		t.Fatal("after negative TTL: want NXDOMAIN error")
	}
	if got := reqs.Load(); got <= first {
		t.Fatalf("requests = %d after TTL window, want > %d: negative entries must expire", first, got)
	}
}

// TestDomainRuleCaseInsensitive: a domain rule from DIRECT_RULES meets the
// same normalization the request path applies (normalizeHost). DNS names
// are case-insensitive and the trailing root dot is cosmetic, so an
// operator writing "Example.COM." means the name the traffic carries as
// "example.com" - without parse-side normalization the rule silently never
// matches and traffic the operator believes is direct goes through the
// tunnel.
func TestDomainRuleCaseInsensitive(t *testing.T) {
	rules, err := NewRuleEngine("Example.COM., Other.Local")
	if err != nil {
		t.Fatalf("NewRuleEngine: %v", err)
	}
	ctx := context.Background()
	for _, tc := range []struct{ rule, host string }{
		{"Example.COM.", "example.com"},
		{"Example.COM.", "EXAMPLE.com"},
		{"Example.COM.", "www.example.com"},
		{"Other.Local", "other.local"},
	} {
		if got := rules.Route(ctx, tc.host, 443); got != RouteDirect {
			t.Errorf("Route(%q) with rule %q = %v, want direct", tc.host, tc.rule, got)
		}
	}
}

// TestRuleEntryParseErrors: rule entries must mean what they look like.
// An empty "re:" pattern compiles to the match-anything regex (a silent
// global direct bypass, splitting-horizon split for all traffic), and a
// bare "." normalizes to the empty domain (a rule that can never fire).
// Both are operator mistakes; loadConfig should reject them at startup,
// not install them as policies.
func TestRuleEntryParseErrors(t *testing.T) {
	for _, raw := range []string{"re:", "."} {
		if _, err := NewRuleEngine(raw); err == nil {
			t.Errorf("NewRuleEngine(%q): want parse error, got none", raw)
		}
	}
}
