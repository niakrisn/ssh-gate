package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
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

	f := startFakeDNSServer(t, func(string) (byte, netip.Addr) { return 0, netip.MustParseAddr("93.184.216.34") })
	rules, _ := tunnelServers(t, &channelDialer{}, f.addr)
	s, err := NewSOCKS5Server("127.0.0.1:0", &Opener{rules: rules, d: testDialer{Target: echo.Addr().String()}, family: FamilyBoth})
	if err != nil {
		t.Fatalf("NewSOCKS5Server: %v", err)
	}
	s.Start()
	t.Cleanup(func() { s.Shutdown(context.Background()) })
	addr := s.ln.Addr().String()

	if code := socks5Connect(t, addr, "example.com", 443); code != 0x00 {
		t.Fatalf("first reply code %d", code)
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

// TestIPRuleMatchesViaDoH: ip: rules are matched against the tunnel-policy
// (DoH) answer, and a name that is tunneled in the end is never sent to the
// local resolver. Before the fix any ip: rule resolved every destination
// name locally, so the local network saw all tunneled names and a forged
// local answer could force traffic direct.
func TestIPRuleMatchesViaDoH(t *testing.T) {
	fake := startFakeDoHServer(t, func(name, qtype string) dohAnswer {
		switch {
		case name == "intranet.example" && qtype == "A":
			return dohAnswer{a: []string{"10.1.2.3"}}
		case name == "public.example" && qtype == "A":
			return dohAnswer{a: []string{"203.0.113.9"}}
		}
		return dohAnswer{status: 0}
	})
	rules, err := NewRuleEngine("ip:10.0.0.0/8")
	if err != nil {
		t.Fatalf("NewRuleEngine: %v", err)
	}
	d, b := setBootstrap(t, fake)
	rules.SetDOH(b.addr, d)
	rules.dns.dohClient.Transport.(*http.Transport).TLSClientConfig = b.tls
	var local atomic.Int64
	rules.dns.localLookup = func(context.Context, string) ([]net.IPAddr, error) {
		local.Add(1)
		// A forged local answer inside the rule CIDR.
		return []net.IPAddr{{IP: net.ParseIP("10.9.9.9")}}, nil
	}

	if route, reason := rules.Decide(context.Background(), "intranet.example", 443); route != RouteDirect || reason != "direct:ip:10.0.0.0/8" {
		t.Fatalf("Decide(intranet.example) = %s (%s), want direct (direct:ip:10.0.0.0/8)", route, reason)
	}
	if route, _ := rules.Decide(context.Background(), "public.example", 443); route != RouteTunnel {
		t.Fatalf("Decide(public.example) = %s, want tunnel: the forged local answer must not count", route)
	}
	if n := local.Load(); n != 0 {
		t.Fatalf("local lookups = %d, want 0: deciding a route must not leak names to local DNS", n)
	}
}

// TestDomainRuleBeatsIPRuleOrder: a name listed in DIRECT_RULES never reaches
// a resolver while the route is decided, even when an ip: rule stands first.
func TestDomainRuleBeatsIPRuleOrder(t *testing.T) {
	for _, raw := range []string{"ip:10.0.0.0/8,internal.local", `ip:10.0.0.0/8,re:\.local$`} {
		rules, err := NewRuleEngine(raw)
		if err != nil {
			t.Fatalf("NewRuleEngine(%q): %v", raw, err)
		}
		fake := startFakeDoHServer(t, func(name, _ string) dohAnswer {
			t.Errorf("tunnel resolver asked for %s", name)
			return dohAnswer{status: 3}
		})
		d, b := setBootstrap(t, fake)
		rules.SetDOH(b.addr, d)
		rules.dns.dohClient.Transport.(*http.Transport).TLSClientConfig = b.tls
		rules.dns.localLookup = func(context.Context, string) ([]net.IPAddr, error) {
			t.Error("local resolver asked while deciding the route")
			return nil, nil
		}

		route, reason := rules.Decide(context.Background(), "internal.local", 443)
		want := "direct:" + strings.Split(raw, ",")[1]
		if route != RouteDirect || reason != want {
			t.Fatalf("%q: Decide = (%s, %s), want (direct, %s)", raw, route, reason, want)
		}
		if got := rules.dns.lookups.Load(); got != 0 {
			t.Fatalf("%q: lookups = %d, want 0", raw, got)
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
		if got, _ := rules.Decide(ctx, tc.host, 443); got != RouteDirect {
			t.Errorf("Decide(%q) with rule %q = %v, want direct", tc.host, tc.rule, got)
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

// TestDecidePrivateLiterals: every spelling of a local address must be
// classified private. netip.Prefix.Contains misses IPv4-mapped addresses
// and addresses with a zone, so before the fix ::ffff:127.0.0.1 went to the
// tunnel and reached the VPS loopback.
func TestDecidePrivateLiterals(t *testing.T) {
	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatalf("NewRuleEngine: %v", err)
	}
	for _, host := range []string{
		"127.0.0.1", "::ffff:127.0.0.1", "::ffff:169.254.169.254", "::ffff:10.1.2.3",
		"0.0.0.0", "::", "100.64.0.1", "fc00::1", "fd12:3456::1", "fe80::1%eth0", "::1",
	} {
		if route, reason := rules.Decide(context.Background(), host, 80); route != RouteDirect || reason != "private" {
			t.Errorf("Decide(%s) = %s (%s), want direct (private)", host, route, reason)
		}
	}
	for _, host := range []string{"203.0.113.1", "2001:db8::1", "::ffff:203.0.113.1", "100.128.0.1"} {
		if route, _ := rules.Decide(context.Background(), host, 80); route != RouteTunnel {
			t.Errorf("Decide(%s) = %s, want tunnel", host, route)
		}
	}
}
