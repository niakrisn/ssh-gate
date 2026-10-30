package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fallbackDialer records every logical dial target. A dial to failTo is
// refused; any other target is redirected to redirect, so a successful Open
// returns a real connection without needing the fake public IPs to exist.
type fallbackDialer struct {
	failTo   string
	redirect string
	mu       sync.Mutex
	targets  []string
}

func (f *fallbackDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	f.mu.Lock()
	f.targets = append(f.targets, addr)
	f.mu.Unlock()
	if addr == f.failTo || f.failTo == "*" {
		return nil, errors.New("stub: connection refused")
	}
	return (&net.Dialer{}).DialContext(ctx, network, f.redirect)
}

func (f *fallbackDialer) Connected() bool { return true }
func (f *fallbackDialer) stop()           {}

func (f *fallbackDialer) dialed() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.targets...)
}

// TestOpenFallsBackToNextAddress: a host with two A records where the first
// address is dead must still connect — Open dials down the resolved list
// until one succeeds instead of failing on the first. (On v0.1.0 Open dialed
// only the picked address, so a stale first A record killed the connect.)
func TestOpenFallsBackToNextAddress(t *testing.T) {
	// Stand-in endpoint the redirected (successful) dial connects to.
	accept, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listener: %v", err)
	}
	defer accept.Close()

	fake := startFakeDoHServer(t, func(name, qtype string) dohAnswer {
		if name == "two.example" && qtype == "A" {
			return dohAnswer{status: 0, a: []string{"203.0.113.1", "203.0.113.2"}}
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

	// Empty rules + public name → tunnel route; the stub dialer plays the
	// SSH tunnel: dead on the first A record, alive on the second.
	stub := &fallbackDialer{failTo: "203.0.113.1:443", redirect: accept.Addr().String()}
	o := &Opener{rules: rules, d: stub, family: FamilyBoth}

	conn, dst, route, _, err := o.Open(context.Background(), "127.0.0.1:1234", "tcp", "two.example", 443)
	if err != nil {
		t.Fatalf("Open: %v (dialed %v)", err, stub.dialed())
	}
	defer conn.Close()
	if route != RouteTunnel {
		t.Fatalf("route = %s, want tunnel", route)
	}
	if dst != "203.0.113.2" {
		t.Fatalf("dst = %s, want 203.0.113.2 (first address refused, second accepted)", dst)
	}
	got := stub.dialed()
	want := []string{"203.0.113.1:443", "203.0.113.2:443"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("dial targets = %v, want %v", got, want)
	}
}

// TestOpenRefusesPrivateViaTunnel: a tunnel-routed name whose answers are
// private or loopback must never reach the tunnel - the VPS would dial its
// own localhost, the cloud metadata service or the provider network. Public
// answers of the same name are still dialed.
func TestOpenRefusesPrivateViaTunnel(t *testing.T) {
	accept, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listener: %v", err)
	}
	defer accept.Close()

	fake := startFakeDoHServer(t, func(name, qtype string) dohAnswer {
		switch {
		case name == "rebind.example" && qtype == "A":
			return dohAnswer{a: []string{"169.254.169.254", "127.0.0.1", "0.0.0.0"}}
		case name == "rebind.example" && qtype == "AAAA":
			return dohAnswer{aaaa: []string{"fc00::1", "::ffff:10.0.0.1"}}
		case name == "mixed.example" && qtype == "A":
			return dohAnswer{a: []string{"127.0.0.1", "203.0.113.5"}}
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

	stub := &fallbackDialer{redirect: accept.Addr().String()}
	o := &Opener{rules: rules, d: stub, family: FamilyBoth}

	if conn, _, _, _, err := o.Open(context.Background(), "127.0.0.1:1234", "socks5", "rebind.example", 80); err == nil {
		conn.Close()
		t.Fatal("Open(rebind.example) succeeded, want refusal")
	}
	if got := stub.dialed(); len(got) != 0 {
		t.Fatalf("tunnel dials for private-only answers: %v, want none", got)
	}

	conn, dst, _, _, err := o.Open(context.Background(), "127.0.0.1:1234", "socks5", "mixed.example", 80)
	if err != nil {
		t.Fatalf("Open(mixed.example): %v", err)
	}
	conn.Close()
	if dst != "203.0.113.5" {
		t.Fatalf("dst = %s, want the public address 203.0.113.5", dst)
	}
	if got := stub.dialed(); len(got) != 1 || got[0] != "203.0.113.5:80" {
		t.Fatalf("tunnel dials = %v, want only 203.0.113.5:80", got)
	}
}

// TestLocalPrivateRoute: with LOCAL_DNS_ON_NXDOMAIN a local answer of private
// addresses is an intranet name and goes direct, but addresses of this machine
// stay refused: otherwise a page could reach them by DNS rebinding.
func TestLocalPrivateRoute(t *testing.T) {
	nx := func(string) (byte, netip.Addr) { return 3, netip.Addr{} }
	dead := func(string) (byte, netip.Addr) { return 2, netip.Addr{} }
	local := func(ips ...net.IPAddr) func(context.Context, string) ([]net.IPAddr, error) {
		return func(context.Context, string) ([]net.IPAddr, error) { return ips, nil }
	}
	ip := func(s string) net.IPAddr { return net.IPAddr{IP: net.ParseIP(s)} }

	cases := []struct {
		name    string
		server  func(string) (byte, netip.Addr)
		on      bool
		down    bool // the SSH tunnel is lost
		family  IPFamily
		answer  []net.IPAddr
		want    []string // nil means refused
		wantWay Route
	}{
		{name: "not found, RFC 1918", server: nx, on: true, answer: []net.IPAddr{ip("10.1.2.3")}, want: []string{"10.1.2.3"}, wantWay: RouteDirect},
		{name: "not found, CGNAT", server: nx, on: true, answer: []net.IPAddr{ip("100.64.1.2")}, want: []string{"100.64.1.2"}, wantWay: RouteDirect},
		{name: "not found, unique local", server: nx, on: true, answer: []net.IPAddr{ip("fd00::1")}, want: []string{"fd00::1"}, wantWay: RouteDirect},
		{name: "tunnel down", server: nx, on: true, down: true, answer: []net.IPAddr{ip("10.1.2.3")}, want: []string{"10.1.2.3"}, wantWay: RouteDirect},
		{name: "tunnel down, loopback", server: nx, on: true, down: true, answer: []net.IPAddr{ip("127.0.0.1")}},
		{name: "resolvers fail, tunnel up: may be a block page", server: dead, on: true, answer: []net.IPAddr{ip("10.1.2.3")}},
		{name: "address of this machine is dropped", server: nx, on: true, answer: []net.IPAddr{ip("10.1.2.3"), ip("127.0.0.1")}, want: []string{"10.1.2.3"}, wantWay: RouteDirect},
		{name: "loopback", server: nx, on: true, answer: []net.IPAddr{ip("127.0.0.1")}},
		{name: "IPv6 loopback", server: nx, on: true, answer: []net.IPAddr{ip("::1")}},
		{name: "mapped loopback", server: nx, on: true, answer: []net.IPAddr{ip("::ffff:127.0.0.1")}},
		{name: "this network", server: nx, on: true, answer: []net.IPAddr{ip("0.0.0.0")}},
		{name: "unspecified IPv6", server: nx, on: true, answer: []net.IPAddr{ip("::")}},
		{name: "link-local, metadata service", server: nx, on: true, answer: []net.IPAddr{ip("169.254.169.254")}},
		{name: "link-local IPv6 with zone", server: nx, on: true, answer: []net.IPAddr{{IP: net.ParseIP("fe80::1"), Zone: "eth0"}}},
		{name: "setting off", server: dead, answer: []net.IPAddr{ip("10.1.2.3")}},
		{name: "public address wins", server: nx, on: true, answer: []net.IPAddr{ip("10.1.2.3"), ip("198.51.100.1")}, want: []string{"198.51.100.1"}, wantWay: RouteTunnel},
		{name: "family filter", server: nx, on: true, family: FamilyIPv4, answer: []net.IPAddr{ip("fd00::1")}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := &channelDialer{}
			d.down.Store(c.down)
			rules, _ := tunnelServers(t, d, startFakeDNSServer(t, c.server).addr)
			rules.dns.localOnNXDomain = c.on
			rules.dns.localLookup = local(c.answer...)
			o := &Opener{rules: rules, d: &fallbackDialer{}, family: c.family}

			addrs, route, reason, err := o.candidates(context.Background(), "intranet.example", 443)
			if c.want == nil {
				if err == nil {
					t.Fatalf("candidates = %v, want refusal", addrs)
				}
				return
			}
			if err != nil {
				t.Fatalf("candidates: %v", err)
			}
			var got []string
			for _, a := range addrs {
				got = append(got, a.String())
			}
			if !slices.Equal(got, c.want) || route != c.wantWay {
				t.Fatalf("candidates = (%v, %s), want (%v, %s)", got, route, c.want, c.wantWay)
			}
			if route == RouteDirect && reason != "local-private" {
				t.Fatalf("reason = %s, want local-private", reason)
			}
		})
	}
}

// TestPrivateFromTunnelResolverRefused: the switch to direct belongs to local
// answers only. A public name a tunnel resolver points at a private address
// stays refused, whatever the setting.
func TestPrivateFromTunnelResolverRefused(t *testing.T) {
	f := startFakeDNSServer(t, func(string) (byte, netip.Addr) { return 0, netip.MustParseAddr("10.1.2.3") })
	rules, _ := tunnelServers(t, &channelDialer{}, f.addr)
	rules.dns.localOnNXDomain = true
	o := &Opener{rules: rules, d: &fallbackDialer{}, family: FamilyBoth}
	if addrs, _, _, err := o.candidates(context.Background(), "rebind.example", 443); err == nil {
		t.Fatalf("candidates = %v, want refusal", addrs)
	}
}

// TestLocalPrivateOpenDialsDirect: Open follows the route candidates returned,
// so the connection never enters the tunnel.
func TestLocalPrivateOpenDialsDirect(t *testing.T) {
	f := startFakeDNSServer(t, func(string) (byte, netip.Addr) { return 3, netip.Addr{} })
	rules, _ := tunnelServers(t, &channelDialer{}, f.addr)
	rules.dns.localOnNXDomain = true
	rules.dns.localLookup = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("10.255.255.1")}}, nil
	}
	stub := &fallbackDialer{}
	o := &Opener{rules: rules, d: stub, family: FamilyBoth}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	conn, _, route, reason, err := o.Open(ctx, "127.0.0.1:1234", "socks5", "intranet.example", 443)
	if err == nil {
		conn.Close() // a network that does route 10.255.255.1 is fine too
	}
	if route != RouteDirect || reason != "local-private" {
		t.Fatalf("Open route = (%s, %s), want (direct, local-private)", route, reason)
	}
	if got := stub.dialed(); len(got) != 0 {
		t.Fatalf("tunnel dials = %v, want none", got)
	}
}

// localPrivateAddr returns a private address of this machine, so a test can
// listen on a real "intranet" destination: loopback never goes direct by DNS.
func localPrivateAddr(t *testing.T) netip.Addr {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skipf("interface addresses: %v", err)
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ip, ok := netip.AddrFromSlice(ipnet.IP.To4()); ok && ip.IsPrivate() {
			return ip
		}
	}
	t.Skip("no private interface address")
	return netip.Addr{}
}

// TestSOCKS5LocalPrivate runs the whole SOCKS5 path, which resolves twice:
// on the handshake and in Open. Both must agree on the route.
func TestSOCKS5LocalPrivate(t *testing.T) {
	nx := func(string) (byte, netip.Addr) { return 3, netip.Addr{} }
	servfail := func(string) (byte, netip.Addr) { return 2, netip.Addr{} }
	start := func(t *testing.T, reply func(string) (byte, netip.Addr), answer netip.Addr) (string, *fallbackDialer, *RuleEngine, *atomic.Int64) {
		t.Helper()
		rules, _ := tunnelServers(t, &channelDialer{}, startFakeDNSServer(t, reply).addr)
		rules.dns.localOnNXDomain = true
		var local atomic.Int64
		rules.dns.localLookup = func(context.Context, string) ([]net.IPAddr, error) {
			local.Add(1)
			return []net.IPAddr{{IP: answer.AsSlice()}}, nil
		}
		stub := &fallbackDialer{failTo: "*"}
		s, err := NewSOCKS5Server("127.0.0.1:0", &Opener{rules: rules, d: stub, family: FamilyBoth})
		if err != nil {
			t.Fatalf("NewSOCKS5Server: %v", err)
		}
		s.Start()
		t.Cleanup(func() { s.Shutdown(context.Background()) })
		return s.ln.Addr().String(), stub, rules, &local
	}

	t.Run("an intranet name goes direct", func(t *testing.T) {
		ip := localPrivateAddr(t)
		ln, err := net.Listen("tcp4", net.JoinHostPort(ip.String(), "0"))
		if err != nil {
			t.Skipf("listen on %s: %v", ip, err)
		}
		defer ln.Close()
		accepted := make(chan struct{}, 1)
		go func() {
			if c, err := ln.Accept(); err == nil {
				c.Close()
				accepted <- struct{}{}
			}
		}()
		addr, stub, rules, local := start(t, nx, ip)
		port := ln.Addr().(*net.TCPAddr).Port

		if code := socks5Connect(t, addr, "intranet.example", port); code != 0x00 {
			t.Fatalf("reply code %d, want success", code)
		}
		select {
		case <-accepted:
		case <-time.After(2 * time.Second):
			t.Fatal("the intranet service got no connection")
		}
		if got := stub.dialed(); len(got) != 0 {
			t.Fatalf("tunnel dials = %v, want none", got)
		}
		// The second resolve is a cache hit: one tunnel not-found, one local answer.
		if rules.dns.lookups.Load() != 1 || local.Load() != 1 {
			t.Fatalf("lookups = %d, local calls = %d, want 1 and 1", rules.dns.lookups.Load(), local.Load())
		}
	})

	t.Run("loopback is refused", func(t *testing.T) {
		addr, stub, _, _ := start(t, nx, netip.MustParseAddr("127.0.0.1"))
		if code := socks5Connect(t, addr, "rebind.example", 80); code != 0x04 {
			t.Fatalf("reply code %d, want host unreachable", code)
		}
		if got := stub.dialed(); len(got) != 0 {
			t.Fatalf("tunnel dials = %v, want none", got)
		}
	})

	t.Run("a private answer is refused while the tunnel is up", func(t *testing.T) {
		addr, stub, _, _ := start(t, servfail, netip.MustParseAddr("10.1.2.3"))
		if code := socks5Connect(t, addr, "blocked.example", 443); code != 0x04 {
			t.Fatalf("reply code %d, want host unreachable", code)
		}
		if got := stub.dialed(); len(got) != 0 {
			t.Fatalf("tunnel dials = %v, want none", got)
		}
	})
}
