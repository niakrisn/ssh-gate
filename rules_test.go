package main

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
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

	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatalf("NewRuleEngine: %v", err)
	}
	s, err := NewSOCKS5Server("127.0.0.1:0", rules, testDialer{Target: echo.Addr().String()}, FamilyBoth)
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
	s, err := NewSOCKS5Server("127.0.0.1:0", rules, testDialer{}, FamilyBoth)
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
	s, err := NewSOCKS5Server("127.0.0.1:0", rules, testDialer{Target: echo.Addr().String()}, FamilyBoth)
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
