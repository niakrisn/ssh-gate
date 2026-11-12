package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestOpenOneLookupPerPolicy(t *testing.T) {
	var entries []string
	for i := range 20 {
		entries = append(entries, fmt.Sprintf("ip:198.18.%d.0/24", i))
	}
	for _, tc := range []struct {
		name         string
		err          error
		fallback     bool
		local, dials int
	}{
		{"TTL zero", nil, false, 0, 1},
		{"NXDOMAIN", errNotFound, false, 0, 0},
		{"SERVFAIL", errors.New("temporary resolver failure"), false, 1, 0},
		{"local fallback", errors.New("temporary resolver failure"), true, 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rules, err := NewRuleEngine(strings.Join(entries, ","))
			if err != nil {
				t.Fatal(err)
			}
			defer rules.Stop()
			var tunnel, local atomic.Int64
			rules.dns.tunnel = []*upstream{{name: "test", lookup: func(context.Context, string) ([]netip.Addr, time.Time, error) {
				tunnel.Add(1)
				return []netip.Addr{netip.MustParseAddr("203.0.113.1")}, time.Now(), tc.err
			}}}
			rules.dns.tunnelUp = func() bool { return true }
			rules.dns.localLookup = func(context.Context, string) ([]net.IPAddr, error) {
				local.Add(1)
				if tc.fallback {
					return []net.IPAddr{{IP: net.ParseIP("203.0.113.2")}}, nil
				}
				return nil, errors.New("local resolver failure")
			}
			d := &fallbackDialer{failTo: "*"}
			o := newTestOpener(rules, d)
			c, _, _, _, _ := o.Open(context.Background(), "client", "http", "target.example", 443)
			if c != nil {
				c.Close()
			}
			if tunnel.Load() != 1 || local.Load() != int64(tc.local) {
				t.Fatalf("lookups: tunnel=%d local=%d, want 1/%d", tunnel.Load(), local.Load(), tc.local)
			}
			if got := len(d.dialed()); got != tc.dials {
				t.Fatalf("dial count=%d want %d", got, tc.dials)
			}
		})
	}
}

func TestDirectDomainSkipsTunnelDNS(t *testing.T) {
	testPreparedDirectPolicy(t, "target.example", 0)
}

func TestCIDRDirectResolvesLocally(t *testing.T) {
	testPreparedDirectPolicy(t, "ip:203.0.113.0/24", 1)
}

func testPreparedDirectPolicy(t *testing.T, rule string, tunnelWant int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan struct{})
	go func() {
		if c, err := ln.Accept(); err == nil {
			c.Close()
		}
		close(accepted)
	}()
	rules, err := NewRuleEngine(rule)
	if err != nil {
		t.Fatal(err)
	}
	defer rules.Stop()
	var tunnel, local atomic.Int64
	rules.dns.tunnelUp = func() bool { return true }
	rules.dns.tunnel = []*upstream{{name: "test", lookup: func(context.Context, string) ([]netip.Addr, time.Time, error) {
		tunnel.Add(1)
		return []netip.Addr{netip.MustParseAddr("203.0.113.9")}, time.Now(), nil
	}}}
	rules.dns.localLookup = func(context.Context, string) ([]net.IPAddr, error) {
		local.Add(1)
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	}
	d := &fallbackDialer{failTo: "*"}
	c, dst, route, reason, err := newTestOpener(rules, d).Open(context.Background(), "client", "http", "TaRgEt.Example.", ln.Addr().(*net.TCPAddr).Port)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	<-accepted
	if route != RouteDirect || dst != "127.0.0.1" || reason != "direct:"+rule {
		t.Fatalf("route=%s dst=%s reason=%s", route, dst, reason)
	}
	if tunnel.Load() != tunnelWant || local.Load() != 1 || len(d.dialed()) != 0 {
		t.Fatalf("queries=%d/%d tunnel dials=%v", tunnel.Load(), local.Load(), d.dialed())
	}
}

func TestSOCKSResolvesOnce(t *testing.T) {
	for _, tc := range []struct {
		name      string
		remoteErr error
		fallback  bool
		code      byte
		local     int64
	}{
		{"TTL zero", nil, false, 0, 0},
		{"NXDOMAIN", errNotFound, false, 4, 0},
		{"SERVFAIL", errors.New("temporary DNS failure"), false, 4, 1},
		{"fallback", errors.New("temporary DNS failure"), true, 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, access, flush := captureLogs(t)
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			go func() {
				if c, err := ln.Accept(); err == nil {
					defer c.Close()
					io.Copy(c, c)
				}
			}()
			rules, _ := NewRuleEngine("")
			defer rules.Stop()
			var tunnel, local atomic.Int64
			rules.dns.tunnelUp = func() bool { return true }
			rules.dns.tunnel = []*upstream{{name: "test", lookup: func(context.Context, string) ([]netip.Addr, time.Time, error) {
				tunnel.Add(1)
				return []netip.Addr{netip.MustParseAddr("203.0.113.1")}, time.Now(), tc.remoteErr
			}}}
			rules.dns.localLookup = func(context.Context, string) ([]net.IPAddr, error) {
				local.Add(1)
				if tc.fallback {
					return []net.IPAddr{{IP: net.ParseIP("203.0.113.1")}}, nil
				}
				return nil, errors.New("local DNS failed")
			}
			d := &fallbackDialer{redirect: ln.Addr().String()}
			s, err := NewSOCKS5Server("127.0.0.1:0", newTestOpener(rules, d))
			if err != nil {
				t.Fatal(err)
			}
			s.Start()
			t.Cleanup(func() { s.Shutdown(context.Background()) })
			if code := socks5Connect(t, s.ln.Addr().String(), "TaRgEt.Example", 443); code != tc.code {
				t.Fatalf("reply=%d want %d", code, tc.code)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := s.Shutdown(ctx); err != nil {
				t.Fatal(err)
			}
			if tunnel.Load() != 1 || local.Load() != tc.local {
				t.Fatalf("queries tunnel=%d local=%d, want 1/%d", tunnel.Load(), local.Load(), tc.local)
			}
			if targets := d.dialed(); tc.code == 0 && (len(targets) != 1 || targets[0] != "203.0.113.1:443") {
				t.Fatalf("dialed %v", targets)
			}
			flush()
			var event struct{ Host, Result string }
			if err := json.Unmarshal(access.Bytes(), &event); err != nil {
				t.Fatal(err)
			}
			if event.Host != "TaRgEt.Example" || (tc.code != 0 && event.Result != "resolve_error") {
				t.Fatalf("access=%s", access.String())
			}
		})
	}
}
