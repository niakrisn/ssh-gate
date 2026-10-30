package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestDNSServerLookup covers one query to a DNS server through the tunnel.
func TestDNSServerLookup(t *testing.T) {
	v4, v6 := netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("2606:2800::1")
	d := &channelDialer{}

	t.Run("A and AAAA", func(t *testing.T) {
		f := startFakeDNSServer(t, func(string) (byte, netip.Addr) { return 0, v4 })
		addrs, err := dnsServerLookup(d, f.addr)(context.Background(), "example.org")
		if err != nil || len(addrs) != 1 || addrs[0] != v4 {
			t.Fatalf("A: (%v, %v)", addrs, err)
		}
		f = startFakeDNSServer(t, func(string) (byte, netip.Addr) { return 0, v6 })
		addrs, err = dnsServerLookup(d, f.addr)(context.Background(), "example.org")
		if err != nil || len(addrs) != 1 || addrs[0] != v6 {
			t.Fatalf("AAAA: (%v, %v)", addrs, err)
		}
	})

	t.Run("NXDOMAIN and an empty answer are not found", func(t *testing.T) {
		for _, rcode := range []byte{3, 0} {
			f := startFakeDNSServer(t, func(string) (byte, netip.Addr) { return rcode, netip.Addr{} })
			if _, err := dnsServerLookup(d, f.addr)(context.Background(), "example.org"); !errors.Is(err, errNotFound) {
				t.Fatalf("rcode %d: err = %v, want errNotFound", rcode, err)
			}
		}
	})

	t.Run("SERVFAIL is a failure without the local server name", func(t *testing.T) {
		f := startFakeDNSServer(t, func(string) (byte, netip.Addr) { return 2, netip.Addr{} })
		_, err := dnsServerLookup(d, f.addr)(context.Background(), "example.org")
		if err == nil || errors.Is(err, errNotFound) {
			t.Fatalf("err = %v, want a failure", err)
		}
		if strings.Contains(err.Error(), " on ") {
			t.Fatalf("err = %q names a server of the local resolv.conf", err)
		}
	})

	t.Run("the name is rooted: no search domain, no hosts file", func(t *testing.T) {
		f := startFakeDNSServer(t, func(string) (byte, netip.Addr) { return 0, v4 })
		lookup := dnsServerLookup(d, f.addr)
		for _, name := range []string{"singlelabel", "localhost"} {
			addrs, err := lookup(context.Background(), name)
			if err != nil || len(addrs) != 1 || addrs[0] != v4 {
				t.Fatalf("%s: (%v, %v)", name, addrs, err)
			}
		}
		for _, name := range f.asked() {
			if name != "singlelabel." && name != "localhost." {
				t.Fatalf("asked %q", name)
			}
		}
	})
}

// TestDNSServerSilentLeavesNoChannels: a silent server must cost nothing once
// the lookup ended. The caller returns on the context either way; the check
// is the channels, which have no deadlines and stay open unless closed.
func TestDNSServerSilentLeavesNoChannels(t *testing.T) {
	f := startFakeDNSServer(t, nil)
	d := &channelDialer{}
	lookup := dnsServerLookup(d, f.addr)
	for i := range 20 {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		if _, err := lookup(ctx, "n"+strconv.Itoa(i)+".example.org"); err == nil || errors.Is(err, errNotFound) {
			t.Fatalf("lookup %d: err = %v, want a timeout", i, err)
		}
		cancel()
	}
	deadline := time.Now().Add(2 * time.Second)
	for d.open.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := d.open.Load(); got != 0 {
		t.Fatalf("open channels = %d, want 0", got)
	}
}

// TestTunnelServerOrder covers the walk over the server list.
func TestTunnelServerOrder(t *testing.T) {
	answer := netip.MustParseAddr("93.184.216.34")
	ok := func(string) (byte, netip.Addr) { return 0, answer }
	nx := func(string) (byte, netip.Addr) { return 3, netip.Addr{} }
	servfail := func(string) (byte, netip.Addr) { return 2, netip.Addr{} }

	t.Run("a failed server passes to the next", func(t *testing.T) {
		first, second := startFakeDNSServer(t, servfail), startFakeDNSServer(t, ok)
		rules, local := tunnelServers(t, &channelDialer{}, first.addr, second.addr)
		addrs, err := rules.ResolveAll(context.Background(), "a.example")
		if err != nil || len(addrs) != 1 || addrs[0] != answer {
			t.Fatalf("ResolveAll = (%v, %v)", addrs, err)
		}
		if local.Load() != 0 {
			t.Fatal("local resolver asked while a server answered")
		}
	})

	t.Run("NXDOMAIN does not pass to the next", func(t *testing.T) {
		first, second := startFakeDNSServer(t, nx), startFakeDNSServer(t, ok)
		rules, local := tunnelServers(t, &channelDialer{}, first.addr, second.addr)
		if _, err := rules.ResolveAll(context.Background(), "a.example"); !errors.Is(err, errNotFound) {
			t.Fatalf("err = %v, want errNotFound", err)
		}
		if len(second.asked()) != 0 || local.Load() != 0 {
			t.Fatalf("second server asked %v, local asked %d times", second.asked(), local.Load())
		}
	})

	t.Run("no server answers: the local answer is not cached", func(t *testing.T) {
		f := startFakeDNSServer(t, servfail)
		rules, local := tunnelServers(t, &channelDialer{}, f.addr)
		for range 2 {
			addrs, err := rules.ResolveAll(context.Background(), "a.example")
			if err != nil || len(addrs) != 1 {
				t.Fatalf("ResolveAll = (%v, %v)", addrs, err)
			}
		}
		if local.Load() != 2 {
			t.Fatalf("local calls = %d, want 2", local.Load())
		}
	})
}

// TestTunnelServerPause: a server no channel opens to is skipped for
// upstreamPause, so a blocked port 53 costs one tunnel step per pause, not one
// per connection.
func TestTunnelServerPause(t *testing.T) {
	answer := netip.MustParseAddr("93.184.216.34")
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	resolve := func(t *testing.T, rules *RuleEngine, name string) {
		t.Helper()
		if _, err := rules.ResolveAll(context.Background(), name); err != nil {
			t.Fatalf("ResolveAll(%s): %v", name, err)
		}
	}
	// flaky is a server behind d whose channel opens only while blocked is
	// false; dials counts the attempts that were not already out of time.
	type flaky struct {
		addr    string
		blocked atomic.Bool
		dials   atomic.Int64
	}
	flakyServer := func(t *testing.T, d *channelDialer) *flaky {
		f := &flaky{addr: startFakeDNSServer(t, func(string) (byte, netip.Addr) { return 0, answer }).addr}
		f.blocked.Store(true)
		d.unreachable = map[string]func(context.Context) error{f.addr: func(ctx context.Context) error {
			if ctx.Err() == nil {
				f.dials.Add(1)
			}
			if f.blocked.Load() {
				return errors.New("connect failed")
			}
			return nil
		}}
		return f
	}
	engine := func(t *testing.T, d dialer, servers ...string) (*RuleEngine, *atomic.Int64) {
		rules, local := tunnelServers(t, d, servers...)
		rules.dns.now = func() time.Time { return time.Unix(0, clock.Load()) }
		return rules, local
	}

	t.Run("the unreachable server is skipped, then used again", func(t *testing.T) {
		d := &channelDialer{}
		f := flakyServer(t, d)
		good := startFakeDNSServer(t, func(string) (byte, netip.Addr) { return 0, answer })
		rules, local := engine(t, d, f.addr, good.addr)
		resolve(t, rules, "a.example")
		asked := f.dials.Load()
		resolve(t, rules, "b.example")
		if got := f.dials.Load(); got != asked {
			t.Fatalf("paused server dialed %d more times", got-asked)
		}
		clock.Add(int64(upstreamPause))
		f.blocked.Store(false)
		resolve(t, rules, "c.example")
		if f.dials.Load() == asked {
			t.Fatal("server not used after the pause")
		}
		if local.Load() != 0 {
			t.Fatal("local resolver asked while a server answered")
		}
	})

	t.Run("all paused: the local resolver answers at once", func(t *testing.T) {
		d := &channelDialer{}
		f := flakyServer(t, d)
		rules, local := engine(t, d, f.addr)
		resolve(t, rules, "a.example")
		asked := f.dials.Load()
		resolve(t, rules, "b.example")
		if f.dials.Load() != asked || local.Load() != 2 {
			t.Fatalf("server dialed %d more times, local calls = %d", f.dials.Load()-asked, local.Load())
		}
	})

	t.Run("a silent port 53 pauses too", func(t *testing.T) {
		d := &channelDialer{unreachable: map[string]func(context.Context) error{}}
		const addr = "192.0.2.1:53"
		var dials atomic.Int64
		d.unreachable[addr] = func(ctx context.Context) error {
			if ctx.Err() == nil {
				dials.Add(1)
			}
			<-ctx.Done()
			return ctx.Err()
		}
		rules, local := engine(t, d, addr)
		resolve(t, rules, "first.example")
		if rules.DNSStatus().Servers[0].Fail != 1 {
			t.Fatalf("status = %+v", rules.DNSStatus())
		}
		before := dials.Load()
		clock.Add(int64(upstreamPause))

		var wg sync.WaitGroup
		for i := range 20 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				rules.ResolveAll(context.Background(), "burst"+strconv.Itoa(i)+".example")
			}()
		}
		wg.Wait()
		// One lookup probes; a piled-up burst would be 40 dials.
		if got := dials.Load() - before; got >= 20 {
			t.Fatalf("dials after the pause = %d, want the probe only", got)
		}
		if got := local.Load(); got != 21 {
			t.Fatalf("local calls = %d, want 21", got)
		}
		u := rules.dns.tunnel[0]
		if u.probing || !u.pausedUntil.After(time.Unix(0, clock.Load())) {
			t.Fatal("failed probe must end and pause the resolver again")
		}
	})

	t.Run("a probe that answers clears the pause", func(t *testing.T) {
		d := &channelDialer{}
		f := flakyServer(t, d)
		rules, _ := engine(t, d, f.addr)
		resolve(t, rules, "a.example")
		clock.Add(int64(upstreamPause))
		f.blocked.Store(false)
		resolve(t, rules, "b.example")
		if u := rules.dns.tunnel[0]; !u.pausedUntil.IsZero() || u.probing {
			t.Fatalf("pausedUntil = %v, probing = %v", u.pausedUntil, u.probing)
		}
	})

	t.Run("a probe the lookup did not need is given back", func(t *testing.T) {
		good := startFakeDNSServer(t, func(string) (byte, netip.Addr) { return 0, answer })
		rules, _ := engine(t, &channelDialer{}, good.addr, "192.0.2.1:53")
		second := rules.dns.tunnel[1]
		second.pausedUntil = time.Unix(0, clock.Load()-1)
		resolve(t, rules, "a.example")
		if second.probing {
			t.Fatal("unused probe stays claimed")
		}
	})

	t.Run("a probe with the tunnel down is given back", func(t *testing.T) {
		d := &channelDialer{}
		f := flakyServer(t, d)
		rules, _ := engine(t, d, f.addr)
		resolve(t, rules, "a.example")
		clock.Add(int64(upstreamPause))
		d.down.Store(true)
		resolve(t, rules, "b.example")
		d.down.Store(false)
		f.blocked.Store(false)
		asked := f.dials.Load()
		resolve(t, rules, "c.example")
		if f.dials.Load() == asked {
			t.Fatal("server left unusable after the tunnel came back")
		}
	})

	t.Run("a down tunnel pauses nothing", func(t *testing.T) {
		good := startFakeDNSServer(t, func(string) (byte, netip.Addr) { return 0, answer })
		d := &channelDialer{}
		d.down.Store(true)
		rules, _ := engine(t, d, good.addr)
		resolve(t, rules, "a.example")
		d.down.Store(false)
		asked := len(good.asked())
		resolve(t, rules, "b.example")
		if len(good.asked()) == asked {
			t.Fatal("server skipped after the tunnel came back")
		}
	})
}

// TestFailedNameDoesNotPauseServer: a failure on an open channel is about the
// name. A web page asking for a broken domain must not switch the tunnel
// resolvers off and send every other name to the local resolver.
func TestFailedNameDoesNotPauseServer(t *testing.T) {
	answer := netip.MustParseAddr("93.184.216.34")
	for _, c := range []struct {
		name  string
		rcode byte
	}{{"SERVFAIL", 2}, {"REFUSED", 5}, {"silence", silentRcode}} {
		t.Run(c.name, func(t *testing.T) {
			reply := func(name string) (byte, netip.Addr) {
				if name == "broken.example." {
					return c.rcode, netip.Addr{}
				}
				return 0, answer
			}
			first, second := startFakeDNSServer(t, reply), startFakeDNSServer(t, reply)
			rules, local := tunnelServers(t, &channelDialer{}, first.addr, second.addr)

			if _, err := rules.ResolveAll(context.Background(), "broken.example"); err != nil {
				t.Fatalf("broken name: %v", err)
			}
			if local.Load() != 1 {
				t.Fatalf("local calls = %d, want 1 for the broken name", local.Load())
			}
			addrs, err := rules.ResolveAll(context.Background(), "good.example")
			if err != nil || len(addrs) != 1 || addrs[0] != answer {
				t.Fatalf("good name = (%v, %v)", addrs, err)
			}
			if local.Load() != 1 {
				t.Fatal("the good name went to the local resolver")
			}
			if s := rules.DNSStatus().Servers[1]; s.Fail != 1 {
				t.Fatalf("second server = %+v, want the failure counted", s)
			}
		})
	}

	t.Run("a probe that reaches the server ends the pause", func(t *testing.T) {
		f := startFakeDNSServer(t, func(string) (byte, netip.Addr) { return 2, netip.Addr{} })
		rules, _ := tunnelServers(t, &channelDialer{}, f.addr)
		u := rules.dns.tunnel[0]
		u.pausedUntil = time.Now().Add(-time.Second)
		rules.ResolveAll(context.Background(), "a.example")
		if !u.pausedUntil.IsZero() {
			t.Fatalf("pausedUntil = %v, want no pause", u.pausedUntil)
		}
	})
}

// TestLocalDNSOnNXDomain covers the setting that lets the local resolver
// answer after a tunnel not-found.
func TestLocalDNSOnNXDomain(t *testing.T) {
	nx := func(string) (byte, netip.Addr) { return 3, netip.Addr{} }

	t.Run("off: not found stands", func(t *testing.T) {
		rules, local := tunnelServers(t, &channelDialer{}, startFakeDNSServer(t, nx).addr)
		if _, err := rules.ResolveAll(context.Background(), "a.example"); !errors.Is(err, errNotFound) {
			t.Fatalf("err = %v, want errNotFound", err)
		}
		if local.Load() != 0 {
			t.Fatal("local resolver asked")
		}
	})

	t.Run("on: the local answer is cached", func(t *testing.T) {
		f := startFakeDNSServer(t, nx)
		rules, local := tunnelServers(t, &channelDialer{}, f.addr)
		rules.dns.localOnNXDomain = true
		for range 2 {
			addrs, localDirect, err := rules.dns.resolveTunnel(context.Background(), "a.example")
			if err != nil || !localDirect || len(addrs) != 1 || addrs[0].String() != "198.51.100.1" {
				t.Fatalf("resolveTunnel = (%v, %v, %v)", addrs, localDirect, err)
			}
		}
		if local.Load() != 1 || rules.dns.lookups.Load() != 1 {
			t.Fatalf("local calls = %d, lookups = %d, want 1 and 1", local.Load(), rules.dns.lookups.Load())
		}
	})

	t.Run("on: a local failure is cached as not found", func(t *testing.T) {
		rules, _ := tunnelServers(t, &channelDialer{}, startFakeDNSServer(t, nx).addr)
		rules.dns.localOnNXDomain = true
		rules.dns.localLookup = func(context.Context, string) ([]net.IPAddr, error) {
			return nil, errors.New("local resolver down")
		}
		for range 2 {
			if _, err := rules.ResolveAll(context.Background(), "a.example"); !errors.Is(err, errNotFound) {
				t.Fatalf("err = %v, want errNotFound", err)
			}
		}
		if got := rules.dns.lookups.Load(); got != 1 {
			t.Fatalf("lookups = %d, want 1 (negative cache)", got)
		}
	})
}

// TestDNSStatus covers what counts in the resolver statistics.
func TestDNSStatus(t *testing.T) {
	answer := netip.MustParseAddr("93.184.216.34")
	ok := func(name string) (byte, netip.Addr) {
		if name == "missing.example." {
			return 3, netip.Addr{}
		}
		return 0, answer
	}
	servfail := func(string) (byte, netip.Addr) { return 2, netip.Addr{} }

	t.Run("answers and NXDOMAIN are successes, one per lookup", func(t *testing.T) {
		rules, _ := tunnelServers(t, &channelDialer{}, startFakeDNSServer(t, ok).addr)
		for _, name := range []string{"a.example", "a.example", "missing.example"} {
			rules.ResolveAll(context.Background(), name)
		}
		st := rules.DNSStatus()
		if st.Mode != "servers" || st.Degraded || st.LocalFallbacks != 0 || len(st.Servers) != 1 {
			t.Fatalf("status = %+v", st)
		}
		if s := st.Servers[0]; s.OK != 2 || s.Fail != 0 || s.LastOKAt == 0 || s.LastFailed {
			t.Fatalf("server = %+v, want 2 answers: the repeat is a cache hit", s)
		}
	})

	t.Run("a failure counts once, the pause counts nothing", func(t *testing.T) {
		const dead = "192.0.2.1:53"
		d := &channelDialer{unreachable: map[string]func(context.Context) error{
			dead: func(context.Context) error { return errors.New("connect failed") },
		}}
		rules, _ := tunnelServers(t, d, dead)
		rules.ResolveAll(context.Background(), "a.example")
		rules.ResolveAll(context.Background(), "b.example")
		st := rules.DNSStatus()
		s := st.Servers[0]
		if s.OK != 0 || s.Fail != 1 || !s.LastFailed || s.Error == "" {
			t.Fatalf("server = %+v", s)
		}
		if strings.Contains(s.Error, " on ") {
			t.Fatalf("error %q names a server of the local resolv.conf", s.Error)
		}
		if st.LocalFallbacks != 2 || !st.Degraded {
			t.Fatalf("status = %+v, want 2 fallbacks and degraded", st)
		}
	})

	t.Run("a failed spare server does not stay degraded", func(t *testing.T) {
		reply := func(name string) (byte, netip.Addr) {
			if name == "broken.example." {
				return 2, netip.Addr{}
			}
			return 0, answer
		}
		first, second := startFakeDNSServer(t, reply), startFakeDNSServer(t, reply)
		rules, _ := tunnelServers(t, &channelDialer{}, first.addr, second.addr)
		rules.ResolveAll(context.Background(), "broken.example")
		rules.ResolveAll(context.Background(), "good.example")
		rules.dns.now = func() time.Time { return time.Now().Add(dnsDegradedWindow) }
		st := rules.DNSStatus()
		if !st.Servers[1].LastFailed || st.Degraded {
			t.Fatalf("status = %+v, want the failure shown and not degraded", st)
		}
	})

	t.Run("a paused server degrades", func(t *testing.T) {
		rules, _ := tunnelServers(t, &channelDialer{}, startFakeDNSServer(t, ok).addr)
		u := rules.dns.tunnel[0]
		u.pausedUntil = time.Now().Add(time.Minute)
		st := rules.DNSStatus()
		if !st.Degraded || !st.Servers[0].Paused {
			t.Fatalf("status = %+v", st)
		}
		u.pausedUntil = time.Now().Add(-time.Second)
		if rules.DNSStatus().Degraded {
			t.Fatal("expired pause still degrades")
		}
	})

	t.Run("SERVFAIL is a failure without a pause", func(t *testing.T) {
		rules, _ := tunnelServers(t, &channelDialer{}, startFakeDNSServer(t, servfail).addr)
		rules.ResolveAll(context.Background(), "a.example")
		rules.ResolveAll(context.Background(), "b.example")
		if s := rules.DNSStatus().Servers[0]; s.Fail != 2 || s.Error == "" || strings.Contains(s.Error, " on ") {
			t.Fatalf("server = %+v", s)
		}
	})

	t.Run("a timeout is a failure", func(t *testing.T) {
		rules, _ := tunnelServers(t, &channelDialer{}, silentListener(t))
		rules.ResolveAll(context.Background(), "a.example")
		if s := rules.DNSStatus().Servers[0]; s.Fail != 1 {
			t.Fatalf("server = %+v", s)
		}
	})

	t.Run("a down tunnel counts only the fallback", func(t *testing.T) {
		d := &channelDialer{}
		d.down.Store(true)
		rules, _ := tunnelServers(t, d, startFakeDNSServer(t, ok).addr)
		rules.ResolveAll(context.Background(), "a.example")
		st := rules.DNSStatus()
		if s := st.Servers[0]; s.Fail != 0 || s.LastFailed || s.Error != "" {
			t.Fatalf("server = %+v", s)
		}
		if st.LocalFallbacks != 1 {
			t.Fatalf("fallbacks = %d, want 1", st.LocalFallbacks)
		}
	})

	t.Run("a fallback degrades for a minute", func(t *testing.T) {
		d := &channelDialer{}
		d.down.Store(true)
		rules, _ := tunnelServers(t, d, startFakeDNSServer(t, ok).addr)
		rules.ResolveAll(context.Background(), "a.example")
		if !rules.DNSStatus().Degraded {
			t.Fatal("not degraded right after a fallback")
		}
		rules.dns.now = func() time.Time { return time.Now().Add(dnsDegradedWindow) }
		if rules.DNSStatus().Degraded {
			t.Fatal("still degraded after the window")
		}
	})

	t.Run("DoH reports its own mode", func(t *testing.T) {
		rules, err := NewRuleEngine("")
		if err != nil {
			t.Fatalf("NewRuleEngine: %v", err)
		}
		rules.SetDOH("dns.example", testDialer{})
		st := rules.DNSStatus()
		if st.Mode != "doh" || len(st.Servers) != 1 || st.Servers[0].Name != "dns.example" {
			t.Fatalf("status = %+v", st)
		}
	})
}

// TestIPRuleMatchesLocalAnswerOnNXDomain: with the setting on, an ip: rule sees
// the local answer for a name public DNS does not know.
func TestIPRuleMatchesLocalAnswerOnNXDomain(t *testing.T) {
	f := startFakeDNSServer(t, func(string) (byte, netip.Addr) { return 3, netip.Addr{} })
	rules, err := NewRuleEngine("ip:198.51.100.0/24")
	if err != nil {
		t.Fatalf("NewRuleEngine: %v", err)
	}
	rules.SetTunnelDNS([]string{f.addr}, &channelDialer{})
	rules.dns.localLookup = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("198.51.100.1")}}, nil
	}
	if route, _ := rules.Decide(context.Background(), "intranet.example", 443); route != RouteTunnel {
		t.Fatalf("setting off: Decide = %s, want tunnel", route)
	}
	rules.dns.mu.Lock()
	clear(rules.dns.cache)
	rules.dns.mu.Unlock()
	rules.dns.localOnNXDomain = true
	if route, reason := rules.Decide(context.Background(), "intranet.example", 443); route != RouteDirect || reason != "direct:ip:198.51.100.0/24" {
		t.Fatalf("setting on: Decide = (%s, %s)", route, reason)
	}
}

// TestLocalFallbackAfterSilentTunnelResolver: a silent tunnel resolver must
// leave the local resolver time to answer. Before the tunnel step had its own
// bound the local lookup got the expired context of the whole lookup.
func TestLocalFallbackAfterSilentTunnelResolver(t *testing.T) {
	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatalf("NewRuleEngine: %v", err)
	}
	rules.SetDOH(silentListener(t), testDialer{})
	want := netip.MustParseAddr("93.184.216.34")
	rules.dns.localLookup = func(ctx context.Context, _ string) ([]net.IPAddr, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return []net.IPAddr{{IP: want.AsSlice()}}, nil
	}

	start := time.Now()
	addrs, err := rules.ResolveAll(context.Background(), "example.org")
	if err != nil || len(addrs) != 1 || addrs[0] != want {
		t.Fatalf("ResolveAll = (%v, %v), want the local answer", addrs, err)
	}
	if took := time.Since(start); took >= 5*time.Second {
		t.Fatalf("took %v, want the tunnel step bound", took)
	}
}

// TestIPRuleUsesLocalFallback: while no tunnel resolver answers, ip: rules keep
// working through the local answer.
func TestIPRuleUsesLocalFallback(t *testing.T) {
	rules, err := NewRuleEngine("ip:10.0.0.0/8")
	if err != nil {
		t.Fatalf("NewRuleEngine: %v", err)
	}
	d := &channelDialer{}
	d.down.Store(true)
	rules.SetTunnelDNS([]string{"192.0.2.1:53"}, d)
	rules.dns.localLookup = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("10.1.2.3")}}, nil
	}
	if route, _ := rules.Decide(context.Background(), "intranet.example", 443); route != RouteDirect {
		t.Fatalf("Decide(intranet.example) = %s, want direct", route)
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
