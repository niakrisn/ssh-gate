package main

import (
	"context"
	"errors"
	"fmt"
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

// Observes when a waiter has installed its select without relying on sleeps.
type observedWaitContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (c *observedWaitContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

func TestDNSWaiterCancellation(t *testing.T) {
	rules, err := NewRuleEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer rules.Stop()
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	var calls atomic.Int64
	rules.dns.localLookup = func(ctx context.Context, _ string) ([]net.IPAddr, error) {
		if calls.Add(1) == 1 {
			close(entered)
		}
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return []net.IPAddr{{IP: net.ParseIP("203.0.113.1")}}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := make(chan error, 1)
	go func() { _, err := rules.dns.localResolveAll(ctx, "wait.example"); first <- err }()
	<-entered
	cancel()
	select {
	case err := <-first:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("waiter=%v", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("canceled waiter still blocks on shared lookup")
	}
	secondCtx := &observedWaitContext{Context: context.Background(), waiting: make(chan struct{})}
	second := make(chan error, 1)
	go func() {
		addrs, err := rules.dns.localResolveAll(secondCtx, "wait.example")
		if err == nil && (len(addrs) != 1 || addrs[0].String() != "203.0.113.1") {
			err = fmt.Errorf("addresses=%v", addrs)
		}
		second <- err
	}()
	select {
	case <-secondCtx.waiting:
	case <-time.After(time.Second):
		t.Fatal("second waiter never joined")
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case err := <-second:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("shared result did not arrive")
	}
	if calls.Load() != 1 {
		t.Fatalf("shared lookups=%d", calls.Load())
	}
}

// TestDNSServerLookup covers one query to a DNS server through the tunnel.
func TestDNSServerLookup(t *testing.T) {
	v4, v6 := netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("2606:2800::1")
	d := &channelDialer{}

	t.Run("A and AAAA", func(t *testing.T) {
		f := startFakeDNSServer(t, func(string) (byte, netip.Addr) { return 0, v4 })
		addrs, _, err := dnsServerLookup(d, f.addr)(context.Background(), "example.org")
		if err != nil || len(addrs) != 1 || addrs[0] != v4 {
			t.Fatalf("A: (%v, %v)", addrs, err)
		}
		f = startFakeDNSServer(t, func(string) (byte, netip.Addr) { return 0, v6 })
		addrs, _, err = dnsServerLookup(d, f.addr)(context.Background(), "example.org")
		if err != nil || len(addrs) != 1 || addrs[0] != v6 {
			t.Fatalf("AAAA: (%v, %v)", addrs, err)
		}
	})

	t.Run("NXDOMAIN and an empty answer are not found", func(t *testing.T) {
		for _, rcode := range []byte{3, 0} {
			f := startFakeDNSServer(t, func(string) (byte, netip.Addr) { return rcode, netip.Addr{} })
			if _, _, err := dnsServerLookup(d, f.addr)(context.Background(), "example.org"); !errors.Is(err, errNotFound) {
				t.Fatalf("rcode %d: err = %v, want errNotFound", rcode, err)
			}
		}
	})

	t.Run("SERVFAIL is a failure without the local server name", func(t *testing.T) {
		f := startFakeDNSServer(t, func(string) (byte, netip.Addr) { return 2, netip.Addr{} })
		_, _, err := dnsServerLookup(d, f.addr)(context.Background(), "example.org")
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
			addrs, _, err := lookup(context.Background(), name)
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
		if _, _, err := lookup(ctx, "n"+strconv.Itoa(i)+".example.org"); err == nil || errors.Is(err, errNotFound) {
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

	t.Run("no server answers: the failure is not cached", func(t *testing.T) {
		f := startFakeDNSServer(t, servfail)
		rules, local := tunnelServers(t, &channelDialer{}, f.addr)
		for range 2 {
			if _, err := rules.ResolveAll(context.Background(), "a.example"); !errors.Is(err, errUnreachable) {
				t.Fatalf("ResolveAll err = %v, want errUnreachable", err)
			}
		}
		if got := len(f.asked()); got != 4 {
			t.Fatalf("server queries = %d, want 4 (two lookups x A+AAAA): a failure must not be cached", got)
		}
		if local.Load() != 0 {
			t.Fatalf("local calls = %d, want 0", local.Load())
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
	// resolveFail covers the lookups no tunnel resolver answers: the name
	// fails here instead of reaching the local resolver.
	resolveFail := func(t *testing.T, rules *RuleEngine, name string) {
		t.Helper()
		if _, err := rules.ResolveAll(context.Background(), name); !errors.Is(err, errUnreachable) {
			t.Fatalf("ResolveAll(%s) = %v, want errUnreachable", name, err)
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

	t.Run("all paused: the lookup fails without dialing again", func(t *testing.T) {
		d := &channelDialer{}
		f := flakyServer(t, d)
		rules, local := engine(t, d, f.addr)
		resolveFail(t, rules, "a.example")
		asked := f.dials.Load()
		resolveFail(t, rules, "b.example")
		if f.dials.Load() != asked || local.Load() != 0 {
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
		resolveFail(t, rules, "first.example")
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
		if got := local.Load(); got != 0 {
			t.Fatalf("local calls = %d, want 0", got)
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
		resolveFail(t, rules, "a.example")
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
		resolveFail(t, rules, "a.example")
		clock.Add(int64(upstreamPause))
		d.down.Store(true)
		resolveFail(t, rules, "b.example")
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
		resolveFail(t, rules, "a.example")
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
// resolvers off and leave every other name without a resolver.
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

			if _, err := rules.ResolveAll(context.Background(), "broken.example"); !errors.Is(err, errUnreachable) {
				t.Fatalf("broken name: %v, want errUnreachable", err)
			}
			if local.Load() != 0 {
				t.Fatalf("local calls = %d, want 0 for the broken name", local.Load())
			}
			addrs, err := rules.ResolveAll(context.Background(), "good.example")
			if err != nil || len(addrs) != 1 || addrs[0] != answer {
				t.Fatalf("good name = (%v, %v)", addrs, err)
			}
			if local.Load() != 0 {
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

// Tunnel NXDOMAIN and failures never consult the local resolver.
func TestTunnelDNSNeverFallsBackToLocal(t *testing.T) {
	rules, err := NewRuleEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	var localCalls atomic.Int64
	rules.dns.localLookup = func(context.Context, string) ([]net.IPAddr, error) {
		localCalls.Add(1)
		return []net.IPAddr{{IP: net.ParseIP("192.0.2.8")}}, nil
	}
	rules.dns.tunnelUp = func() bool { return true }
	rules.dns.tunnel = []*upstream{{name: "dns", lookup: func(context.Context, string) ([]netip.Addr, time.Time, error) { return nil, time.Time{}, errNotFound }}}
	if _, err := rules.ResolveAll(context.Background(), "missing.example"); !errors.Is(err, errNotFound) {
		t.Fatalf("NXDOMAIN err=%v", err)
	}
	if localCalls.Load() != 0 {
		t.Fatalf("local DNS calls=%d", localCalls.Load())
	}

	failed, err := NewRuleEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	failed.dns.localLookup = rules.dns.localLookup
	failed.dns.tunnelUp = func() bool { return true }
	failed.dns.tunnel = []*upstream{{name: "dns", lookup: func(context.Context, string) ([]netip.Addr, time.Time, error) {
		return nil, time.Time{}, fmt.Errorf("%w: connect failed", errUnreachable)
	}}}
	for range 2 {
		if _, err := failed.ResolveAll(context.Background(), "broken.example"); err == nil {
			t.Fatal("expected tunnel DNS error")
		}
	}
	if localCalls.Load() != 0 {
		t.Fatalf("local DNS calls after resolver failure=%d", localCalls.Load())
	}
}

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
		if st.Mode != "servers" || st.Degraded || len(st.Servers) != 1 {
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
		if !st.Degraded {
			t.Fatalf("status = %+v, want no local fallback and a paused resolver", st)
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
		rules.dns.now = func() time.Time { return time.Now().Add(upstreamPause) }
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

	t.Run("a down tunnel does not count as a resolver failure", func(t *testing.T) {
		d := &channelDialer{}
		d.down.Store(true)
		rules, _ := tunnelServers(t, d, startFakeDNSServer(t, ok).addr)
		rules.ResolveAll(context.Background(), "a.example")
		st := rules.DNSStatus()
		if s := st.Servers[0]; s.Fail != 0 || s.LastFailed || s.Error != "" {
			t.Fatalf("server = %+v", s)
		}
		if st.Degraded {
			t.Fatalf("status = %+v, want no local fallback or degradation", st)
		}
	})

	t.Run("a down tunnel does not degrade DNS status", func(t *testing.T) {
		d := &channelDialer{}
		d.down.Store(true)
		rules, _ := tunnelServers(t, d, startFakeDNSServer(t, ok).addr)
		rules.ResolveAll(context.Background(), "a.example")
		if rules.DNSStatus().Degraded {
			t.Fatal("down tunnel was counted as local fallback")
		}
		rules.dns.now = func() time.Time { return time.Now().Add(upstreamPause) }
		if rules.DNSStatus().Degraded {
			t.Fatal("down tunnel changed DNS status")
		}
	})

	t.Run("DoH reports its own mode", func(t *testing.T) {
		rules, err := NewRuleEngine(nil)
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

// TestTunnelDNSFailureDoesNotUseLocalDNS: an unreachable tunnel resolver is the
// end of the lookup. The local resolver stays untouched, and the failure is not
// cached, so the next request retries instead of inheriting a stale answer.
func TestTunnelDNSFailureDoesNotUseLocalDNS(t *testing.T) {
	rules, err := NewRuleEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	var localCalls atomic.Int64
	rules.dns.localLookup = func(context.Context, string) ([]net.IPAddr, error) {
		localCalls.Add(1)
		return []net.IPAddr{{IP: net.ParseIP("10.1.2.3")}}, nil
	}
	rules.dns.tunnelUp = func() bool { return true }
	rules.dns.tunnel = []*upstream{{name: "dns", lookup: func(context.Context, string) ([]netip.Addr, time.Time, error) {
		return nil, time.Time{}, fmt.Errorf("%w: closed", errUnreachable)
	}}}
	for range 2 {
		if _, err := rules.ResolveAll(context.Background(), "intranet.example"); err == nil {
			t.Fatal("expected resolver failure")
		}
	}
	if localCalls.Load() != 0 {
		t.Fatalf("local DNS calls=%d, want 0", localCalls.Load())
	}
	if len(rules.dns.cache) != 0 {
		t.Fatalf("failed tunnel lookup cached: %+v", rules.dns.cache)
	}
}

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
	rules, err := NewRuleEngine(nil)
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
	rules, err := NewRuleEngine(nil)
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

func TestTunnelDNSPauseIsPerSSHServer(t *testing.T) {
	ip := netip.MustParseAddr("93.184.216.34")
	resolver := startFakeDNSServer(t, func(string) (byte, netip.Addr) { return 0, ip })
	a := newSSHTransportPool(&scriptedSlotDialer{errs: []error{errors.New("SSH channel unavailable")}})
	a.id = "edge-a"
	b := newSSHTransportPool(&channelDialer{})
	b.id = "edge-b"
	rules, err := NewRuleEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rules.Stop)
	rules.SetTunnelDNS([]string{resolver.addr}, &sshDialerSet{pools: []*sshTransportPool{a, b}})
	if _, err := rules.dns.ResolveAll(contextWithDialer(t.Context(), a), "same.example"); !errors.Is(err, errUnreachable) {
		t.Fatalf("edge-a resolver error = %v", err)
	}
	if result, err := rules.dns.ResolveAll(contextWithDialer(t.Context(), b), "same.example"); err != nil || len(result) != 1 || result[0] != ip {
		t.Fatalf("edge-b resolver answer = %v, error = %v", result, err)
	}
	st := rules.DNSStatus()
	if !st.Degraded || len(st.Servers) != 2 || st.Servers[0].ServerID != a.id || !st.Servers[0].Paused ||
		st.Servers[1].ServerID != b.id || st.Servers[1].Paused || st.Servers[1].OK != 1 {
		t.Fatalf("DNS status does not show pause only on edge-a: %+v", st)
	}
}
