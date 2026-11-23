package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type healthProbeDialer struct {
	calls     atomic.Int32
	addr      string
	untracked bool
}

func (d *healthProbeDialer) DialContext(ctx context.Context, _, addr string) (net.Conn, error) {
	d.calls.Add(1)
	d.addr = addr
	d.untracked = ctx.Value(noTrackKey{}) != nil
	return nil, errors.New("test channel open failure")
}
func (*healthProbeDialer) Connected() bool { return true }
func (*healthProbeDialer) stop()           {}

func TestResolveTunnelFreshBypassesCachedResultAndKeepsServerSelection(t *testing.T) {
	rules, err := NewRuleEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer rules.Stop()
	var calls int
	rules.dns.tunnel = []*upstream{{name: "fake", lookup: func(ctx context.Context, _ string) ([]netip.Addr, time.Time, error) {
		calls++
		if got := selectedServerKey(ctx); got != "edge-a" {
			t.Fatalf("selected server = %q, want edge-a", got)
		}
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, time.Time{}, nil
	}}}
	ctx := contextWithDialer(context.Background(), &sshTransportPool{id: "edge-a"})
	if _, _, err := rules.dns.resolveTunnel(ctx, "probe.example"); err != nil {
		t.Fatal(err)
	}
	if _, err := rules.dns.resolveTunnelFresh(ctx, "probe.example"); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("upstream lookups = %d, want 2 (fresh check bypasses cache)", calls)
	}
}

func TestHTTPSProbeUsesFreshSelectedTunnelChannel(t *testing.T) {
	rules, err := NewRuleEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer rules.Stop()
	rules.dns.tunnel = []*upstream{{name: "fake", lookup: func(ctx context.Context, _ string) ([]netip.Addr, time.Time, error) {
		if got := selectedServerKey(ctx); got != "edge-a" {
			t.Fatalf("selected server = %q, want edge-a", got)
		}
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, time.Time{}, nil
	}}}
	d := &healthProbeDialer{}
	pool := &sshTransportPool{id: "edge-a", slots: []*transportSlot{{dialer: d, index: 0}}}
	err = checkServerHTTPS(context.Background(), pool, rules, "https://probe.example/health")
	if err == nil || !strings.Contains(err.Error(), "test channel open failure") {
		t.Fatalf("probe error = %v, want channel open failure", err)
	}
	if d.calls.Load() != 1 || d.addr != "93.184.216.34:443" || !d.untracked {
		t.Fatalf("probe dial calls=%d addr=%q untracked=%v", d.calls.Load(), d.addr, d.untracked)
	}
}
