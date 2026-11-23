package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestServerQuotaSeparatesTunnelAndPendingOpenLimits(t *testing.T) {
	q := newServerQuota(1, 2, 1)
	release, err := q.reserveTunnel()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.reserveTunnel(); err == nil {
		t.Fatal("accepted tunnel over limit")
	}
	if _, err := q.acquireOpen(false); err != nil {
		t.Fatal(err)
	}
	if _, err := q.acquireOpen(false); err != nil {
		t.Fatal(err)
	}
	if _, err := q.acquireOpen(false); err == nil {
		t.Fatal("accepted client channel open over limit")
	}
	service, err := q.acquireOpen(true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.acquireOpen(true); err == nil {
		t.Fatal("accepted service channel open over limit")
	}
	<-service
	release()
	if _, err := q.reserveTunnel(); err != nil {
		t.Fatalf("tunnel quota not released: %v", err)
	}
}

func TestServerQuotaLimitsAreIndependent(t *testing.T) {
	a, b := newServerQuota(1, 1, 1), newServerQuota(1, 1, 1)
	if _, err := a.reserveTunnel(); err != nil {
		t.Fatal(err)
	}
	if _, err := b.reserveTunnel(); err != nil {
		t.Fatalf("second server shares tunnel quota: %v", err)
	}
	if _, err := a.acquireOpen(true); err != nil {
		t.Fatal(err)
	}
	if _, err := b.acquireOpen(true); err != nil {
		t.Fatalf("second server shares service quota: %v", err)
	}
}

func TestClientTunnelLimitErrorIsClear(t *testing.T) {
	_, err := newServerQuota(1, 1, 1).reserveTunnel()
	if err != nil {
		t.Fatal(err)
	}
	q := newServerQuota(1, 1, 1)
	_, _ = q.reserveTunnel()
	if _, err = q.reserveTunnel(); err == nil || !strings.Contains(err.Error(), "client tunnel limit") {
		t.Fatalf("err=%v", err)
	}
}

func TestTunnelQuotaIsCheckedBeforeDNS(t *testing.T) {
	rules, err := NewRuleEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	q := newServerQuota(1, 1, 1)
	_, _ = q.reserveTunnel()
	p := newSSHTransportPool(&alwaysConnectedDialer{})
	p.id = "edge-a"
	p.quota = q
	d := &sshDialerSet{pools: []*sshTransportPool{p}}
	o := &Opener{rules: rules, d: d, family: FamilyBoth, hashKey: "client_ip_destination"}
	_, _, route, _, err := o.Open(t.Context(), "192.0.2.10:40000", "http", "does-not-resolve.invalid", 443)
	if route != RouteTunnel || err == nil || !strings.Contains(err.Error(), "client tunnel limit reached") {
		t.Fatalf("route=%v err=%v", route, err)
	}
	if len(q.clientTunnels) != 1 {
		t.Fatalf("quota changed while rejecting request: %d", len(q.clientTunnels))
	}
}

func TestDirectOpenDoesNotReserveSSHQuota(t *testing.T) {
	rules, err := NewRuleEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	q := newServerQuota(1, 1, 1)
	p := newSSHTransportPool(&alwaysConnectedDialer{})
	p.id = "edge-a"
	p.quota = q
	d := &sshDialerSet{pools: []*sshTransportPool{p}}
	o := &Opener{rules: rules, d: d, family: FamilyBoth}
	_, _, route, _, _ := o.Open(t.Context(), "192.0.2.10:40000", "http", "127.0.0.1", 1)
	if route != RouteDirect {
		t.Fatalf("route=%v, want direct", route)
	}
	if len(q.clientTunnels) != 0 {
		t.Fatalf("direct request used SSH quota: %d", len(q.clientTunnels))
	}
}

type countingSSHSlot struct {
	*sshDialer
	calls atomic.Int64
}

func (d *countingSSHSlot) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.calls.Add(1)
	return d.sshDialer.DialContext(ctx, network, addr)
}

func TestOpenQuotaStopsOtherIPsAndServers(t *testing.T) {
	for _, inFlight := range []bool{false, true} {
		name := "quota already full"
		if inFlight {
			name = "quota exhausted by the first IP"
		}
		t.Run(name, func(t *testing.T) {
			opens := make(chan ssh.NewChannel, 8)
			sshAddr, signer := startTestSSHServerWithChannelHandler(t, "", true, func(open ssh.NewChannel) error {
				opens <- open
				return nil
			})
			quota := newServerQuota(1, 1, 1)
			if !inFlight {
				pending, err := quota.acquireOpen(false)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { <-pending }()
			}
			newSlot := func() *countingSSHSlot {
				return &countingSSHSlot{sshDialer: &sshDialer{
					client: connectTestSSHClient(t, sshAddr, signer), cfg: sshDialerCfg{openQuota: quota},
				}}
			}
			first, second := newSlot(), newSlot()
			primary := newSSHTransportPool(first, second)
			primary.id, primary.quota = "edge-a", quota
			escape := &scriptedSlotDialer{}
			fallback := newSSHTransportPool(escape)
			fallback.id = "edge-b"
			set := &sshDialerSet{pools: []*sshTransportPool{primary, fallback}}
			t.Cleanup(set.stop)
			rules, err := NewRuleEngine(nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(rules.Stop)
			rules.dns.tunnel = []*upstream{{name: "test", lookup: func(context.Context, string) ([]netip.Addr, time.Time, error) {
				return []netip.Addr{netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("203.0.113.2"), netip.MustParseAddr("203.0.113.3")}, time.Now(), nil
			}}}
			o := &Opener{rules: rules, d: set, dialTimeout: time.Second, maxAttempts: 8}
			const host = "example.test"
			src := "192.0.2.1:40000"
			for i := 1; set.selectPool(src, host, "") != primary; i++ {
				src = fmt.Sprintf("192.0.2.%d:40000", i)
			}
			conn, _, _, _, err := o.Open(t.Context(), src, "http", host, 443)
			if conn != nil {
				conn.Close()
			}
			var limit *pendingOpenLimitError
			if !errors.As(err, &limit) {
				t.Fatalf("Open error = %v, want pending-open limit", err)
			}
			var secondCalls int64
			if inFlight {
				secondCalls = 1
			}
			if a, b, c := first.calls.Load(), second.calls.Load(), escape.calls.Load(); a != 1 || b != secondCalls || c != 0 {
				t.Fatalf("slot dials = %d/%d, other server = %d, want 1/%d and 0", a, b, c, secondCalls)
			}
			if len(quota.clientTunnels) != 0 || len(quota.pendingOpens) != 1 {
				t.Fatal("tunnel quota retained or pending open quota released early")
			}
			if !inFlight {
				return
			}
			select {
			case open := <-opens:
				// Fail back if cancellation left the late channel alive.
				ch, requests, err := open.Accept()
				if err != nil {
					t.Fatal(err)
				}
				defer ch.Close()
				select {
				case <-requests:
				case <-time.After(time.Second):
					t.Fatal("late SSH channel remained open after quota refusal")
				}
				waitPendingSSH(t, first.sshDialer, 0)
			case <-time.After(time.Second):
				t.Fatal("first SSH open did not reach the server")
			}
		})
	}
}
