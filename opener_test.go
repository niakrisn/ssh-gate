package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"testing"
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
	if addr == f.failTo {
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
