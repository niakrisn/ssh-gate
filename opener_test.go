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
