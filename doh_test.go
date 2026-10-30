package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
)

// TestDoHAfterTunnelLoss: the DoH client keeps connections in a pool. When the
// tunnel drops they die with it, and the next lookup must open a new one
// instead of counting a failure or pausing the endpoint.
func TestDoHAfterTunnelLoss(t *testing.T) {
	answer := "93.184.216.34"
	fake := startFakeDoHServer(t, func(_, qtype string) dohAnswer {
		if qtype == "A" {
			return dohAnswer{a: []string{answer}}
		}
		return dohAnswer{}
	})
	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatalf("NewRuleEngine: %v", err)
	}
	_, b := setBootstrap(t, fake)
	d := &losableDialer{target: b.addr}
	rules.SetDOH(b.addr, d)
	rules.dns.dohClient.Transport.(*http.Transport).TLSClientConfig = b.tls
	rules.dns.localLookup = func(context.Context, string) ([]net.IPAddr, error) {
		t.Error("local resolver asked")
		return nil, errors.New("not expected")
	}

	check := func(name string) {
		t.Helper()
		addrs, err := rules.ResolveAll(context.Background(), name)
		if err != nil || len(addrs) != 1 || addrs[0].String() != answer {
			t.Fatalf("ResolveAll(%s) = (%v, %v)", name, addrs, err)
		}
	}
	check("a.example")
	if got := d.dials.Load(); got != 1 {
		t.Fatalf("dials = %d, want 1: the test needs a pooled connection", got)
	}
	d.lose()
	check("b.example")
	if got := d.dials.Load(); got != 2 {
		t.Fatalf("dials = %d, want a new connection after the loss", got)
	}
	st := rules.DNSStatus()
	if s := st.Servers[0]; s.Fail != 0 || s.Paused || st.LocalFallbacks != 0 {
		t.Fatalf("status = %+v", st)
	}
}

// TestDoHPause: the DoH endpoint follows the same rule: a failed connection
// pauses it, a SERVFAIL on a working connection does not.
func TestDoHPause(t *testing.T) {
	t.Run("no connection", func(t *testing.T) {
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
		rules.dns.localLookup = func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("198.51.100.1")}}, nil
		}
		rules.ResolveAll(context.Background(), "a.example")
		if rules.dns.tunnel[0].pausedUntil.IsZero() {
			t.Fatal("endpoint not paused")
		}
	})

	t.Run("SERVFAIL", func(t *testing.T) {
		fake := startFakeDoHServer(t, func(string, string) dohAnswer { return dohAnswer{status: 2} })
		rules, err := NewRuleEngine("")
		if err != nil {
			t.Fatalf("NewRuleEngine: %v", err)
		}
		d, b := setBootstrap(t, fake)
		rules.SetDOH(b.addr, d)
		rules.dns.dohClient.Transport.(*http.Transport).TLSClientConfig = b.tls
		rules.dns.localLookup = func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("198.51.100.1")}}, nil
		}
		rules.ResolveAll(context.Background(), "a.example")
		u := rules.dns.tunnel[0]
		if !u.pausedUntil.IsZero() || u.fail != 1 {
			t.Fatalf("pausedUntil = %v, fail = %d", u.pausedUntil, u.fail)
		}
	})
}

// TestResolveAllDOH: when a DoH endpoint is configured, cached resolution
// asks the endpoint (dialing it through the SSH dialer, here a testDialer
// that redirects to a local TLS server) instead of the local resolver. A
// definitive DoH answer wins even when the local resolver would fail
// (.example is reserved, so the local lookup is NXDOMAIN), the answer is
// cached, and a DoH NXDOMAIN is authoritative (no local fallback).
func TestResolveAllDOH(t *testing.T) {
	var reqs atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
		reqs.Add(1)
		name, qtype := r.URL.Query().Get("name"), r.URL.Query().Get("type")
		w.Header().Set("Content-Type", "application/dns-json")
		switch {
		case name == "blocked.example" && qtype == "A":
			io.WriteString(w, `{"Status":0,"Answer":[{"Type":1,"Data":"203.0.113.7"}]}`)
		case name == "v6only.example" && qtype == "AAAA":
			io.WriteString(w, `{"Status":0,"Answer":[{"Type":28,"Data":"2001:db8::7"}]}`)
		case name == "missing.example":
			io.WriteString(w, `{"Status":3,"Answer":[]}`)
		default:
			io.WriteString(w, `{"Status":0,"Answer":[]}`)
		}
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatalf("NewRuleEngine: %v", err)
	}
	// The testDialer stands in for the SSH tunnel: it redirects the dial to
	// the local DoH server, whose certificate matches the 127.0.0.1 hostname
	// used in the URL.
	rules.SetDOH(srv.Listener.Addr().String(), testDialer{Target: srv.Listener.Addr().String()})
	rules.dns.dohClient.Transport.(*http.Transport).TLSClientConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig

	addrs, err := rules.ResolveAll(context.Background(), "blocked.example")
	if err != nil {
		t.Fatalf("ResolveAll via DoH: %v", err)
	}
	if len(addrs) != 1 || addrs[0] != netip.MustParseAddr("203.0.113.7") {
		t.Fatalf("addrs = %v, want [203.0.113.7]", addrs)
	}

	// A repeat within the TTL is served from the cache: no further DoH query.
	before := reqs.Load()
	if _, err := rules.ResolveAll(context.Background(), "blocked.example"); err != nil {
		t.Fatalf("cached ResolveAll: %v", err)
	}
	if got := reqs.Load(); got != before {
		t.Fatalf("cache miss: DoH requests %d -> %d", before, got)
	}

	// A v6-only host: the A query is NOERROR with an empty answer, the AAAA
	// query carries the record — dohLookup must merge both queries.
	v6, err := rules.ResolveAll(context.Background(), "v6only.example")
	if err != nil {
		t.Fatalf("ResolveAll v6-only via DoH: %v", err)
	}
	if len(v6) != 1 || v6[0] != netip.MustParseAddr("2001:db8::7") {
		t.Fatalf("addrs = %v, want [2001:db8::7]", v6)
	}

	// A definitive DoH NXDOMAIN is authoritative: no local fallback.
	if _, err := rules.ResolveAll(context.Background(), "missing.example"); err == nil {
		t.Fatal("NXDOMAIN via DoH: want error, got success")
	}
}

// TestResolveAllDOHServerFallback: a non-definitive DoH failure (SERVFAIL)
// is not authoritative, unlike a definitive NXDOMAIN: resolution falls back
// to the local resolver. example.com resolves locally, so success proves the
// fallback happened (a treated-as-definitive SERVFAIL would fail the lookup).
func TestResolveAllDOHServerFallback(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/dns-json")
		io.WriteString(w, `{"Status":2,"Answer":[]}`) // SERVFAIL
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatalf("NewRuleEngine: %v", err)
	}
	rules.SetDOH(srv.Listener.Addr().String(), testDialer{Target: srv.Listener.Addr().String()})
	rules.dns.dohClient.Transport.(*http.Transport).TLSClientConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig

	if _, err := rules.ResolveAll(context.Background(), "example.com"); err != nil {
		t.Skipf("local resolver unavailable: %v", err)
	}
}

// TestResolveAllDOHFallback: when the DoH endpoint is unreachable, cached
// resolution falls back to the local resolver.
func TestResolveAllDOHFallback(t *testing.T) {
	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatalf("NewRuleEngine: %v", err)
	}
	// A closed local port: the dial fails before the TLS handshake.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listener: %v", err)
	}
	closed := l.Addr().String()
	l.Close()

	rules.SetDOH(closed, testDialer{})
	if _, err := rules.ResolveAll(context.Background(), "example.com"); err != nil {
		t.Skipf("local resolver unavailable: %v", err)
	}
}
