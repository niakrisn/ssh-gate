package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/net/dns/dnsmessage"
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

func TestResolveAllDOH(t *testing.T) {
	var reqs atomic.Int64
	srv := startFakeDoHServer(t, func(name, qtype string) dohAnswer {
		reqs.Add(1)
		switch {
		case name == "blocked.example" && qtype == "A":
			return dohAnswer{a: []string{"203.0.113.7"}}
		case name == "v6only.example" && qtype == "AAAA":
			return dohAnswer{aaaa: []string{"2001:db8::7"}}
		case name == "missing.example" || name == "other-missing.example":
			return dohAnswer{status: 3}
		default:
			return dohAnswer{}
		}
	})
	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatal(err)
	}
	d, b := setBootstrap(t, srv)
	rules.SetDOH(b.addr, d)
	rules.dns.dohClient.Transport.(*http.Transport).TLSClientConfig = b.tls
	var localCalls int
	local := netip.MustParseAddr("192.0.2.9")
	rules.dns.localLookup = func(context.Context, string) ([]net.IPAddr, error) {
		localCalls++
		return []net.IPAddr{{IP: local.AsSlice()}}, nil
	}

	addrs, err := rules.ResolveAll(context.Background(), "blocked.example")
	if err != nil || len(addrs) != 1 || addrs[0] != netip.MustParseAddr("203.0.113.7") {
		t.Fatalf("ResolveAll via DoH: (%v, %v)", addrs, err)
	}
	before := reqs.Load()
	if _, err := rules.ResolveAll(context.Background(), "blocked.example"); err != nil {
		t.Fatalf("cached ResolveAll: %v", err)
	}
	if got := reqs.Load(); got != before {
		t.Fatalf("cache miss: DoH requests %d -> %d", before, got)
	}

	// NODATA for A still allows the AAAA lookup.
	v6, err := rules.ResolveAll(context.Background(), "v6only.example")
	if err != nil || len(v6) != 1 || v6[0] != netip.MustParseAddr("2001:db8::7") {
		t.Fatalf("ResolveAll v6-only: (%v, %v)", v6, err)
	}
	if _, err := rules.ResolveAll(context.Background(), "missing.example"); !errors.Is(err, errNotFound) || localCalls != 0 {
		t.Fatalf("NXDOMAIN: err=%v, local calls=%d", err, localCalls)
	}
	rules.dns.localOnNXDomain = true
	addrs, localDirect, err := rules.dns.resolveTunnel(context.Background(), "other-missing.example")
	if err != nil || len(addrs) != 1 || addrs[0] != local || !localDirect || localCalls != 1 {
		t.Fatalf("NXDOMAIN with local DNS: (%v, %t, %v), local calls=%d", addrs, localDirect, err, localCalls)
	}
}

func TestResolveAllDOHServerFallback(t *testing.T) {
	srv := startFakeDoHServer(t, func(_, _ string) dohAnswer {
		return dohAnswer{status: int(dnsmessage.RCodeServerFailure)}
	})
	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatal(err)
	}
	d, b := setBootstrap(t, srv)
	rules.SetDOH(b.addr, d)
	rules.dns.dohClient.Transport.(*http.Transport).TLSClientConfig = b.tls
	var localCalls int
	local := netip.MustParseAddr("192.0.2.9")
	rules.dns.localLookup = func(context.Context, string) ([]net.IPAddr, error) {
		localCalls++
		return []net.IPAddr{{IP: local.AsSlice()}}, nil
	}

	addrs, err := rules.ResolveAll(context.Background(), "broken.example")
	if err != nil || len(addrs) != 1 || addrs[0] != local || localCalls != 1 {
		t.Fatalf("SERVFAIL fallback: (%v, %v), local calls=%d", addrs, err, localCalls)
	}
	server := rules.DNSStatus().Servers[0]
	if server.Fail != 1 || !strings.Contains(server.Error, dnsmessage.RCodeServerFailure.String()) {
		t.Fatalf("DoH status = %+v, want DNS SERVFAIL", server)
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

func TestDoHRedirect(t *testing.T) {
	var plaintext atomic.Int64
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		plaintext.Add(1)
		io.WriteString(w, "plaintext")
	}))
	defer httpServer.Close()
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dns-query":
			http.Redirect(w, r, "/answer?dns=example", http.StatusFound)
		case "/answer":
			if r.URL.RawQuery != "dns=example" {
				t.Errorf("redirect query = %s", r.URL.RawQuery)
			}
			w.WriteHeader(http.StatusNoContent)
		case "/downgrade":
			http.Redirect(w, r, httpServer.URL, http.StatusFound)
		case "/loop":
			http.Redirect(w, r, "/loop", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer tlsServer.Close()

	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatal(err)
	}
	rules.SetDOH(tlsServer.Listener.Addr().String(), testDialer{})
	client := rules.dns.dohClient
	client.Transport.(*http.Transport).TLSClientConfig = tlsServer.Client().Transport.(*http.Transport).TLSClientConfig
	resp, err := client.Get(tlsServer.URL + "/dns-query")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("same-origin redirect returned %d", resp.StatusCode)
	}

	for _, accept := range []string{dohWireMediaType, "application/dns-json"} {
		for _, path := range []string{"/downgrade", "/loop"} {
			req, err := http.NewRequest(http.MethodGet, tlsServer.URL+path, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Accept", accept)
			if resp, err := client.Do(req); err == nil {
				resp.Body.Close()
				t.Errorf("redirect %s succeeded for %s", path, accept)
			}
		}
	}
	if got := plaintext.Load(); got != 0 {
		t.Fatalf("plaintext endpoint received %d requests", got)
	}
}

func TestDoHOverSSH(t *testing.T) {
	const host = "ssh-doh.example"
	var queries, channels atomic.Int64
	srv := startFakeDoHServer(t, func(name, _ string) dohAnswer {
		queries.Add(1)
		if name != host {
			t.Errorf("DNS name = %s, want %s", name, host)
		}
		return dohAnswer{a: []string{"192.0.2.1"}, aaaa: []string{"2001:db8::1"}}
	})
	target := srv.Listener.Addr().(*net.TCPAddr)
	sshAddr, signer := startTestSSHServerWithChannelHandler(t, "", true, func(incoming ssh.NewChannel) error {
		var request struct {
			Host       string
			Port       uint32
			OriginHost string
			OriginPort uint32
		}
		err := ssh.Unmarshal(incoming.ExtraData(), &request)
		if err != nil || incoming.ChannelType() != "direct-tcpip" ||
			request.Host != target.IP.String() || request.Port != uint32(target.Port) {
			t.Errorf("SSH channel %s: destination %+v, error %v", incoming.ChannelType(), request, err)
			return incoming.Reject(ssh.Prohibited, "unexpected test destination")
		}
		conn, err := net.DialTCP("tcp", nil, target)
		if err != nil {
			t.Errorf("dial test HTTPS server: %v", err)
			return incoming.Reject(ssh.ConnectionFailed, "test HTTPS server unavailable")
		}
		ch, requests, err := incoming.Accept()
		if err != nil {
			conn.Close()
			return err
		}
		channels.Add(1)
		go ssh.DiscardRequests(requests)
		go func() {
			done := make(chan struct{})
			go func() {
				defer close(done)
				io.Copy(conn, ch)
				conn.CloseWrite()
			}()
			io.Copy(ch, conn)
			ch.Close()
			conn.Close()
			<-done
		}()
		return nil
	})

	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatal(err)
	}
	d := &sshDialer{client: connectTestSSHClient(t, sshAddr, signer)}
	rules.SetDOH(target.String(), d)
	transport := rules.dns.dohClient.Transport.(*http.Transport)
	transport.TLSClientConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig
	t.Cleanup(transport.CloseIdleConnections)
	var localCalls int
	rules.dns.localLookup = func(context.Context, string) ([]net.IPAddr, error) {
		localCalls++
		return nil, errors.New("unexpected local DNS")
	}

	want := []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")}
	for range 2 {
		got, err := rules.ResolveAll(context.Background(), host)
		if err != nil || !slices.Equal(got, want) {
			t.Fatalf("ResolveAll over SSH = (%v, %v), want %v", got, err, want)
		}
		if channels.Load() < 1 || queries.Load() != 2 || localCalls != 0 {
			t.Fatalf("SSH channels=%d, HTTPS queries=%d, local calls=%d", channels.Load(), queries.Load(), localCalls)
		}
	}
}
