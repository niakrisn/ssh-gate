package main

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// dohAnswer is one fake server response: a DNS RCODE plus the record
// lists returned on NOERROR.
type dohAnswer struct {
	status int
	a      []string
	aaaa   []string
}

// startFakeDoHServer starts a local RFC 8484 server with one answer per question.
func startFakeDoHServer(t *testing.T, reply func(name, qtype string) dohAnswer) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
		msg, err := readDoHWireQuery(r)
		if err != nil {
			t.Errorf("invalid DoH request: %v", err)
			http.Error(w, "invalid test request", http.StatusBadRequest)
			return
		}
		q := msg.Questions[0]
		name := q.Name.String()
		qtype := "A"
		switch q.Type {
		case dnsmessage.TypeA:
		case dnsmessage.TypeAAAA:
			qtype = "AAAA"
		default:
			t.Errorf("unexpected question type %v", q.Type)
			http.Error(w, "invalid test question", http.StatusBadRequest)
			return
		}
		ans := reply(strings.TrimSuffix(name, "."), qtype)
		msg.Response = true
		msg.RCode = dnsmessage.RCode(ans.status)
		if msg.RCode == dnsmessage.RCodeSuccess {
			if q.Type == dnsmessage.TypeA {
				for _, s := range ans.a {
					msg.Answers = append(msg.Answers, doHRecord(name, 60, &dnsmessage.AResource{A: netip.MustParseAddr(s).As4()}))
				}
			} else {
				for _, s := range ans.aaaa {
					msg.Answers = append(msg.Answers, doHRecord(name, 60, &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr(s).As16()}))
				}
			}
		}
		if len(msg.Answers) == 0 && (msg.RCode == dnsmessage.RCodeSuccess || msg.RCode == dnsmessage.RCodeNameError) {
			msg.Authorities = []dnsmessage.Resource{doHSOA(name, 60, 60)}
		}
		writeDoHWireResponse(t, w, msg)
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// dohBootstrap names the DoH endpoint a test points the resolver at, plus
// the TLS config that trusts the fake server's certificate.
type dohBootstrap struct {
	addr string
	tls  *tls.Config
}

// setBootstrap returns the dialer and bootstrap that point at the fake
// server: the testDialer redirects every tunnel dial to it, and the
// bootstrap trusts its test CA.
func setBootstrap(t *testing.T, srv *httptest.Server) (testDialer, dohBootstrap) {
	t.Helper()
	addr := srv.Listener.Addr().String()
	return testDialer{Target: addr}, dohBootstrap{
		addr: addr,
		tls:  srv.Client().Transport.(*http.Transport).TLSClientConfig,
	}
}

// fakeDNSServer answers DNS over TCP on a local port and records the
// question names.
type fakeDNSServer struct {
	addr  string
	mu    sync.Mutex
	names []string
}

func (f *fakeDNSServer) asked() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.names...)
}

// silentRcode as a reply makes the server read on and never answer.
const silentRcode = 0xff

// startFakeDNSServer starts the server. reply picks the rcode and the address
// for a question; the address is sent when it fits the question type. A nil
// reply makes a server that accepts connections and stays silent.
func startFakeDNSServer(t *testing.T, reply func(name string) (byte, netip.Addr)) *fakeDNSServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listener: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	f := &fakeDNSServer{addr: ln.Addr().String()}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(conn, reply)
		}
	}()
	return f
}

func (f *fakeDNSServer) serve(conn net.Conn, reply func(string) (byte, netip.Addr)) {
	defer conn.Close()
	if reply == nil {
		io.Copy(io.Discard, conn)
		return
	}
	for {
		msg, err := readTCPDNSQuery(conn)
		if err != nil {
			return
		}
		q := msg.Questions[0]
		name := q.Name.String()
		f.mu.Lock()
		f.names = append(f.names, name)
		f.mu.Unlock()
		rcode, addr := reply(name)
		if rcode == silentRcode {
			io.Copy(io.Discard, conn)
			return
		}
		msg.Response = true
		msg.RecursionAvailable = true
		msg.RCode = dnsmessage.RCode(rcode)
		msg.Answers = nil
		msg.Authorities = nil
		if rcode == 0 && addr.IsValid() {
			switch {
			case addr.Is4() && q.Type == dnsmessage.TypeA:
				msg.Answers = []dnsmessage.Resource{doHRecord(name, 30, &dnsmessage.AResource{A: addr.As4()})}
			case addr.Is6() && q.Type == dnsmessage.TypeAAAA:
				msg.Answers = []dnsmessage.Resource{doHRecord(name, 30, &dnsmessage.AAAAResource{AAAA: addr.As16()})}
			}
		}
		if len(msg.Answers) == 0 && (rcode == 0 || rcode == 3) {
			// Existing cache tests model an authoritative, cacheable negative.
			// Missing SOA and zero TTL have separate TCP regression cases.
			msg.Authorities = []dnsmessage.Resource{doHSOA(".", 10, 10)}
		}
		if err := writeTCPDNSAnswer(conn, msg); err != nil {
			return
		}
	}
}

// losableDialer dials a fixed target and can drop all its connections at once,
// as a lost SSH transport does to its channels.
type losableDialer struct {
	target string
	dials  atomic.Int64
	mu     sync.Mutex
	conns  []net.Conn
}

func (d *losableDialer) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, network, d.target)
	if err != nil {
		return nil, err
	}
	d.dials.Add(1)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.conns = append(d.conns, conn)
	return conn, nil
}

func (d *losableDialer) lose() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, c := range d.conns {
		c.Close()
	}
	d.conns = nil
}

func (d *losableDialer) Connected() bool { return true }
func (d *losableDialer) stop()           {}

// channelConn behaves like an SSH channel: deadlines fail and do nothing.
type channelConn struct {
	net.Conn
	closed sync.Once
	open   *atomic.Int64
}

func (c *channelConn) SetDeadline(time.Time) error { return errors.New("deadline not supported") }

func (c *channelConn) SetReadDeadline(time.Time) error { return errors.New("deadline not supported") }

func (c *channelConn) SetWriteDeadline(time.Time) error { return errors.New("deadline not supported") }

func (c *channelConn) Close() error {
	c.closed.Do(func() { c.open.Add(-1) })
	return c.Conn.Close()
}

// channelDialer plays the SSH tunnel: it reaches the address it is asked for
// through a channelConn and counts open channels. down plays a lost tunnel;
// unreachable, keyed by address, plays a channel that does not open: a non-nil
// error fails the dial.
type channelDialer struct {
	open        atomic.Int64
	down        atomic.Bool
	unreachable map[string]func(context.Context) error
}

func (d *channelDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if d.down.Load() {
		return nil, errors.New("SSH client not connected")
	}
	if f := d.unreachable[addr]; f != nil {
		if err := f(ctx); err != nil {
			return nil, err
		}
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	d.open.Add(1)
	return &channelConn{Conn: conn, open: &d.open}, nil
}

func (d *channelDialer) Connected() bool { return !d.down.Load() }

func (d *channelDialer) stop() {}

// tunnelServers is a rule engine with the given DNS servers behind d and a
// local resolver that answers 198.51.100.1 and counts its calls.
func tunnelServers(t *testing.T, d dialer, servers ...string) (*RuleEngine, *atomic.Int64) {
	t.Helper()
	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatalf("NewRuleEngine: %v", err)
	}
	rules.SetTunnelDNS(servers, d)
	var calls atomic.Int64
	rules.dns.localLookup = func(context.Context, string) ([]net.IPAddr, error) {
		calls.Add(1)
		return []net.IPAddr{{IP: net.ParseIP("198.51.100.1")}}, nil
	}
	return rules, &calls
}

// silentListener accepts connections and never answers.
func silentListener(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listener: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				io.Copy(io.Discard, conn)
				conn.Close()
			}()
		}
	}()
	return ln.Addr().String()
}
