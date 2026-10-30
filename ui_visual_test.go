package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"testing"
	"time"
)

// TestManualWebUIVisualHold is a manual stand, not an automated check: it
// serves seeded connections for a visual UI pass (run explicitly with
// UI_VISUAL=1; skips otherwise) and holds the server for 90 seconds.
func TestManualWebUIVisualHold(t *testing.T) {
	if os.Getenv("UI_VISUAL") == "" {
		t.Skip("UI_VISUAL not set")
	}

	tr := NewConnTracker(100, time.Hour)
	tr.Begin(ConnMeta{Proto: "socks5", Src: "192.168.1.10:51234"}, "github.com", 443)
	tr.Begin(ConnMeta{Proto: "http", Src: "192.168.1.10:51235"}, "example.org", 8080)

	for _, h := range []struct {
		host  string
		proto string
		err   string
	}{
		{"pypi.org", "socks5", "dial tcp: connection refused"},
		{"internal.corp", "http", ""},
		{"mail.example.com", "http", "read: connection reset by peer"},
		{"example.com", "socks5", ""},
		{"cdn.example.net", "socks5", ""},
		{"api.github.com", "http", ""},
	} {
		id := tr.Begin(ConnMeta{Proto: h.proto, Src: "192.168.1.10:40000"}, h.host, 443)
		if h.err != "" {
			tr.Fail(id, errors.New(h.err))
			continue
		}
		tr.Done(id, &fakeHalfCloseConn{}).Close()
	}

	// a live local port so the status line probes a reachable endpoint.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listener: %v", err)
	}
	defer l.Close()
	sshHost, portStr, _ := net.SplitHostPort(l.Addr().String())
	sshPort, _ := strconv.Atoi(portStr)

	// UI_VISUAL picks the DNS row: 1 healthy, 2 failures, 3 degraded, 4 no
	// resolvers (dns is null), 5 not configured (the whole status line).
	var d dialer = testDialer{}
	if os.Getenv("UI_VISUAL") == "5" {
		d = unconfiguredDialer{}
	}
	h, err := NewHealthServer("127.0.0.1:0", sshHost, sshPort, d, tr)
	if err != nil {
		t.Fatalf("NewHealthServer: %v", err)
	}
	dns, ok := map[string]dnsStatus{
		"1": {Mode: "servers", Servers: []dnsServerStatus{
			{Name: "1.1.1.1", OK: 1200, RTTMs: 14, LastOKAt: 1},
			{Name: "8.8.8.8"},
		}},
		"2": {Mode: "servers", Servers: []dnsServerStatus{
			{Name: "1.1.1.1", OK: 1197, Fail: 3, RTTMs: 14, LastOKAt: 1, Error: "i/o timeout"},
			{Name: "8.8.8.8"},
		}},
		"3": {Mode: "servers", Degraded: true, LocalFallbacks: 3, LastFallbackAt: 1, Servers: []dnsServerStatus{
			{Name: "1.1.1.1", Fail: 3, LastFailed: true, Error: "i/o timeout"},
			{Name: "8.8.8.8", Fail: 3, LastFailed: true, Error: "i/o timeout"},
		}},
	}[os.Getenv("UI_VISUAL")]
	if ok {
		h.SetDNSStatus(func() dnsStatus { return dns })
	}
	h.Start()
	t.Cleanup(func() { h.Shutdown(context.Background()) })
	fmt.Println("UI_VISUAL_URL http://" + h.ln.Addr().String() + "/")
	time.Sleep(90 * time.Second)
}
