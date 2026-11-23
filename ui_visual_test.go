package main

import (
	"context"
	"errors"
	"fmt"
	"os"
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

	// UI_VISUAL picks the DNS row: 1 healthy, 2 recent failures, 3 excluded,
	// 4 no resolver status, 5 no SSH servers (direct routes only).
	mode := os.Getenv("UI_VISUAL")
	var d dialer
	if mode == "5" {
		d = &sshDialerSet{}
	} else {
		pool := &sshTransportPool{id: "edge-a", host: "ssh-a.example.net", port: 22, user: "tunnel", healthURL: "https://www.youtube.com", quota: newServerQuota(4096, 256, 32), health: newServerHealth(3, 30*time.Second, 30*time.Second, 3, 2), slots: []*transportSlot{{dialer: testDialer{}, index: 0}}}
		switch mode {
		case "1", "4":
			pool.recordHealthProbe(nil)
			pool.recordHealthProbe(nil)
		case "2":
			pool.recordHealthProbe(nil)
			pool.recordHealthProbe(nil)
			pool.recordHealthProbe(errors.New("i/o timeout"))
			pool.recordHealthProbe(errors.New("i/o timeout"))
		case "3":
			for range 3 {
				pool.recordHealthProbe(errors.New("i/o timeout"))
			}
		}
		d = &sshDialerSet{pools: []*sshTransportPool{pool}}
	}
	h, err := NewHealthServer("127.0.0.1:0", d, tr)
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
		"3": {Mode: "servers", Degraded: true, Servers: []dnsServerStatus{
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
