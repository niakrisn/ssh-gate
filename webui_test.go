package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// startTestHealth stands up a health server that probes the given SSH
// endpoint (usually a live or dead local port) for /api/status.
func startTestHealth(t *testing.T, d dialer, tr *ConnTracker, sshHost string, sshPort int) string {
	t.Helper()
	h, err := NewHealthServer("127.0.0.1:0", sshHost, sshPort, d, tr)
	if err != nil {
		t.Fatalf("NewHealthServer: %v", err)
	}
	h.Start()
	t.Cleanup(func() { h.Shutdown(context.Background()) })
	return h.ln.Addr().String()
}

// liveLocalPort returns the address of a throwaway TCP listener.
func liveLocalPort(t *testing.T) (string, int) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listener: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	host, portStr, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port: %v", err)
	}
	return host, port
}

func getAPI(t *testing.T, url string) (int, connectionsResponse) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	var out connectionsResponse
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatalf("decode %s: %v", url, err)
		}
	}
	return resp.StatusCode, out
}

func TestWebUIConnectionsAPI(t *testing.T) {
	tr := NewConnTracker(100, time.Minute)
	idOld := tr.Begin(ConnMeta{Proto: "socks5", Src: "10.0.0.1:1111"}, "example.com", 443)
	tr.Fail(idOld, errors.New("boom"))
	idNew := tr.Begin(ConnMeta{Proto: "http", Src: "10.0.0.1:2222"}, "example.org", 80)
	tr.Fail(idNew, errors.New("boom2"))
	idLive := tr.Begin(ConnMeta{Proto: "socks5", Src: "10.0.0.3:3333"}, "live.example.com", 8443)
	_ = idLive

	addr := startTestHealth(t, testDialer{}, tr, "127.0.0.1", 1)
	base := "http://" + addr

	// history: both records, newest first, default page/page_size.
	code, body := getAPI(t, base+"/api/connections?tab=history")
	if code != http.StatusOK || body.Total != 2 || len(body.Items) != 2 {
		t.Fatalf("history: code=%d total=%d items=%d", code, body.Total, len(body.Items))
	}
	if body.Page != 1 || body.PageSize != 50 {
		t.Fatalf("defaults: page=%d page_size=%d", body.Page, body.PageSize)
	}
	if body.Items[0].ID != idNew || body.Items[1].ID != idOld {
		t.Fatalf("sort: %v", body.Items)
	}

	// active: live record in dialing status.
	code, body = getAPI(t, base+"/api/connections?tab=active")
	if code != http.StatusOK || body.Total != 1 || body.Items[0].Status != StateDialing {
		t.Fatalf("active: code=%d body=%+v", code, body)
	}
	if body.Items[0].Host != "live.example.com" || body.Items[0].Port != 8443 {
		t.Fatalf("active record: %+v", body.Items[0])
	}

	// q: case-insensitive host substring.
	if _, body = getAPI(t, base+"/api/connections?tab=history&q=EXAMPLE"); body.Total != 2 {
		t.Fatalf("q=EXAMPLE: total=%d", body.Total)
	}
	if _, body = getAPI(t, base+"/api/connections?tab=history&q=live"); body.Total != 0 {
		t.Fatalf("q=live: total=%d", body.Total)
	}

	// proto: exact protocol filter.
	if _, body = getAPI(t, base+"/api/connections?tab=history&proto=socks5"); body.Total != 1 {
		t.Fatalf("proto=socks5: total=%d, want 1", body.Total)
	}
	if _, body = getAPI(t, base+"/api/connections?tab=history&proto=bogus"); body.Total != 0 {
		t.Fatalf("proto=bogus: total=%d, want 0", body.Total)
	}

	// pagination: second of two pages.
	code, body = getAPI(t, base+"/api/connections?tab=history&page=2&page_size=1")
	if code != http.StatusOK || body.Total != 2 || len(body.Items) != 1 || body.Items[0].ID != idOld {
		t.Fatalf("page 2: code=%d body=%+v", code, body)
	}

	// the default tab is active.
	if _, body = getAPI(t, base+"/api/connections"); body.Total != 1 {
		t.Fatalf("default tab: total=%d", body.Total)
	}

	// 400 on invalid parameters.
	for _, path := range []string{
		"/api/connections?tab=bogus",
		"/api/connections?page=0",
		"/api/connections?page=abc",
		"/api/connections?page_size=0",
		"/api/connections?page_size=201",
		"/api/connections?page_size=abc",
	} {
		code, _ = getAPI(t, base+path)
		if code != http.StatusBadRequest {
			t.Fatalf("%s: code=%d, want 400", path, code)
		}
	}

	// POST is not supported.
	resp, err := http.Post(base+"/api/connections", "application/x-www-form-urlencoded", nil)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST: code=%d, want 405", resp.StatusCode)
	}
}

func TestWebUIStatusAPI(t *testing.T) {
	tr := NewConnTracker(100, time.Minute)
	tr.Begin(ConnMeta{Proto: "socks5"}, "h1", 443)
	tr.Begin(ConnMeta{Proto: "socks5"}, "h2", 443)
	tr.Begin(ConnMeta{Proto: "http"}, "h3", 80)

	sshHost, sshPort := liveLocalPort(t)
	addr := startTestHealth(t, testDialer{}, tr, sshHost, sshPort)

	var out struct {
		SSH struct {
			Host      string    `json:"host"`
			Port      int       `json:"port"`
			Connected bool      `json:"connected"`
			Reachable bool      `json:"reachable"`
			RttMs     int64     `json:"rtt_ms"`
			TCP       *tcpStats `json:"tcp"`
		} `json:"ssh"`
		Active      map[string]int `json:"active"`
		ActiveTotal int            `json:"active_total"`
	}
	// the first probe runs right after Start; retry briefly until it landed.
	for i := 0; i < 20; i++ {
		resp, err := http.Get("http://" + addr + "/api/status")
		if err != nil {
			t.Fatalf("GET /api/status: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("code=%d, want 200", resp.StatusCode)
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		resp.Body.Close()
		if out.SSH.Reachable {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if out.SSH.Host != sshHost || out.SSH.Port != sshPort {
		t.Fatalf("ssh endpoint: %+v", out.SSH)
	}
	if !out.SSH.Reachable || out.SSH.RttMs < 0 {
		t.Fatalf("probe: reachable=%v rtt=%d", out.SSH.Reachable, out.SSH.RttMs)
	}
	if !out.SSH.Connected {
		t.Fatal("testDialer is connected, want connected=true")
	}
	if out.ActiveTotal != 3 || out.Active["socks5"] != 2 || out.Active["http"] != 1 {
		t.Fatalf("active: total=%d map=%v", out.ActiveTotal, out.Active)
	}
	// testDialer implements tcpStatsProvider with fixed values.
	if out.SSH.TCP == nil || out.SSH.TCP.RTTMs != 42 || out.SSH.TCP.TotalRetrans != 7 {
		t.Fatalf("tcp: %+v, want fixed test values", out.SSH.TCP)
	}

	resp, err := http.Post("http://"+addr+"/api/status", "", nil)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST: code=%d, want 405", resp.StatusCode)
	}
}

// TestWebUIStatusAPIWithoutProvider: a dialer without TunnelTCPStats must
// yield "tcp": null in /api/status, not fail the request.
func TestWebUIStatusAPIWithoutProvider(t *testing.T) {
	sshHost, sshPort := liveLocalPort(t)
	addr := startTestHealth(t, &captureMetaDialer{}, nil, sshHost, sshPort)

	resp, err := http.Get("http://" + addr + "/api/status")
	if err != nil {
		t.Fatalf("GET /api/status: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("code=%d, want 200", resp.StatusCode)
	}

	var out struct {
		SSH struct {
			TCP *tcpStats `json:"tcp"`
		} `json:"ssh"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.SSH.TCP != nil {
		t.Fatalf("tcp = %+v, want null", out.SSH.TCP)
	}
}

// TestWebUIStatusAPIUnreachable: a dead SSH port must report
// reachable=false with zero rtt (the first probe runs right after Start).
func TestWebUIStatusAPIUnreachable(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listener: %v", err)
	}
	deadHost, deadPortStr, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	l.Close()
	deadPort, err := strconv.Atoi(deadPortStr)
	if err != nil {
		t.Fatalf("port: %v", err)
	}

	addr := startTestHealth(t, testDialer{}, nil, deadHost, deadPort)

	var out struct {
		SSH struct {
			Reachable bool  `json:"reachable"`
			RttMs     int64 `json:"rtt_ms"`
			CheckedAt int64 `json:"checked_at"`
		} `json:"ssh"`
	}
	// Before the first probe lands, checked_at is a zero time (negative unix).
	for i := 0; i < 20; i++ {
		resp, err := http.Get("http://" + addr + "/api/status")
		if err != nil {
			t.Fatalf("GET /api/status: %v", err)
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		resp.Body.Close()
		if out.SSH.CheckedAt > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if out.SSH.CheckedAt <= 0 {
		t.Fatal("probe never completed")
	}
	if out.SSH.Reachable || out.SSH.RttMs != 0 {
		t.Fatalf("probe: reachable=%v rtt=%d, want false/0", out.SSH.Reachable, out.SSH.RttMs)
	}
}

func TestWebUIStaticAndHealth(t *testing.T) {
	addr := startTestHealth(t, testDialer{}, nil, "127.0.0.1", 1)
	base := "http://" + addr

	// / serves index.html.
	resp, err := http.Get(base + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(data), "<title>ssh-gate</title>") {
		t.Fatalf("/: code=%d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("/ content-type: %q", ct)
	}

	// static assets: content type by extension, not sniffing.
	for p, wantCT := range map[string]string{
		"/app.js":    "text/javascript",
		"/style.css": "text/css",
	} {
		resp, err := http.Get(base + p)
		if err != nil {
			t.Fatalf("GET %s: %v", p, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: code=%d", p, resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, wantCT) {
			t.Fatalf("%s content-type: %q, want prefix %q", p, ct, wantCT)
		}
	}

	// unknown paths return 404.
	for _, p := range []string{"/favicon.ico", "/nope.js", "/sub/dir"} {
		resp, err := http.Get(base + p)
		if err != nil {
			t.Fatalf("GET %s: %v", p, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s: code=%d, want 404", p, resp.StatusCode)
		}
	}

	// health endpoints are unchanged.
	resp, err = http.Get(base + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	data, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(data) != "ok" {
		t.Fatalf("/healthz: code=%d body=%q", resp.StatusCode, data)
	}
	resp, err = http.Get(base + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz: %v", err)
	}
	data, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(data) != "ok" {
		t.Fatalf("/readyz: code=%d body=%q", resp.StatusCode, data)
	}

	// tracker == nil: the API answers with an empty list instead of panicking.
	code, body := getAPI(t, base+"/api/connections?tab=history")
	if code != http.StatusOK || body.Total != 0 || len(body.Items) != 0 {
		t.Fatalf("nil tracker: code=%d body=%+v", code, body)
	}
}
