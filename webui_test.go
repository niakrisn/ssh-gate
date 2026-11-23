package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// startTestHealth stands up a health server for API and UI checks.
func startTestHealth(t *testing.T, d dialer, tr *ConnTracker) string {
	t.Helper()
	h, err := NewHealthServer("127.0.0.1:0", d, tr)
	if err != nil {
		t.Fatalf("NewHealthServer: %v", err)
	}
	h.Start()
	t.Cleanup(func() { h.Shutdown(context.Background()) })
	return h.ln.Addr().String()
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

	addr := startTestHealth(t, testDialer{}, tr)
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

	pool := &sshTransportPool{id: "edge-a", host: "ssh-a.example.net", port: 22, user: "tunnel", quota: newServerQuota(10, 4, 2), health: newServerHealth(3, time.Minute, time.Minute, 3, 2)}
	pool.slots = []*transportSlot{{dialer: testDialer{}, index: 0}}
	pool.health.recordProbe(true)
	pool.health.recordProbe(true)
	set := &sshDialerSet{pools: []*sshTransportPool{pool}}
	h := &HealthServer{dialer: set, tracker: tr}

	var out struct {
		SSH struct {
			Connected bool              `json:"connected"`
			Eligible  bool              `json:"eligible"`
			Servers   []sshServerStatus `json:"servers"`
		} `json:"ssh"`
		Active      map[string]int `json:"active"`
		ActiveTotal int            `json:"active_total"`
		UptimeS     int64          `json:"uptime_s"`
	}
	rec := httptest.NewRecorder()
	h.statusHandler(rec, httptest.NewRequest(http.MethodGet, "/api/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d, want 200", rec.Code)
	}
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if !out.SSH.Connected || !out.SSH.Eligible || len(out.SSH.Servers) != 1 {
		t.Fatalf("SSH summary: %+v", out.SSH)
	}
	if out.ActiveTotal != 3 || out.Active["socks5"] != 2 || out.Active["http"] != 1 {
		t.Fatalf("active: total=%d map=%v", out.ActiveTotal, out.Active)
	}
	if slot := out.SSH.Servers[0].Transports[0]; slot.TCP == nil || slot.TCP.RTTMs != 42 || slot.TCP.TotalRetrans != 7 {
		t.Fatalf("transport tcp: %+v, want fixed test values", slot.TCP)
	}
	// uptime_s is the process uptime; handler and test share the clock, so
	// the value must lie within [0, elapsed].
	if want := int64(time.Since(processStartedAt).Seconds()); out.UptimeS < 0 || out.UptimeS > want+1 {
		t.Fatalf("uptime_s=%d, want in [0, %d]", out.UptimeS, want+1)
	}

	rec = httptest.NewRecorder()
	h.statusHandler(rec, httptest.NewRequest(http.MethodPost, "/api/status", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: code=%d, want 405", rec.Code)
	}
}

// TestWebUIStatusDNS: /api/status carries the resolver status when a source is
// set and null otherwise, and a degraded resolver does not touch readyz.
func TestWebUIStatusDNS(t *testing.T) {
	status := func(h *HealthServer) map[string]json.RawMessage {
		t.Helper()
		resp, err := http.Get("http://" + h.ln.Addr().String() + "/api/status")
		if err != nil {
			t.Fatalf("GET /api/status: %v", err)
		}
		defer resp.Body.Close()
		var out map[string]json.RawMessage
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return out
	}
	start := func(set bool) *HealthServer {
		h, err := NewHealthServer("127.0.0.1:0", testDialer{}, nil)
		if err != nil {
			t.Fatalf("NewHealthServer: %v", err)
		}
		if set {
			h.SetDNSStatus(func() dnsStatus {
				return dnsStatus{Mode: "servers", Degraded: true, Servers: []dnsServerStatus{{ServerID: "edge-a", Name: "1.1.1.1", OK: 1197, Fail: 3, Paused: true}}}
			})
		}
		h.Start()
		t.Cleanup(func() { h.Shutdown(context.Background()) })
		return h
	}

	off := status(start(false))
	if got := string(off["dns"]); got != "null" {
		t.Fatalf("dns without a source = %s, want null", got)
	}

	h := start(true)
	out := status(h)
	var dns dnsStatus
	if err := json.Unmarshal(out["dns"], &dns); err != nil {
		t.Fatalf("decode dns: %v", err)
	}
	if !dns.Degraded || len(dns.Servers) != 1 || dns.Servers[0].Fail != 3 || dns.Servers[0].ServerID != "edge-a" || !dns.Servers[0].Paused {
		t.Fatalf("dns = %+v", dns)
	}
	for _, key := range []string{"ssh", "active", "active_total", "uptime_s"} {
		if _, ok := out[key]; !ok {
			t.Fatalf("field %s lost", key)
		}
	}

	resp, err := http.Get("http://" + h.ln.Addr().String() + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("readyz with degraded DNS = %d, want 200", resp.StatusCode)
	}
}

// A transport without TCP stats must yield "tcp": null in /api/status.
func TestWebUIStatusAPIWithoutProvider(t *testing.T) {
	p := &sshTransportPool{id: "edge-a", host: "ssh-a.example.net", port: 22, health: newServerHealth(3, time.Minute, time.Minute, 3, 2), slots: []*transportSlot{{dialer: &captureMetaDialer{}, index: 0}}}
	p.health.recordProbe(true)
	p.health.recordProbe(true)
	h := &HealthServer{dialer: &sshDialerSet{pools: []*sshTransportPool{p}}}
	rec := httptest.NewRecorder()
	h.statusHandler(rec, httptest.NewRequest(http.MethodGet, "/api/status", nil))

	var out struct {
		SSH struct {
			Servers []sshServerStatus `json:"servers"`
		} `json:"ssh"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.SSH.Servers) != 1 || len(out.SSH.Servers[0].Transports) != 1 || out.SSH.Servers[0].Transports[0].TCP != nil {
		t.Fatalf("server transports = %+v, want tcp null", out.SSH.Servers)
	}
}

// A disconnected pool reports its per-server reason without an unauthenticated
// TCP probe to the SSH port.
func TestWebUIStatusReportsDisconnectedServer(t *testing.T) {
	p := &sshTransportPool{id: "edge-a", host: "ssh-a.example.net", port: 22, health: newServerHealth(3, time.Minute, time.Minute, 3, 2), slots: []*transportSlot{{dialer: disconnectedDialer{}, index: 0}}}
	h := &HealthServer{dialer: &sshDialerSet{pools: []*sshTransportPool{p}}}
	rec := httptest.NewRecorder()
	h.statusHandler(rec, httptest.NewRequest(http.MethodGet, "/api/status", nil))
	var out struct {
		SSH struct {
			Connected bool              `json:"connected"`
			Eligible  bool              `json:"eligible"`
			Servers   []sshServerStatus `json:"servers"`
		} `json:"ssh"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.SSH.Connected || out.SSH.Eligible || len(out.SSH.Servers) != 1 || out.SSH.Servers[0].State != "disconnected" {
		t.Fatalf("SSH status = %+v", out.SSH)
	}
	if out.SSH.Servers[0].Reason != "no connected SSH transport" {
		t.Fatalf("reason = %q", out.SSH.Servers[0].Reason)
	}
}

func TestWebUIStaticAndHealth(t *testing.T) {
	addr := startTestHealth(t, testDialer{}, nil)
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

// getWithHost sends GET path to addr with the given Host header.
func getWithHost(t *testing.T, addr, path, host string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://"+addr+path, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = host
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s (Host %s): %v", path, host, err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp
}

// TestWebUIHostGuard: the UI and the API answer only to allowed Host names.
// Without the check a page in a local browser could rebind its own name to
// 127.0.0.1 and read the connection history same-origin. Health probes stay
// open to any Host.
func TestWebUIHostGuard(t *testing.T) {
	tr := NewConnTracker(10, time.Minute)
	h, err := NewHealthServer("127.0.0.1:0", testDialer{}, tr)
	if err != nil {
		t.Fatalf("NewHealthServer: %v", err)
	}
	h.AllowHosts([]string{"gate.lan"})
	h.Start()
	t.Cleanup(func() { h.Shutdown(context.Background()) })
	addr := h.ln.Addr().String()
	_, port, _ := net.SplitHostPort(addr)

	for _, path := range []string{"/", "/app.js", "/api/connections", "/api/status"} {
		if resp := getWithHost(t, addr, path, "evil.example:"+port); resp.StatusCode != http.StatusForbidden {
			t.Errorf("GET %s with foreign Host = %d, want 403", path, resp.StatusCode)
		}
	}
	for _, host := range []string{"127.0.0.1:" + port, "localhost:" + port, "LocalHost", "[::1]:" + port, "gate.lan", "GATE.LAN.:" + port} {
		resp := getWithHost(t, addr, "/api/status", host)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET /api/status with Host %s = %d, want 200", host, resp.StatusCode)
			continue
		}
		if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
		}
		if got := resp.Header.Get("Content-Security-Policy"); !strings.Contains(got, "default-src 'self'") {
			t.Errorf("Content-Security-Policy = %q, want default-src 'self'", got)
		}
	}
	for _, path := range []string{"/healthz", "/readyz"} {
		if resp := getWithHost(t, addr, path, "10.0.0.7:"+port); resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s with any Host = %d, want 200", path, resp.StatusCode)
		}
	}
}

// TestWebUIHostGuardListenHost: a specific listen address is an allowed
// name; an unspecified one is not.
func TestWebUIHostGuardListenHost(t *testing.T) {
	h, err := NewHealthServer("0.0.0.0:0", testDialer{}, nil)
	if err != nil {
		t.Fatalf("NewHealthServer: %v", err)
	}
	defer h.ln.Close()
	if h.allowedHosts["0.0.0.0"] {
		t.Fatal("unspecified listen host 0.0.0.0 allowed as a Host name")
	}
	h2, err := NewHealthServer("127.0.0.2:0", testDialer{}, nil)
	if err != nil {
		t.Skipf("127.0.0.2 not bindable: %v", err)
	}
	defer h2.ln.Close()
	if !h2.allowedHosts["127.0.0.2"] {
		t.Fatal("specific listen host 127.0.0.2 not allowed")
	}
}

// disconnectedDialer is a testDialer whose SSH session is down.
type disconnectedDialer struct{ testDialer }

func (disconnectedDialer) Connected() bool { return false }

func TestStatusWithNoSSHServersKeepsListenerReady(t *testing.T) {
	h := &HealthServer{dialer: &sshDialerSet{}}
	h.SetReady(true)
	rec := httptest.NewRecorder()
	h.readyHandler(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("readyz = %d, want 200", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.statusHandler(rec, httptest.NewRequest(http.MethodGet, "/api/status", nil))
	var status struct {
		SSH struct {
			Connected bool              `json:"connected"`
			Eligible  bool              `json:"eligible"`
			Servers   []sshServerStatus `json:"servers"`
		} `json:"ssh"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	if status.SSH.Connected || status.SSH.Eligible || len(status.SSH.Servers) != 0 {
		t.Fatalf("ssh = %+v", status.SSH)
	}
}
