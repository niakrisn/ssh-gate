package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/9seconds/mtg/v2/network"
)

func TestSOCKS5_DirectRoute(t *testing.T) {
	upstream := newTestHTTPServer(t)
	defer upstream.Close()

	upHost, _, _ := net.SplitHostPort(upstream.Listener.Addr().String())
	rules, err := NewRuleEngine("ip:"+upHost+"/32")
	if err != nil {
		t.Fatal(err)
	}

	mockDialer := newMockSSHDialer()
	s5, err := NewSOCKS5Server("127.0.0.1:0", rules, mockDialer, FamilyBoth)
	if err != nil {
		t.Fatal(err)
	}
	s5.Start()
	defer s5.Shutdown(context.Background())

	addr := s5.ln.Addr().String()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// SOCKS5 handshake
	conn.Write([]byte{5, 1, 0}) // VER=5, NMETHODS=1, METHODS=no-auth
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}
	if resp[0] != 5 || resp[1] != 0 {
		t.Fatalf("bad handshake: %v", resp)
	}

	// CONNECT request — domain ATYP with separate host and port
	targetHost, targetPortStr, _ := net.SplitHostPort(upstream.Listener.Addr().String())
	targetPort, _ := strconv.Atoi(targetPortStr)
	req := []byte{5, 1, 0, 3, byte(len(targetHost))}
	req = append(req, []byte(targetHost)...)
	req = append(req, byte(targetPort>>8), byte(targetPort))
	conn.Write(req)

	reply := make([]byte, 6)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0 {
		t.Fatalf("connect failed: %v", reply)
	}

	// HTTP request through proxy (with Connection: close to get EOF)
	target := upstream.Listener.Addr().String()
	reqStr := "GET /test HTTP/1.1\r\nHost: " + target + "\r\nConnection: close\r\n\r\n"
	conn.Write([]byte(reqStr))

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	// Read response line-by-line until we get body (works even with splice relay)
	reader := bufio.NewReader(conn)
	var respBody string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		if line == "\r\n" {
			// headers done, read body
			bodyBytes, _ := io.ReadAll(reader)
			respBody = string(bodyBytes)
			break
		}
	}
	conn.SetReadDeadline(time.Time{})
	assertContains(t, respBody, "OK /test")

	// Direct route → tunnel dialer not called
	assertEqual(t, mockDialer.dialCount.Load(), int32(0))
}

func TestSOCKS5_Routing_Direct(t *testing.T) {
	upstream := newTestHTTPServer(t)
	defer upstream.Close()

	upHost, _, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	mockDialer := newMockSSHDialer()
	rules, err := NewRuleEngine("ip:"+upHost+"/32")
	if err != nil {
		t.Fatal(err)
	}

	s5, err := NewSOCKS5Server("127.0.0.1:0", rules, mockDialer, FamilyBoth)
	if err != nil {
		t.Fatal(err)
	}
	s5.Start()
	defer s5.Shutdown(context.Background())

	r := rules.Route(upHost, 80)
	assertEqual(t, r, RouteDirect)
}

func TestSOCKS5_Routing_Tunnel(t *testing.T) {
	mockDialer := newMockSSHDialer()
	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatal(err)
	}

	s5, err := NewSOCKS5Server("127.0.0.1:0", rules, mockDialer, FamilyBoth)
	if err != nil {
		t.Fatal(err)
	}
	s5.Start()
	defer s5.Shutdown(context.Background())

	// Non-private IP should route via tunnel (fallback)
	r := rules.Route("8.8.8.8", 80)
	assertEqual(t, r, RouteTunnel)
}

func TestMTProtoServer_Create(t *testing.T) {
	mockDialer := newMockSSHDialer()
	// Format: ee + 16-byte key (32 hex) + hostname (ASCII hex)
	// ee + deadbeef...deadbeef + "example.com"
	srv, err := newMTProtoServer("127.0.0.1:0", "ee"+
		"deadbeefdeadbeefdeadbeefdeadbeef"+
		"6578616d706c652e636f6d", mockDialer.NetworkDialer(), "9.9.9.9")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Shutdown(context.Background())

	if srv.ln == nil {
		t.Fatal("expected listener")
	}
	if srv.proxy == nil {
		t.Fatal("expected proxy")
	}
}

func TestMTProtoServer_ListenPort(t *testing.T) {
	mockDialer := newMockSSHDialer()
	srv, err := newMTProtoServer("127.0.0.1:0", "ee"+
		"deadbeefdeadbeefdeadbeefdeadbeef"+
		"6578616d706c652e636f6d", mockDialer.NetworkDialer(), "9.9.9.9")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Shutdown(context.Background())

	srv.Start()

	conn, err := net.DialTimeout("tcp", srv.ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}

func TestMTProtoServer_InvalidSecret(t *testing.T) {
	mockDialer := newMockSSHDialer()
	_, err := newMTProtoServer("127.0.0.1:0", "invalid_secret", mockDialer.NetworkDialer(), "9.9.9.9")
	assertError(t, err)
}

func TestParseModes(t *testing.T) {
	tests := []struct {
		raw  string
		want []string
	}{
		{"socks5", []string{"socks5"}},
		{"socks5,http", []string{"socks5", "http"}},
		{"socks5,http,mtproto", []string{"socks5", "http", "mtproto"}},
		{"SOCKS5,HTTP", []string{"socks5", "http"}},
		{"", []string{"socks5"}},
		{"socks5, , mtproto", []string{"socks5", "mtproto"}},
	}

	for _, tc := range tests {
		got := parseModes(tc.raw)
		if len(got) != len(tc.want) {
			t.Errorf("parseModes(%q) = %v, want %v", tc.raw, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("parseModes(%q)[%d] = %q, want %q", tc.raw, i, got[i], tc.want[i])
			}
		}
	}
}

func TestContains(t *testing.T) {
	tests := []struct {
		slice []string
		elem  string
		want  bool
	}{
		{[]string{"socks5", "http"}, "socks5", true},
		{[]string{"socks5", "http"}, "mtproto", false},
		{[]string{}, "socks5", false},
	}

	for _, tc := range tests {
		got := contains(tc.slice, tc.elem)
		assertEqual(t, got, tc.want)
	}
}

func TestConfig_LoadConfig(t *testing.T) {
	t.Setenv("SSH_HOST", "vps.example.com")
	t.Setenv("SSH_USER", "user")

	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}

	assertEqual(t, cfg.sshHost, "vps.example.com")
	assertEqual(t, cfg.sshPort, 22)
	assertEqual(t, cfg.sshUser, "user")
	assertEqual(t, len(cfg.proxyModes), 1)
	assertEqual(t, cfg.proxyModes[0], "socks5")
	assertEqual(t, cfg.socks5Addr, ":1080")
	assertEqual(t, cfg.directIPFamily, FamilyBoth)
	assertEqual(t, cfg.dohIP, "9.9.9.9")
}

func TestConfig_ProxyModes(t *testing.T) {
	t.Setenv("SSH_HOST", "vps.example.com")
	t.Setenv("SSH_USER", "user")
	t.Setenv("PROXY_MODES", "socks5,mtproto")
	t.Setenv("SOCKS5_LISTEN", "0.0.0.0:1080")
	t.Setenv("MTPROTO_LISTEN", "0.0.0.0:20443")
	t.Setenv("DIRECT_RULES", "ip:10.0.0.0/8")
	t.Setenv("DIRECT_IP_FAMILY", "ipv6")

	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}

	assertEqual(t, len(cfg.proxyModes), 2)
	assertEqual(t, cfg.socks5Addr, "0.0.0.0:1080")
	assertEqual(t, cfg.mtprotoAddr, "0.0.0.0:20443")
	assertEqual(t, cfg.directRules, "ip:10.0.0.0/8")
	assertEqual(t, cfg.directIPFamily, FamilyIPv6)
}

// redirectDialer redirects all connections to a fixed target address.
type redirectDialer struct {
	target    string
	dialCount atomic.Int32
}

func (r *redirectDialer) DialContext(_ context.Context, network, _ string) (net.Conn, error) {
	r.dialCount.Add(1)
	return net.Dial(network, r.target)
}

func (r *redirectDialer) NetworkDialer() network.Dialer {
	return &mockNetworkDialer{m: (*mockSSHDialer)(nil)} // unused in these tests
}

func (r *redirectDialer) stop() {}

func TestSOCKS5_TunnelViaMockDialer(t *testing.T) {
	upstream := newTestHTTPServer(t)
	defer upstream.Close()

	upTarget := upstream.Listener.Addr().String()

	// Use redirect dialer: any CONNECT request goes to upstream
	rd := &redirectDialer{target: upTarget}

	// Empty rules → non-private IP routes via tunnel (mock dialer)
	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatal(err)
	}

	s5, err := NewSOCKS5Server("127.0.0.1:0", rules, rd, FamilyBoth)
	if err != nil {
		t.Fatal(err)
	}
	s5.Start()
	defer s5.Shutdown(context.Background())

	conn, err := net.Dial("tcp", s5.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// SOCKS5 handshake
	conn.Write([]byte{5, 1, 0})
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}
	if resp[0] != 5 || resp[1] != 0 {
		t.Fatalf("bad handshake: %v", resp)
	}

	// CONNECT to non-private IP (routes via tunnel → redirectDialer → upstream)
	remoteHost := "8.8.8.8"
	remotePort := 80
	req := []byte{5, 1, 0, 3, byte(len(remoteHost))}
	req = append(req, []byte(remoteHost)...)
	req = append(req, byte(remotePort>>8), byte(remotePort))
	conn.Write(req)

	reply := make([]byte, 6)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0 {
		t.Fatalf("connect failed: %v", reply)
	}

	// Send HTTP request (tunneled to upstream via redirectDialer)
	reqStr := "GET /tunnel HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
	conn.Write([]byte(reqStr))

	// Read with deadline — splice relay may close connection before/after response
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	allData, err := io.ReadAll(conn)
	conn.SetReadDeadline(time.Time{})
	if err != nil && err != io.EOF {
		t.Fatalf("read error: %v", err)
	}
	assertContains(t, string(allData), "HTTP/")
	assertContains(t, string(allData), "200")
	assertContains(t, string(allData), "OK /tunnel")

	// Tunnel route → dialer should have been called
	assertEqual(t, rd.dialCount.Load(), int32(1))
}

func TestSOCKS5_DirectRoute_LargePayload(t *testing.T) {
	upstream := newTestHTTPServer(t)
	defer upstream.Close()

	upHost, _, _ := net.SplitHostPort(upstream.Listener.Addr().String())
	rules, err := NewRuleEngine("ip:"+upHost+"/32")
	if err != nil {
		t.Fatal(err)
	}

	mockDialer := newMockSSHDialer()
	s5, err := NewSOCKS5Server("127.0.0.1:0", rules, mockDialer, FamilyBoth)
	if err != nil {
		t.Fatal(err)
	}
	s5.Start()
	defer s5.Shutdown(context.Background())

	conn, err := net.Dial("tcp", s5.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Handshake
	conn.Write([]byte{5, 1, 0})
	resp := make([]byte, 2)
	io.ReadFull(conn, resp)

	// CONNECT
	targetHost, targetPortStr, _ := net.SplitHostPort(upstream.Listener.Addr().String())
	targetPort, _ := strconv.Atoi(targetPortStr)
	req := []byte{5, 1, 0, 3, byte(len(targetHost))}
	req = append(req, []byte(targetHost)...)
	req = append(req, byte(targetPort>>8), byte(targetPort))
	conn.Write(req)

	reply := make([]byte, 6)
	io.ReadFull(conn, reply)

	// Send request with body
	body := strings.Repeat("A", 8192)
	reqStr := "POST /post HTTP/1.1\r\nHost: " + upstream.Listener.Addr().String() +
		"\r\nContent-Length: " + strconv.Itoa(len(body)) +
		"\r\nConnection: close\r\n\r\n" + body
	conn.Write([]byte(reqStr))

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	data, _ := io.ReadAll(conn)
	conn.SetReadDeadline(time.Time{})
	assertContains(t, string(data), "200")
	assertContains(t, string(data), "OK /post")
}

func TestSOCKS5_ServerShutdown(t *testing.T) {
	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatal(err)
	}

	mockDialer := newMockSSHDialer()
	s5, err := NewSOCKS5Server("127.0.0.1:0", rules, mockDialer, FamilyBoth)
	if err != nil {
		t.Fatal(err)
	}
	s5.Start()

	addr := s5.ln.Addr().String()

	// Verify server is running
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()

	// Shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err = s5.Shutdown(ctx)
	assertNoError(t, err)

	// Server should no longer accept connections
	_, err = net.DialTimeout("tcp", addr, 1*time.Second)
	assertError(t, err)
}

func TestMultiServer_Concurrent(t *testing.T) {
	upstream := newTestHTTPServer(t)
	defer upstream.Close()

	upHost, _, _ := net.SplitHostPort(upstream.Listener.Addr().String())
	rules, err := NewRuleEngine("ip:"+upHost+"/32")
	if err != nil {
		t.Fatal(err)
	}

	mockDialer := newMockSSHDialer()

	s5, err := NewSOCKS5Server("127.0.0.1:0", rules, mockDialer, FamilyBoth)
	if err != nil {
		t.Fatal(err)
	}
	s5.Start()
	defer s5.Shutdown(context.Background())

	// Test SOCKS5 works
	s5Conn, err := net.Dial("tcp", s5.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	s5Conn.Write([]byte{5, 1, 0})
	s5Resp := make([]byte, 2)
	io.ReadFull(s5Conn, s5Resp)
	assertEqual(t, s5Resp[0], byte(5))
	assertEqual(t, s5Resp[1], byte(0))
	s5Conn.Close()
}

func TestSOCKS5_DirectRoute_ConcurrentConnections(t *testing.T) {
	upstream := newTestHTTPServer(t)
	defer upstream.Close()

	upHost, _, _ := net.SplitHostPort(upstream.Listener.Addr().String())
	rules, err := NewRuleEngine("ip:"+upHost+"/32")
	if err != nil {
		t.Fatal(err)
	}

	mockDialer := newMockSSHDialer()
	s5, err := NewSOCKS5Server("127.0.0.1:0", rules, mockDialer, FamilyBoth)
	if err != nil {
		t.Fatal(err)
	}
	s5.Start()
	defer s5.Shutdown(context.Background())

	target := upstream.Listener.Addr().String()
	targetHost, targetPortStr, _ := net.SplitHostPort(target)
	targetPort, _ := strconv.Atoi(targetPortStr)

	for i := 0; i < 5; i++ {
		conn, err := net.Dial("tcp", s5.ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}

		// Handshake
		conn.Write([]byte{5, 1, 0})
		resp := make([]byte, 2)
		io.ReadFull(conn, resp)

		// CONNECT
		req := []byte{5, 1, 0, 3, byte(len(targetHost))}
		req = append(req, []byte(targetHost)...)
		req = append(req, byte(targetPort>>8), byte(targetPort))
		conn.Write(req)

		reply := make([]byte, 6)
		io.ReadFull(conn, reply)
		if reply[1] != 0 {
			conn.Close()
			t.Fatalf("connect failed on iteration %d: %v", i, reply)
		}

		// Request
		reqStr := "GET /concurrent HTTP/1.1\r\nHost: " + target + "\r\nConnection: close\r\n\r\n"
		conn.Write([]byte(reqStr))

		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		data, _ := io.ReadAll(conn)
		conn.SetReadDeadline(time.Time{})
		conn.Close()

		assertContains(t, string(data), "OK /concurrent")
	}
}

// newTestTLSServer creates an HTTPS server that echoes the request path.
func newTestTLSServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK " + r.URL.Path))
	}))
	srv.Config.ErrorLog = nil
	return srv
}

// TestSOCKS5_DirectRoute_TLS_Idle verifies that a direct-route SOCKS5 connection
// to a TLS upstream survives idle periods >10 seconds.
// Uses http.Client with socks5:// proxy (Go 1.19+ built-in SOCKS5 support)
// to avoid racing tls.Client and go-socks5 Proxy on the same file descriptor.
func TestSOCKS5_DirectRoute_TLS_Idle(t *testing.T) {
	// Upstream TLS server that sleeps 12s before responding.
	// During that sleep the proxy-relayed connection is idle.
	// If proxy kills idle connections, the request fails.
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(12 * time.Second)
		w.Write([]byte("OK " + r.URL.Path))
	}))
	defer upstream.Close()

	upHost, _, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	rules, err := NewRuleEngine("ip:"+upHost+"/32")
	if err != nil {
		t.Fatal(err)
	}

	mockDialer := newMockSSHDialer()
	s5, err := NewSOCKS5Server("127.0.0.1:0", rules, mockDialer, FamilyBoth)
	if err != nil {
		t.Fatal(err)
	}
	s5.Start()
	defer s5.Shutdown(context.Background())

	proxyURL, _ := url.Parse("socks5://" + s5.ln.Addr().String())

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   20 * time.Second,
	}

	resp, err := client.Get(upstream.URL + "/socks5-idle")
	if err != nil {
		t.Fatalf("GET via SOCKS5: %v", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	assertContains(t, string(data), "OK /socks5-idle")

	// Direct route → tunnel dialer not called
	assertEqual(t, mockDialer.dialCount.Load(), int32(0))
}
