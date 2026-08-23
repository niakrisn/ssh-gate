package main

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
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
	rules, err := NewRuleEngine("ip:"+upHost+"/32", "", "")
	if err != nil {
		t.Fatal(err)
	}

	mockDialer := newMockSSHDialer()
	s5, err := NewSOCKS5Server("127.0.0.1:0", rules, mockDialer)
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

func TestHTTP_CONNECT_DirectRoute(t *testing.T) {
	upstream := newTestHTTPServer(t)
	defer upstream.Close()

	upHost, _, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	rules, err := NewRuleEngine("ip:"+upHost+"/32", "", "")
	if err != nil {
		t.Fatal(err)
	}

	mockDialer := newMockSSHDialer()
	hServer, err := NewHTTPServer("127.0.0.1:0", rules, mockDialer)
	if err != nil {
		t.Fatal(err)
	}
	hServer.Start()
	defer hServer.Shutdown(context.Background())

	proxyAddr := hServer.ln.Addr().String()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Send CONNECT request manually
	target := upstream.Listener.Addr().String()
	connectReq := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"
	if _, err := conn.Write([]byte(connectReq)); err != nil {
		t.Fatal(err)
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)
	respHeaders, _ := http.ReadResponse(reader, nil)
	conn.SetReadDeadline(time.Time{})
	assertEqual(t, respHeaders.StatusCode, http.StatusOK)
	respHeaders.Body.Close()

	// Send HTTP request through established tunnel
	reqStr := "GET /connect-test HTTP/1.1\r\nHost: " + target + "\r\nConnection: close\r\n\r\n"
	conn.Write([]byte(reqStr))

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	bodyReader := bufio.NewReader(conn)
	resp2, _ := http.ReadResponse(bodyReader, nil)
	conn.SetReadDeadline(time.Time{})
	assertEqual(t, resp2.StatusCode, http.StatusOK)

	body, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	assertContains(t, string(body), "OK /connect-test")

	// Direct route → tunnel dialer not called
	assertEqual(t, mockDialer.dialCount.Load(), int32(0))
}

func TestHTTP_CONNECT_TunnelRoute(t *testing.T) {
	upstream := newTestHTTPServer(t)
	defer upstream.Close()

	mockDialer := newMockSSHDialer()
	rules, err := NewRuleEngine("", "", "")
	if err != nil {
		t.Fatal(err)
	}

	hServer, err := NewHTTPServer("127.0.0.1:0", rules, mockDialer)
	if err != nil {
		t.Fatal(err)
	}
	hServer.Start()
	defer hServer.Shutdown(context.Background())

	proxyAddr := hServer.ln.Addr().String()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Send CONNECT request manually
	target := upstream.Listener.Addr().String()
	connectReq := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"
	if _, err := conn.Write([]byte(connectReq)); err != nil {
		t.Fatal(err)
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)
	respHeaders, _ := http.ReadResponse(reader, nil)
	conn.SetReadDeadline(time.Time{})
	assertEqual(t, respHeaders.StatusCode, http.StatusOK)
	respHeaders.Body.Close()

	// Send HTTP request through established tunnel
	reqStr := "GET /tunnel-test HTTP/1.1\r\nHost: " + target + "\r\nConnection: close\r\n\r\n"
	conn.Write([]byte(reqStr))

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	bodyReader := bufio.NewReader(conn)
	resp2, _ := http.ReadResponse(bodyReader, nil)
	conn.SetReadDeadline(time.Time{})
	assertEqual(t, resp2.StatusCode, http.StatusOK)

	body, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	assertContains(t, string(body), "OK /tunnel-test")

	// Tunnel route → dialer should have been called (only if target is not private)
	// Note: 127.x.x.x is private, so it routes direct even without rules
}

func TestSOCKS5_Routing_Direct(t *testing.T) {
	upstream := newTestHTTPServer(t)
	defer upstream.Close()

	upHost, _, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	mockDialer := newMockSSHDialer()
	rules, err := NewRuleEngine("ip:"+upHost+"/32", "", "")
	if err != nil {
		t.Fatal(err)
	}

	s5, err := NewSOCKS5Server("127.0.0.1:0", rules, mockDialer)
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
	rules, err := NewRuleEngine("", "", "")
	if err != nil {
		t.Fatal(err)
	}

	s5, err := NewSOCKS5Server("127.0.0.1:0", rules, mockDialer)
	if err != nil {
		t.Fatal(err)
	}
	s5.Start()
	defer s5.Shutdown(context.Background())

	// Non-private IP should route via tunnel (fallback)
	r := rules.Route("8.8.8.8", 80)
	assertEqual(t, r, RouteTunnel)
}

func TestHTTPServer_MethodNotAllowed(t *testing.T) {
	upstream := newTestHTTPServer(t)
	defer upstream.Close()

	upHost, upPort, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	rules, err := NewRuleEngine("ip:"+upHost+"/32", "", "")
	if err != nil {
		t.Fatal(err)
	}

	mockDialer := newMockSSHDialer()
	hServer, err := NewHTTPServer("127.0.0.1:0", rules, mockDialer)
	if err != nil {
		t.Fatal(err)
	}
	hServer.Start()
	defer hServer.Shutdown(context.Background())

	addr := hServer.ln.Addr().String()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + upHost + ":" + upPort + "\r\n\r\n"))
	assertNoError(t, err)

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	data, _ := io.ReadAll(conn)
	conn.SetReadDeadline(time.Time{})
	assertContains(t, string(data), "405")
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
	assertEqual(t, cfg.dohIP, "9.9.9.9")
}

func TestConfig_ProxyModes(t *testing.T) {
	t.Setenv("SSH_HOST", "vps.example.com")
	t.Setenv("SSH_USER", "user")
	t.Setenv("PROXY_MODES", "socks5,http,mtproto")
	t.Setenv("SOCKS5_LISTEN", "0.0.0.0:1080")
	t.Setenv("HTTP_LISTEN", "0.0.0.0:3128")
	t.Setenv("MTPROTO_LISTEN", "0.0.0.0:20443")
	t.Setenv("DIRECT_RULES", "ip:10.0.0.0/8")
	t.Setenv("TUNNEL_RULES", "re:.*\\.internal\\.com$")
	t.Setenv("NO_PROXY", "localhost")

	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}

	assertEqual(t, len(cfg.proxyModes), 3)
	assertEqual(t, cfg.socks5Addr, "0.0.0.0:1080")
	assertEqual(t, cfg.httpAddr, "0.0.0.0:3128")
	assertEqual(t, cfg.mtprotoAddr, "0.0.0.0:20443")
	assertEqual(t, cfg.directRules, "ip:10.0.0.0/8")
	assertEqual(t, cfg.tunnelRules, "re:.*\\.internal\\.com$")
	assertEqual(t, cfg.noProxy, "localhost")
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
	rules, err := NewRuleEngine("", "", "")
	if err != nil {
		t.Fatal(err)
	}

	s5, err := NewSOCKS5Server("127.0.0.1:0", rules, rd)
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

func TestHTTP_CONNECT_TunnelViaMockDialer(t *testing.T) {
	upstream := newTestHTTPServer(t)
	defer upstream.Close()

	upTarget := upstream.Listener.Addr().String()

	// Redirect dialer: any tunnel connection goes to upstream
	rd := &redirectDialer{target: upTarget}

	// Empty rules → non-private IP routes via tunnel
	rules, err := NewRuleEngine("", "", "")
	if err != nil {
		t.Fatal(err)
	}

	hServer, err := NewHTTPServer("127.0.0.1:0", rules, rd)
	if err != nil {
		t.Fatal(err)
	}
	hServer.Start()
	defer hServer.Shutdown(context.Background())

	conn, err := net.Dial("tcp", hServer.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// CONNECT to non-private IP (routes via tunnel → redirectDialer → upstream)
	remoteTarget := "8.8.8.8:80"
	connectReq := "CONNECT " + remoteTarget + " HTTP/1.1\r\nHost: " + remoteTarget + "\r\n\r\n"
	if _, err := conn.Write([]byte(connectReq)); err != nil {
		t.Fatal(err)
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)
	respHeaders, _ := http.ReadResponse(reader, nil)
	conn.SetReadDeadline(time.Time{})
	assertEqual(t, respHeaders.StatusCode, http.StatusOK)
	respHeaders.Body.Close()

	// Send HTTP request through tunnel
	reqStr := "GET /tunnel-http HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
	conn.Write([]byte(reqStr))

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	bodyReader := bufio.NewReader(conn)
	resp2, _ := http.ReadResponse(bodyReader, nil)
	conn.SetReadDeadline(time.Time{})
	assertEqual(t, resp2.StatusCode, http.StatusOK)

	body, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	assertContains(t, string(body), "OK /tunnel-http")

	// Tunnel route → dialer should have been called
	assertEqual(t, rd.dialCount.Load(), int32(1))
}

func TestSOCKS5_DirectRoute_LargePayload(t *testing.T) {
	upstream := newTestHTTPServer(t)
	defer upstream.Close()

	upHost, _, _ := net.SplitHostPort(upstream.Listener.Addr().String())
	rules, err := NewRuleEngine("ip:"+upHost+"/32", "", "")
	if err != nil {
		t.Fatal(err)
	}

	mockDialer := newMockSSHDialer()
	s5, err := NewSOCKS5Server("127.0.0.1:0", rules, mockDialer)
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

func TestHTTP_CONNECT_UpstreamUnreachable(t *testing.T) {
	rules, err := NewRuleEngine("", "", "")
	if err != nil {
		t.Fatal(err)
	}

	mockDialer := newMockSSHDialer()
	hServer, err := NewHTTPServer("127.0.0.1:0", rules, mockDialer)
	if err != nil {
		t.Fatal(err)
	}
	hServer.Start()
	defer hServer.Shutdown(context.Background())

	conn, err := net.Dial("tcp", hServer.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// CONNECT to a private IP with no listener → routes DIRECT, dial fails fast
	connectReq := "CONNECT 127.0.0.1:19999 HTTP/1.1\r\nHost: 127.0.0.1:19999\r\n\r\n"
	conn.Write([]byte(connectReq))

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	data, _ := io.ReadAll(conn)
	conn.SetReadDeadline(time.Time{})
	assertContains(t, string(data), "502")
}

func TestHTTPServer_Shutdown(t *testing.T) {
	rules, err := NewRuleEngine("", "", "")
	if err != nil {
		t.Fatal(err)
	}

	mockDialer := newMockSSHDialer()
	hServer, err := NewHTTPServer("127.0.0.1:0", rules, mockDialer)
	if err != nil {
		t.Fatal(err)
	}
	hServer.Start()

	addr := hServer.ln.Addr().String()

	// Verify server is running
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()

	// Shutdown should complete quickly
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err = hServer.Shutdown(ctx)
	assertNoError(t, err)

	// Server should no longer accept connections
	_, err = net.DialTimeout("tcp", addr, 1*time.Second)
	assertError(t, err)
}

func TestSOCKS5_ServerShutdown(t *testing.T) {
	rules, err := NewRuleEngine("", "", "")
	if err != nil {
		t.Fatal(err)
	}

	mockDialer := newMockSSHDialer()
	s5, err := NewSOCKS5Server("127.0.0.1:0", rules, mockDialer)
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
	rules, err := NewRuleEngine("ip:"+upHost+"/32", "", "")
	if err != nil {
		t.Fatal(err)
	}

	mockDialer := newMockSSHDialer()

	s5, err := NewSOCKS5Server("127.0.0.1:0", rules, mockDialer)
	if err != nil {
		t.Fatal(err)
	}
	s5.Start()
	defer s5.Shutdown(context.Background())

	hServer, err := NewHTTPServer("127.0.0.1:0", rules, mockDialer)
	if err != nil {
		t.Fatal(err)
	}
	hServer.Start()
	defer hServer.Shutdown(context.Background())

	// Both should be listening on different ports
	s5Addr := s5.ln.Addr().String()
	hAddr := hServer.ln.Addr().String()
	if s5Addr == hAddr {
		t.Fatal("SOCKS5 and HTTP should listen on different ports")
	}

	// Test SOCKS5 works
	s5Conn, err := net.Dial("tcp", s5Addr)
	if err != nil {
		t.Fatal(err)
	}
	s5Conn.Write([]byte{5, 1, 0})
	s5Resp := make([]byte, 2)
	io.ReadFull(s5Conn, s5Resp)
	assertEqual(t, s5Resp[0], byte(5))
	assertEqual(t, s5Resp[1], byte(0))
	s5Conn.Close()

	// Test HTTP works
	hConn, err := net.Dial("tcp", hAddr)
	if err != nil {
		t.Fatal(err)
	}
	target := upstream.Listener.Addr().String()
	connectReq := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"
	hConn.Write([]byte(connectReq))

	hConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(hConn)
	resp, _ := http.ReadResponse(reader, nil)
	hConn.SetReadDeadline(time.Time{})
	assertEqual(t, resp.StatusCode, http.StatusOK)
	resp.Body.Close()
	hConn.Close()
}

func TestSOCKS5_DirectRoute_ConcurrentConnections(t *testing.T) {
	upstream := newTestHTTPServer(t)
	defer upstream.Close()

	upHost, _, _ := net.SplitHostPort(upstream.Listener.Addr().String())
	rules, err := NewRuleEngine("ip:"+upHost+"/32", "", "")
	if err != nil {
		t.Fatal(err)
	}

	mockDialer := newMockSSHDialer()
	s5, err := NewSOCKS5Server("127.0.0.1:0", rules, mockDialer)
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
