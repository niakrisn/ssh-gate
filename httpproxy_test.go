package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/9seconds/mtg/v2/network"
)

// testDialer dials Target (usually a local server); when Target is empty it
// dials the requested address directly. When Err is set it is returned
// without dialing.
type testDialer struct {
	Target string
	Err    error
}

func (td testDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if td.Err != nil {
		return nil, td.Err
	}
	if td.Target != "" {
		addr = td.Target
	}
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

func (testDialer) NetworkDialer() network.Dialer { return nil }
func (testDialer) Connected() bool               { return true }
func (testDialer) stop()                         {}

func startTestProxy(t *testing.T, dialTarget string) *HTTPProxyServer {
	t.Helper()
	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatalf("NewRuleEngine: %v", err)
	}
	s, err := NewHTTPProxyServer("127.0.0.1:0", rules, testDialer{Target: dialTarget}, FamilyBoth)
	if err != nil {
		t.Fatalf("NewHTTPProxyServer: %v", err)
	}
	s.Start()
	t.Cleanup(func() { s.Shutdown(context.Background()) })
	return s
}

func proxyAddr(s *HTTPProxyServer) string {
	return s.ln.Addr().String()
}

func readStatus(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	line, err := r.ReadSlice('\n')
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	return string(line)
}

// oneShotHTTPServer accepts a single raw HTTP request, captures the body
// (by Content-Length or until EOF for close-delimited bodies) and replies 200.
func oneShotHTTPServer(t *testing.T, bodyOut chan []byte) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("server listener: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		if _, err := r.ReadString('\n'); err != nil {
			return
		}
		var contentLength int64 = -1
		for {
			line, err := r.ReadString('\n')
			if err != nil || line == "\r\n" {
				break
			}
			if v, ok := strings.CutPrefix(strings.ToLower(line), "content-length:"); ok {
				contentLength, _ = strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			}
		}
		var body []byte
		if contentLength >= 0 {
			body = make([]byte, contentLength)
			if _, err := io.ReadFull(r, body); err != nil {
				return
			}
		} else {
			body, _ = io.ReadAll(r)
		}
		bodyOut <- body
		io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	}()
	return ln
}

func expectStatus(t *testing.T, r *bufio.Reader, want string) {
	t.Helper()
	status := readStatus(t, r)
	if !strings.HasPrefix(status, "HTTP/1.1 "+want) {
		t.Fatalf("status = %q, want %s", status, want)
	}
}

// TestHTTPProxyCONNECT tunnels to a local echo server.
func TestHTTPProxyCONNECT(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listener: %v", err)
	}
	defer echo.Close()
	go func() {
		c, err := echo.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.Copy(c, c)
	}()

	s := startTestProxy(t, "")

	c, err := net.Dial("tcp", proxyAddr(s))
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer c.Close()

	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echo.Addr().String(), echo.Addr().String())
	r := bufio.NewReader(c)
	expectStatus(t, r, "200")
	// Read the empty line terminating the CONNECT response.
	if _, err := r.ReadSlice('\n'); err != nil {
		t.Fatalf("read CONNECT end: %v", err)
	}

	c.Write([]byte("hello"))
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != "hello" {
		t.Fatalf("echo = %q, want %q", buf, "hello")
	}
}

// TestHTTPProxyGET forwards an absolute-form request to a local HTTP server.
func TestHTTPProxyGET(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listener: %v", err)
	}
	defer ln.Close()
	reqLines := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		reqLine, _ := r.ReadString('\n')
		reqLines <- reqLine
		for {
			h, _ := r.ReadString('\n')
			if h == "\r\n" {
				break
			}
		}
		io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	}()

	s := startTestProxy(t, "")

	c, err := net.Dial("tcp", proxyAddr(s))
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer c.Close()

	fmt.Fprintf(c, "GET http://%s/ping HTTP/1.1\r\nHost: %s\r\n\r\n", ln.Addr().String(), ln.Addr().String())
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if string(body) != "ok" {
		t.Fatalf("body = %q, want %q", body, "ok")
	}

	select {
	case reqLine := <-reqLines:
		if !strings.HasPrefix(reqLine, "GET /ping HTTP/1.1") {
			t.Fatalf("upstream request line = %q, want origin form", reqLine)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not receive the request")
	}
}

// TestHTTPProxyPOSTContentLength forwards the request body when framed by
// Content-Length (regression: the body used to be dropped).
func TestHTTPProxyPOSTContentLength(t *testing.T) {
	bodyOut := make(chan []byte, 1)
	ln := oneShotHTTPServer(t, bodyOut)
	s := startTestProxy(t, "")

	c, err := net.Dial("tcp", proxyAddr(s))
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer c.Close()

	fmt.Fprintf(c, "POST http://%s/submit HTTP/1.1\r\nHost: %s\r\nContent-Length: 5\r\n\r\nhello",
		ln.Addr().String(), ln.Addr().String())
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	select {
	case body := <-bodyOut:
		if string(body) != "hello" {
			t.Fatalf("upstream body = %q, want %q", body, "hello")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not receive the body")
	}
}

// TestHTTPProxyPOSTChunked de-chunks the body and terminates it with EOF.
func TestHTTPProxyPOSTChunked(t *testing.T) {
	bodyOut := make(chan []byte, 1)
	ln := oneShotHTTPServer(t, bodyOut)
	s := startTestProxy(t, "")

	c, err := net.Dial("tcp", proxyAddr(s))
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer c.Close()

	fmt.Fprintf(c, "POST http://%s/submit HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
		ln.Addr().String(), ln.Addr().String())
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	select {
	case body := <-bodyOut:
		if string(body) != "hello" {
			t.Fatalf("upstream body = %q, want %q", body, "hello")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not receive the body")
	}
}

// TestHTTPProxyTunnelRoute dials through the dialer (SSH tunnel path).
func TestHTTPProxyTunnelRoute(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listener: %v", err)
	}
	defer echo.Close()
	go func() {
		c, err := echo.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.Copy(c, c)
	}()

	// dialTarget set: the dialer stands in for the SSH tunnel and redirects
	// any destination to the local echo server.
	s := startTestProxy(t, echo.Addr().String())

	c, err := net.Dial("tcp", proxyAddr(s))
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer c.Close()

	// Non-private hostname: the rule engine routes it through the tunnel.
	fmt.Fprintf(c, "CONNECT tunnel.test:443 HTTP/1.1\r\nHost: tunnel.test:443\r\n\r\n")
	r := bufio.NewReader(c)
	expectStatus(t, r, "200")
	if _, err := r.ReadSlice('\n'); err != nil {
		t.Fatalf("read CONNECT end: %v", err)
	}

	c.Write([]byte("via-tunnel"))
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 10)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != "via-tunnel" {
		t.Fatalf("echo = %q, want %q", buf, "via-tunnel")
	}
}

// TestHTTPProxyOriginFormRejected returns 400 for non-absolute, non-CONNECT requests.
func TestHTTPProxyOriginFormRejected(t *testing.T) {
	s := startTestProxy(t, "")

	c, err := net.Dial("tcp", proxyAddr(s))
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer c.Close()

	c.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	expectStatus(t, bufio.NewReader(c), "400")
}

// TestHTTPProxyNonHTTPSchemeRejected returns 400 for absolute-form non-http URLs.
func TestHTTPProxyNonHTTPSchemeRejected(t *testing.T) {
	s := startTestProxy(t, "")

	c, err := net.Dial("tcp", proxyAddr(s))
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer c.Close()

	c.Write([]byte("GET ftp://example.com/file HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	expectStatus(t, bufio.NewReader(c), "400")
}

// TestHTTPProxyTransferEncodingRejected returns 400 for Transfer-Encoding
// values other than plain chunked (RFC 9112 6.3: we can only re-frame chunked).
func TestHTTPProxyTransferEncodingRejected(t *testing.T) {
	s := startTestProxy(t, "")

	for _, te := range []string{"gzip", "gzip, chunked", "chunked, gzip"} {
		c, err := net.Dial("tcp", proxyAddr(s))
		if err != nil {
			t.Fatalf("dial proxy: %v", err)
		}
		fmt.Fprintf(c, "POST http://127.0.0.1:9/submit HTTP/1.1\r\nHost: 127.0.0.1:9\r\nTransfer-Encoding: %s\r\n\r\n", te)
		expectStatus(t, bufio.NewReader(c), "400")
		c.Close()
	}
}

// TestHTTPProxyDialTimeout returns 504 when the upstream dial times out.
func TestHTTPProxyDialTimeout(t *testing.T) {
	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatalf("NewRuleEngine: %v", err)
	}
	s, err := NewHTTPProxyServer("127.0.0.1:0", rules, testDialer{Err: &net.DNSError{IsTimeout: true}}, FamilyBoth)
	if err != nil {
		t.Fatalf("NewHTTPProxyServer: %v", err)
	}
	s.Start()
	t.Cleanup(func() { s.Shutdown(context.Background()) })

	c, err := net.Dial("tcp", proxyAddr(s))
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer c.Close()

	// Non-private hostname: routed through the tunnel, so the failing dialer is used.
	fmt.Fprintf(c, "CONNECT tunnel.test:443 HTTP/1.1\r\nHost: tunnel.test:443\r\n\r\n")
	expectStatus(t, bufio.NewReader(c), "504")
}

// TestHTTPProxyDialFailure returns 502 when the target refuses the connection.
func TestHTTPProxyDialFailure(t *testing.T) {
	// Find a closed port: listen, note the port, close.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listener: %v", err)
	}
	closedAddr := ln.Addr().String()
	ln.Close()

	s := startTestProxy(t, "")

	c, err := net.Dial("tcp", proxyAddr(s))
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer c.Close()

	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", closedAddr, closedAddr)
	expectStatus(t, bufio.NewReader(c), "502")
}
