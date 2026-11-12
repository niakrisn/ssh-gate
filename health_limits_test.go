package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func healthForLimits(t *testing.T) *HealthServer {
	t.Helper()
	h, err := NewHealthServer("127.0.0.1:0", "", 0, testDialer{}, NewConnTracker(8, time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	// Shorten configured deadlines without supplying a missing production bound.
	for _, d := range []*time.Duration{&h.srv.ReadHeaderTimeout, &h.srv.ReadTimeout, &h.srv.WriteTimeout, &h.srv.IdleTimeout} {
		if *d > 0 {
			*d = 80 * time.Millisecond
		}
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = h.Shutdown(ctx)
	})
	return h
}

func healthConn(t *testing.T, h *HealthServer) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", h.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(time.Second))
	return c
}

func healthSlotReleased(t *testing.T, h *HealthServer) {
	t.Helper()
	l, ok := h.ln.(*limitListener)
	if !ok {
		t.Fatal("health listener has no connection limit")
	}
	deadline := time.Now().Add(time.Second)
	for len(l.limit.slots) != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("health slots still held: %d", len(l.limit.slots))
		}
		time.Sleep(time.Millisecond)
	}
}

func TestHealthSlowHeadersClosed(t *testing.T) {
	h := healthForLimits(t)
	h.Start()
	c := healthConn(t, h)
	io.WriteString(c, "GET /healthz HTTP/1.1\r\nHost:")
	_, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("server did not close slow headers: %v", err)
	}
	healthSlotReleased(t, h)
}

func TestHealthSlowBodyClosed(t *testing.T) {
	h := healthForLimits(t)
	h.Start()
	c := healthConn(t, h)
	io.WriteString(c, "GET /healthz HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\n\r\nx")
	_, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("server did not close incomplete body: %v", err)
	}
	healthSlotReleased(t, h)
}

func TestHealthIdleKeepAliveClosed(t *testing.T) {
	h := healthForLimits(t)
	h.Start()
	c := healthConn(t, h)
	io.WriteString(c, "GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
	r := bufio.NewReader(c)
	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || string(body) != "ok" || resp.Close {
		t.Fatalf("keep-alive response: %q, %v, close=%v", body, err, resp.Close)
	}
	if _, err := r.ReadByte(); err != io.EOF {
		t.Fatalf("idle socket not closed: %v", err)
	}
	healthSlotReleased(t, h)
}

type healthPipeListener struct {
	net.Listener
	conn      net.Conn
	once      sync.Once
	closeOnce sync.Once
	done      chan struct{}
}

func (l *healthPipeListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() { c = l.conn })
	if c != nil {
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}
func (l *healthPipeListener) Close() error {
	l.closeOnce.Do(func() { close(l.done) })
	return nil
}

func TestHealthWriteDeadline(t *testing.T) {
	h := healthForLimits(t)
	original := h.ln
	server, client := net.Pipe()
	defer client.Close()
	_ = original.Close()
	l := &healthPipeListener{Listener: original, conn: server, done: make(chan struct{})}
	h.ln = limitConns(l, newConnLimiter(1))
	closed := make(chan struct{})
	h.srv.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateClosed {
			close(closed)
		}
	}
	h.Start()
	_ = client.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := io.WriteString(client, "GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	// A pipe has no write buffer. Never read the response: the server write must time out.
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("blocked response write did not finish")
	}
	healthSlotReleased(t, h)
}

func TestHealthHeaderLimit(t *testing.T) {
	h := healthForLimits(t)
	h.Start()
	c := healthConn(t, h)
	io.WriteString(c, "GET /healthz HTTP/1.1\r\nHost: localhost\r\nX-Large: "+strings.Repeat("x", 80<<10)+"\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestHealthConnectionLimitIndependent(t *testing.T) {
	h := healthForLimits(t)
	h.srv.ReadHeaderTimeout = 2 * time.Second
	h.Start()
	proxyLimit := newConnLimiter(1)
	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatal(err)
	}
	defer rules.Stop()
	p, err := NewHTTPProxyServer("127.0.0.1:0", newTestOpener(rules, testDialer{}))
	if err != nil {
		t.Fatal(err)
	}
	p.SetConnLimit(proxyLimit)
	p.Start()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = p.Shutdown(ctx)
	})
	clients := make([]net.Conn, 0, 128)
	for i := 0; i < 128; i++ {
		c := healthConn(t, h)
		clients = append(clients, c)
		io.WriteString(c, "G")
	}
	excess := healthConn(t, h)
	_ = excess.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := excess.Read(make([]byte, 1)); err == nil {
		t.Fatal("excess health client accepted")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("excess health client was queued")
	}
	pc, err := net.Dial("tcp", p.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = pc.SetDeadline(time.Now().Add(time.Second))
	io.WriteString(pc, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(pc), nil)
	if err != nil {
		t.Fatalf("health saturation blocked proxy: %v", err)
	}
	resp.Body.Close()
	pc.Close()
	for _, c := range clients {
		c.Close()
	}
	healthSlotReleased(t, h)
	// Hold a real client in the proxy's only admission slot.
	held, err := net.Dial("tcp", p.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	io.WriteString(held, "G")
	deadline := time.Now().Add(time.Second)
	for len(proxyLimit.slots) != 1 {
		if time.Now().After(deadline) {
			t.Fatal("proxy client not admitted")
		}
		time.Sleep(time.Millisecond)
	}
	refused, err := net.Dial("tcp", p.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer refused.Close()
	_ = refused.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := refused.Read(make([]byte, 1)); err == nil {
		t.Fatal("excess proxy client admitted")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("excess proxy client queued")
	}

	hc := healthConn(t, h)
	fmt.Fprint(hc, "GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
	resp, err = http.ReadResponse(bufio.NewReader(hc), nil)
	if err != nil {
		t.Fatalf("proxy saturation blocked health: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.StatusCode != 200 || string(body) != "ok" {
		t.Fatalf("health response: %q %v", body, err)
	}
}
