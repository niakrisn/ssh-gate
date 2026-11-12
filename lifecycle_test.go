package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestClientCloseWaitsForHandler(t *testing.T) {
	r := newClientRegistry()
	c, peer := net.Pipe()
	defer peer.Close()
	owned, ok := r.add(c)
	if !ok {
		t.Fatal("registration failed")
	}
	r.stop()
	r.forceClose()
	if !errors.Is(owned.ctx.Err(), context.Canceled) {
		t.Fatal("client work not canceled")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := r.drain(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("socket close retired running handler: %v", err)
	}
	owned.finish()
	owned.finish()
	if err := r.drain(ctx); err != nil {
		t.Fatalf("completed drain must win over canceled ctx: %v", err)
	}
}

type pausedAcceptListener struct {
	net.Listener
	accepted chan struct{}
	release  chan struct{}
}

func (l pausedAcceptListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		close(l.accepted)
		<-l.release
	}
	return c, err
}

func TestShutdownAcceptRace(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	pause := pausedAcceptListener{ln, make(chan struct{}), make(chan struct{})}
	limit := newConnLimiter(1)
	r := newClientRegistry()
	l := &clientListener{Listener: limitConns(pause, limit), clients: r}
	done := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if c != nil {
			c.(*clientConn).finish()
		}
		done <- err
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	<-pause.accepted
	r.stop()
	ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := r.drain(ctx); !errors.Is(err, context.DeadlineExceeded) {
		close(pause.release)
		<-done
		t.Fatalf("drain ignored a socket still inside Accept: %v", err)
	}
	close(pause.release)
	if err := <-done; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("late admission: %v", err)
	}
	c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("late socket not closed: %v", err)
	}
	if len(limit.slots) != 0 {
		t.Fatal("late admission retained limiter slot")
	}
	if err := r.drain(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestShutdownIdempotent(t *testing.T) {
	s, err := NewSOCKS5Server("127.0.0.1:0", &Opener{})
	if err != nil {
		t.Fatal(err)
	}
	s.Start()
	c, err := net.Dial("tcp", s.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	c.Write([]byte{5, 1, 0})
	if _, err := io.ReadFull(c, make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.Shutdown(ctx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("shutdown: %v", err)
			}
		}()
	}
	wg.Wait()
	cleanup, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := s.Drain(cleanup); err != nil {
		t.Fatal(err)
	}
	s.clients.mu.Lock()
	n := len(s.clients.clients)
	s.clients.mu.Unlock()
	if n != 0 {
		t.Fatalf("retained clients: %d", n)
	}
}

func TestShutdownCountsDial(t *testing.T) {
	d, live, pending := pendingSSH(t)
	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatal(err)
	}
	defer rules.Stop()
	s, err := NewSOCKS5Server("127.0.0.1:0", newTestOpener(rules, d))
	if err != nil {
		t.Fatal(err)
	}
	s.Start()
	t.Cleanup(func() { s.ForceClose(); s.Shutdown(context.Background()) })
	c, err := net.Dial("tcp", s.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	c.Write([]byte{5, 1, 0})
	if _, err := io.ReadFull(c, make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	c.Write([]byte{5, 1, 0, 1, 203, 0, 113, 1, 0, 80})
	var n ssh.NewChannel
	select {
	case n = <-pending:
	case <-time.After(time.Second):
		t.Fatal("missing pending dial")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := s.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("dial omitted from drain: %v", err)
	}
	cleanup, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := s.Drain(cleanup); err != nil {
		t.Fatalf("dial wait not canceled: %v", err)
	}
	ch, reqs, err := n.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer ch.Close()
	select {
	case <-reqs:
	case <-time.After(time.Second):
		t.Fatal("late dial survived shutdown")
	}
	checkSSHRelay(t, live)
}

func TestShutdownCountsHandshake(t *testing.T) {
	s, err := NewSOCKS5Server("127.0.0.1:0", &Opener{})
	if err != nil {
		t.Fatal(err)
	}
	s.handshakeTimeout = time.Hour
	limit := newConnLimiter(1)
	s.SetConnLimit(limit)
	s.Start()
	c, err := net.Dial("tcp", s.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		s.Shutdown(ctx)
	})
	c.SetDeadline(time.Now().Add(time.Second))
	c.Write([]byte{5, 1, 0})
	if _, err := io.ReadFull(c, make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := s.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("handshake omitted from drain: %v", err)
	}
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("client still open")
	} else if n, ok := err.(net.Error); ok && n.Timeout() {
		t.Fatal("shutdown left handshake socket open")
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	if err := s.Shutdown(ctx2); err != nil {
		t.Fatal(err)
	}
	if n := len(limit.slots); n != 0 {
		t.Fatalf("retained limiter slots: %d", n)
	}
}

func TestHTTPShutdownClosesClients(t *testing.T) {
	for _, phase := range []string{"headers", "http", "connect"} {
		t.Run(phase, func(t *testing.T) {
			closed := make(chan error, 1)
			addr := "127.0.0.1:9"
			if phase != "headers" {
				addr, _ = rawHTTPOrigin(t, func(c net.Conn) {
					if phase == "http" {
						if _, err := http.ReadRequest(bufio.NewReader(c)); err != nil {
							closed <- err
							return
						}
						io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n")
						c.Write(make([]byte, 8192))
					}
					_, err := io.Copy(io.Discard, c)
					closed <- err
				})
			}
			rules, err := NewRuleEngine("")
			if err != nil {
				t.Fatal(err)
			}
			defer rules.Stop()
			s, err := NewHTTPProxyServer("127.0.0.1:0", newTestOpener(rules, testDialer{}))
			if err != nil {
				t.Fatal(err)
			}
			limit := newConnLimiter(1)
			s.SetConnLimit(limit)
			accepted := make(chan struct{})
			prev := s.srv.ConnState
			s.srv.ConnState = func(c net.Conn, state http.ConnState) {
				if prev != nil {
					prev(c, state)
				}
				if state == http.StateNew {
					close(accepted)
				}
			}
			s.Start()
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				s.Shutdown(ctx)
			})
			c, br := proxyHTTPConn(t, s)
			<-accepted
			switch phase {
			case "headers":
				io.WriteString(c, "GET ")
			case "http":
				fmt.Fprintf(c, "GET http://%s/ HTTP/1.1\r\nHost: %s\r\n\r\n", addr, addr)
				r, err := http.ReadResponse(br, nil)
				if err != nil || r.StatusCode != 200 {
					t.Fatalf("response=%v err=%v", r, err)
				}
			case "connect":
				fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", addr, addr)
				r, err := http.ReadResponse(br, nil)
				if err != nil || r.StatusCode != 200 {
					t.Fatalf("response=%v err=%v", r, err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			defer cancel()
			if err := s.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("active client omitted: %v", err)
			}
			c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			if _, err := io.Copy(io.Discard, br); err != nil {
				t.Fatalf("client not closed by forced shutdown: %v", err)
			}
			if phase != "headers" {
				select {
				case err := <-closed:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("upstream survived forced shutdown")
				}
			}
			cleanup, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			if err := s.Shutdown(cleanup); err != nil {
				t.Fatal(err)
			}
			if len(limit.slots) != 0 {
				t.Fatal("client slot retained")
			}
		})
	}
}

func TestShutdownStopsAllListenersBeforeDrain(t *testing.T) {
	addr, _ := rawHTTPOrigin(t, func(c net.Conn) { io.Copy(io.Discard, c) })
	first := startTestProxy(t, "")
	second, err := NewSOCKS5Server("127.0.0.1:0", &Opener{})
	if err != nil {
		t.Fatal(err)
	}
	second.Start()
	defer second.Shutdown(context.Background())
	health, err := NewHealthServer("127.0.0.1:0", "", 0, testDialer{}, NewConnTracker(8, time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	health.Start()
	defer health.Shutdown(context.Background())
	c, br := proxyHTTPConn(t, first)
	defer c.Close()
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", addr, addr)
	if r, err := http.ReadResponse(br, nil); err != nil || r.StatusCode != 200 {
		t.Fatalf("connect=%v err=%v", r, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan struct{})
	draining := make(chan struct{})
	var drainOnce sync.Once
	go func() {
		shutdownServers(ctx, []server{
			{Name: "http", StopAccept: first.StopAccept, Drain: func(ctx context.Context) error { drainOnce.Do(func() { close(draining) }); return first.Drain(ctx) }, ForceClose: first.ForceClose},
			{Name: "socks", StopAccept: second.StopAccept, Drain: second.Drain, ForceClose: second.ForceClose},
			{Name: "health", StopAccept: health.StopAccept, Drain: health.Drain, ForceClose: health.ForceClose},
		}, nil, testDialer{})
		close(done)
	}()
	<-draining
	// The first relay still owns the drain; every other listener must
	// already be closed, not merely scheduled to close after that relay.
	for _, target := range []string{second.ln.Addr().String(), health.ln.Addr().String()} {
		probe, err := net.DialTimeout("tcp", target, 100*time.Millisecond)
		if err == nil {
			probe.Close()
			t.Errorf("listener %s still accepts during another listener's drain", target)
		}
	}
	c.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not finish")
	}
}

type closeGateConn struct {
	net.Conn
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *closeGateConn) Close() error {
	c.once.Do(func() { close(c.entered) })
	<-c.release
	return c.Conn.Close()
}

func TestDNSStopDoesNotWaitForTransportClose(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") }))
	defer origin.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	rules, _ := NewRuleEngine("")
	rules.dns.dohClient = &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return &closeGateConn{Conn: c, entered: entered, release: release}, nil
	}}}
	r, err := rules.dns.dohClient.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, r.Body)
	r.Body.Close()
	stopped := make(chan struct{})
	go func() { rules.Stop(); close(stopped) }()
	<-entered
	select {
	case <-stopped:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("DNS stop blocks before SSH can close the transport")
	}
	releaseOnce.Do(func() { close(release) })
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := rules.dns.waitStopped(ctx); err != nil {
		t.Fatal(err)
	}
}

type shutdownDialer struct {
	testDialer
	stopped atomic.Bool
}

func (d *shutdownDialer) stop() { d.stopped.Store(true) }

func TestShutdownPreservesInFlightPayload(t *testing.T) {
	const size = 128 << 10
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	upstreamDone := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			upstreamDone <- err
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		b, err := io.ReadAll(c)
		if err == nil && !bytes.Equal(b, bytes.Repeat([]byte("x"), size)) {
			err = fmt.Errorf("upload length=%d", len(b))
		}
		if err == nil {
			_, err = c.Write(b)
		}
		upstreamDone <- err
	}()
	rules, _ := NewRuleEngine("drain.example")
	defer rules.Stop()
	lookup, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	rules.dns.localLookup = func(ctx context.Context, _ string) ([]net.IPAddr, error) {
		close(lookup)
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	}
	d := &shutdownDialer{}
	s, err := NewSOCKS5Server("127.0.0.1:0", newTestOpener(rules, d))
	if err != nil {
		t.Fatal(err)
	}
	s.Start()
	c, err := net.Dial("tcp", s.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	c.Write([]byte{5, 1, 0})
	if _, err := io.ReadFull(c, make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	name := "drain.example"
	port := ln.Addr().(*net.TCPAddr).Port
	request := append([]byte{5, 1, 0, 3, byte(len(name))}, name...)
	c.Write(append(request, byte(port>>8), byte(port)))
	<-lookup
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- shutdownServers(ctx, []server{{Name: "socks", StopAccept: s.StopAccept, Drain: s.Drain, ForceClose: s.ForceClose}}, rules, d)
	}()
	<-s.shutCh
	if rules.dns.ctx.Err() != nil || d.stopped.Load() {
		t.Fatal("DNS or SSH stopped before accepted request drained")
	}
	releaseOnce.Do(func() { close(release) })
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil || reply[1] != 0 {
		t.Fatalf("reply=%x err=%v", reply, err)
	}
	c.Write(bytes.Repeat([]byte("x"), size))
	c.(*net.TCPConn).CloseWrite()
	b, err := io.ReadAll(c)
	if err != nil || !bytes.Equal(b, bytes.Repeat([]byte("x"), size)) {
		t.Fatalf("drained response length=%d err=%v", len(b), err)
	}
	if err := <-upstreamDone; err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if rules.dns.ctx.Err() == nil || !d.stopped.Load() {
		t.Fatal("owners remained active after drain")
	}
}
