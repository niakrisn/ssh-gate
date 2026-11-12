package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestConnectCopyErrorClosesBoth(t *testing.T) {
	_, access, flush := captureLogs(t)
	channelClosed := make(chan struct{})
	addr, signer := startTestSSHServerWithChannelHandler(t, "", true, func(open ssh.NewChannel) error {
		_, requests, err := open.Accept()
		if err == nil {
			go func() {
				ssh.DiscardRequests(requests)
				close(channelClosed)
			}()
		}
		return err
	})
	client := connectTestSSHClient(t, addr, signer)
	d := &sshDialer{client: client}
	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewHTTPProxyServer("127.0.0.1:0", newTestOpener(rules, d))
	if err != nil {
		t.Fatal(err)
	}
	limit := newConnLimiter(1)
	s.SetConnLimit(limit)
	s.Start()
	t.Cleanup(func() {
		d.stop()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		s.Shutdown(ctx)
	})
	c, err := net.Dial("tcp", proxyAddr(s))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(2 * time.Second))
	io.WriteString(c, "CONNECT 203.0.113.1:443 HTTP/1.1\r\nHost: 203.0.113.1:443\r\n\r\n")
	r := bufio.NewReader(c)
	expectStatus(t, r, "200")
	if _, err := r.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	if err := c.(*net.TCPConn).SetLinger(0); err != nil {
		t.Fatal(err)
	}
	c.Close()
	select {
	case <-channelClosed:
	case <-time.After(time.Second):
		t.Fatal("client reset left the SSH channel open")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("relay did not finish: %v", err)
	}
	if got := len(limit.slots); got != 0 {
		t.Fatalf("connection slots retained: %d", got)
	}
	flush()
	if !strings.Contains(access.String(), `"result":"relay_error"`) {
		t.Fatalf("reset was not logged as a relay error: %s", access.String())
	}
}

// connectFaultConn controls failures at the socket boundary while reads
// still block on a real pipe until the relay closes it.
type connectFaultConn struct {
	net.Conn
	writeErr      error
	closeWriteErr error
}

func (c *connectFaultConn) Write(p []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return c.Conn.Write(p)
}

func (c *connectFaultConn) CloseWrite() error { return c.closeWriteErr }

type connectConnDialer struct{ net.Conn }

func (d connectConnDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return d.Conn, nil
}
func (connectConnDialer) Connected() bool { return true }
func (connectConnDialer) stop()           {}

func TestConnectReplyWriteFailure(t *testing.T) {
	testConnectSocketFailure(t, "reply")
}

func TestConnectUpstreamWriteFailure(t *testing.T) {
	testConnectSocketFailure(t, "upstream")
}

func TestConnectHalfCloseFailure(t *testing.T) {
	testConnectSocketFailure(t, "half-close")
}

func testConnectSocketFailure(t *testing.T, failure string) {
	t.Helper()
	_, access, flush := captureLogs(t)
	client, peer := net.Pipe()
	upstream, target := net.Pipe()
	done := make(chan struct{})
	t.Cleanup(func() {
		client.Close()
		peer.Close()
		upstream.Close()
		target.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("relay did not exit after cleanup")
		}
	})
	fault := errors.New("test socket failure")
	clientConn := &connectFaultConn{Conn: client}
	upstreamConn := &connectFaultConn{Conn: upstream}
	var src io.Reader = strings.NewReader("")
	switch failure {
	case "reply":
		clientConn.writeErr = fault
	case "upstream":
		upstreamConn.writeErr = fault
		src = strings.NewReader("request")
	case "half-close":
		upstreamConn.closeWriteErr = fault
	}
	if failure != "reply" {
		go io.Copy(io.Discard, peer)
	}
	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatal(err)
	}
	s := &HTTPProxyServer{opener: newTestOpener(rules, connectConnDialer{upstreamConn})}
	go func() {
		s.handleConnect(clientConn, src, &http.Request{URL: &url.URL{Host: "203.0.113.1:443"}})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("%s failure left relay waiting on the other direction", failure)
	}
	target.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := target.Write([]byte("late data")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("upstream was not closed: %v", err)
	}
	flush()
	if !strings.Contains(access.String(), `"result":"relay_error"`) {
		t.Fatalf("socket error missing from access log: %s", access.String())
	}
}

func TestConnectHalfClosePreservesResponse(t *testing.T) {
	for _, first := range []string{"client", "upstream"} {
		t.Run(first, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			payload := strings.Repeat("response", 16384)
			result := make(chan error, 1)
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					result <- err
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				if first == "upstream" {
					_, err = io.WriteString(conn, payload)
					if err == nil {
						err = conn.(*net.TCPConn).CloseWrite()
					}
				}
				body, readErr := io.ReadAll(conn)
				if err == nil {
					err = readErr
				}
				if err == nil && string(body) != "request" {
					err = errors.New("request truncated")
				}
				if err == nil && first == "client" {
					_, err = io.WriteString(conn, payload)
				}
				result <- err
			}()
			s := startTestProxy(t, "")
			conn, err := net.Dial("tcp", proxyAddr(s))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			io.WriteString(conn, "CONNECT "+ln.Addr().String()+" HTTP/1.1\r\nHost: "+ln.Addr().String()+"\r\n\r\n")
			reader := bufio.NewReader(conn)
			expectStatus(t, reader, "200")
			reader.ReadString('\n')
			if first == "client" {
				io.WriteString(conn, "request")
				conn.(*net.TCPConn).CloseWrite()
			}
			body, err := io.ReadAll(reader)
			if err != nil || string(body) != payload {
				t.Fatalf("response truncated: bytes=%d err=%v", len(body), err)
			}
			if first == "upstream" {
				io.WriteString(conn, "request")
				conn.(*net.TCPConn).CloseWrite()
			}
			if err := <-result; err != nil {
				t.Fatal(err)
			}
		})
	}
}
