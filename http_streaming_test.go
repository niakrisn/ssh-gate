package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func writeChunks(w io.Writer, size int64, sent *atomic.Int64) error {
	buf := bytes.Repeat([]byte("z"), 32<<10)
	for size > 0 {
		n := int(min(size, int64(len(buf))))
		if _, err := fmt.Fprintf(w, "%x\r\n", n); err != nil {
			return err
		}
		written, err := w.Write(buf[:n])
		if sent != nil {
			sent.Add(int64(written))
		}
		if err != nil {
			return err
		}
		if _, err := io.WriteString(w, "\r\n"); err != nil {
			return err
		}
		size -= int64(n)
	}
	_, err := io.WriteString(w, "0\r\n\r\n")
	return err
}

func TestHTTPChunkedStreamsBeforeEOF(t *testing.T) {
	first := make(chan error, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 5)
		_, err := io.ReadFull(r.Body, b)
		if err == nil && string(b) != "hello" {
			err = fmt.Errorf("first chunk=%q", b)
		}
		first <- err
		io.Copy(io.Discard, r.Body)
		io.WriteString(w, "ok")
	}))
	defer origin.Close()
	s := startTestProxy(t, "")
	c, br := proxyHTTPConn(t, s)
	defer c.Close()
	fmt.Fprintf(c, "POST %s/ HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n", origin.URL, strings.TrimPrefix(origin.URL, "http://"))
	select {
	case err := <-first:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("origin received no chunk before client EOF")
	}
	io.WriteString(c, "0\r\n\r\n")
	r, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatalf("status=%d", r.StatusCode)
	}
}

func TestHTTPChunkedLargeUpload(t *testing.T) {
	const size = 64 << 20
	type receipt struct {
		size int64
		sum  []byte
		err  error
	}
	seen := make(chan receipt, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := sha256.New()
		n, err := io.CopyBuffer(h, r.Body, make([]byte, 32<<10))
		seen <- receipt{n, h.Sum(nil), err}
		io.WriteString(w, "ok")
	}))
	defer origin.Close()
	c, br := proxyHTTPConn(t, startTestProxy(t, ""))
	defer c.Close()
	c.SetDeadline(time.Now().Add(20 * time.Second))
	fmt.Fprintf(c, "POST %s/ HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\n\r\n", origin.URL, strings.TrimPrefix(origin.URL, "http://"))
	written := make(chan error, 1)
	go func() { written <- writeChunks(c, size, nil) }()
	r, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatalf("large upload rejected: %d", r.StatusCode)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	got := <-seen
	h := sha256.New()
	buf := bytes.Repeat([]byte("z"), 32<<10)
	for range size / len(buf) {
		h.Write(buf)
	}
	if got.err != nil || got.size != size || !bytes.Equal(got.sum, h.Sum(nil)) {
		t.Fatalf("upload size=%d hash=%x err=%v", got.size, got.sum, got.err)
	}
}

func TestHTTPChunkedBackpressure(t *testing.T) {
	first, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		io.ReadFull(r.Body, make([]byte, 32<<10))
		close(first)
		<-release
		io.Copy(io.Discard, r.Body)
	}))
	defer origin.Close()
	defer close(release)
	s := startTestProxy(t, "")
	c, _ := proxyHTTPConn(t, s)
	defer c.Close()
	c.(*net.TCPConn).SetWriteBuffer(32 << 10)
	fmt.Fprintf(c, "POST %s/ HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\n\r\n", origin.URL, strings.TrimPrefix(origin.URL, "http://"))
	c.SetWriteDeadline(time.Now().Add(300 * time.Millisecond))
	var sent atomic.Int64
	written := make(chan error, 1)
	go func() { written <- writeChunks(c, 64<<20, &sent) }()
	select {
	case <-first:
	case <-time.After(time.Second):
		t.Fatal("origin never saw first bytes")
	}
	select {
	case err := <-written:
		if err == nil {
			t.Fatal("client sent whole upload despite blocked origin")
		}
	case <-time.After(time.Second):
		t.Fatal("write deadline did not stop blocked client")
	}
	if n := sent.Load(); n >= 16<<20 {
		t.Fatalf("proxy absorbed %d bytes behind blocked origin", n)
	}
}

func TestHTTPUploadAbortReleasesResources(t *testing.T) {
	for _, route := range []string{"direct", "ssh"} {
		t.Run(route, func(t *testing.T) {
			first, closed := make(chan struct{}), make(chan struct{})
			consume := func(r *http.Request) {
				if _, err := io.ReadFull(r.Body, make([]byte, 5)); err != nil {
					t.Error(err)
					return
				}
				close(first)
				io.Copy(io.Discard, r.Body)
			}
			target := "http://203.0.113.1/"
			var d dialer = testDialer{}
			if route == "direct" {
				origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { defer close(closed); consume(r) }))
				defer origin.Close()
				target = origin.URL + "/"
			} else {
				addr, signer := startTestSSHServerWithChannelHandler(t, "", true, func(n ssh.NewChannel) error {
					c, reqs, err := n.Accept()
					if err != nil {
						return err
					}
					go ssh.DiscardRequests(reqs)
					go func() {
						defer close(closed)
						defer c.Close()
						r, err := http.ReadRequest(bufio.NewReader(c))
						if err != nil {
							t.Error(err)
							return
						}
						consume(r)
					}()
					return nil
				})
				d = &sshDialer{client: connectTestSSHClient(t, addr, signer)}
			}
			rules, _ := NewRuleEngine("")
			defer rules.Stop()
			s, err := NewHTTPProxyServer("127.0.0.1:0", newTestOpener(rules, d))
			if err != nil {
				t.Fatal(err)
			}
			limit := newConnLimiter(1)
			s.SetConnLimit(limit)
			s.Start()
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				s.Shutdown(ctx)
			})
			c, _ := proxyHTTPConn(t, s)
			fmt.Fprintf(c, "POST %s HTTP/1.1\r\nHost: ignored\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n", target)
			select {
			case <-first:
			case <-time.After(time.Second):
				t.Fatal("upload not started")
			}
			c.(*net.TCPConn).SetLinger(0)
			c.Close()
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("aborted upload retained upstream")
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := s.Shutdown(ctx); err != nil {
				t.Fatal(err)
			}
			if len(limit.slots) != 0 {
				t.Fatal("aborted upload retained client slot")
			}
		})
	}
}
