package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func rawHTTPOrigin(t *testing.T, serve func(net.Conn)) (string, <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		serve(c)
	}()
	t.Cleanup(func() {
		ln.Close()
		select {
		case <-done:
		case <-time.After(4 * time.Second):
			t.Error("origin handler did not stop")
		}
	})
	return ln.Addr().String(), done
}

func proxyHTTPConn(t *testing.T, s *HTTPProxyServer) (net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.Dial("tcp", proxyAddr(s))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(2 * time.Second))
	return c, bufio.NewReader(c)
}

func TestHTTPExpectContinue(t *testing.T) {
	for _, chunked := range []bool{false, true} {
		t.Run(fmt.Sprintf("chunked=%v", chunked), func(t *testing.T) {
			addr, done := rawHTTPOrigin(t, func(c net.Conn) {
				r, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil {
					t.Error(err)
					return
				}
				io.WriteString(c, "HTTP/1.1 100 Continue\r\n\r\n")
				b, err := io.ReadAll(r.Body)
				if err != nil || string(b) != "hello" {
					t.Errorf("upload=%q err=%v", b, err)
					return
				}
				io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone")
			})
			s := startTestProxy(t, "")
			c, br := proxyHTTPConn(t, s)
			framing, body := "Content-Length: 5", "hello"
			if chunked {
				framing, body = "Transfer-Encoding: chunked", "5\r\nhello\r\n0\r\n\r\n"
			}
			fmt.Fprintf(c, "POST http://%s/ HTTP/1.1\r\nHost: %s\r\nExpect: 100-continue\r\n%s\r\n\r\n", addr, addr, framing)
			r, err := http.ReadResponse(br, nil)
			if err != nil || r.StatusCode != 100 {
				t.Fatalf("continue=%v err=%v", r, err)
			}
			io.WriteString(c, body)
			r, err = http.ReadResponse(br, nil)
			if err != nil || r.StatusCode != 200 {
				t.Fatalf("final=%v err=%v", r, err)
			}
			b, err := io.ReadAll(r.Body)
			r.Body.Close()
			if err != nil || string(b) != "done" {
				t.Fatalf("response=%q err=%v", b, err)
			}
			<-done
		})
	}
}

func TestHTTPEarlyFinalResponse(t *testing.T) {
	for _, code := range []int{401, 413} {
		for _, expect := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/expect=%v", code, expect), func(t *testing.T) {
				closed := make(chan error, 1)
				addr, _ := rawHTTPOrigin(t, func(c net.Conn) {
					br := bufio.NewReader(c)
					if _, err := http.ReadRequest(br); err != nil {
						closed <- err
						return
					}
					fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nContent-Length: 6\r\n\r\ndenied", code, http.StatusText(code))
					_, err := io.Copy(io.Discard, br)
					closed <- err
				})
				s := startTestProxy(t, "")
				c, br := proxyHTTPConn(t, s)
				head := ""
				if expect {
					head = "Expect: 100-continue\r\n"
				}
				fmt.Fprintf(c, "POST http://%s/ HTTP/1.1\r\nHost: %s\r\nContent-Length: 10000000\r\n%s\r\n", addr, addr, head)
				if !expect {
					io.WriteString(c, "partial")
				}
				var r *http.Response
				for {
					var err error
					r, err = http.ReadResponse(br, nil)
					if err != nil {
						t.Fatal(err)
					}
					if r.StatusCode != 100 {
						break
					}
				}
				if r.StatusCode != code {
					t.Fatalf("status=%d", r.StatusCode)
				}
				b, err := io.ReadAll(r.Body)
				r.Body.Close()
				if err != nil || string(b) != "denied" {
					t.Fatalf("response=%q err=%v", b, err)
				}
				select {
				case err := <-closed:
					if err != nil {
						t.Fatalf("upstream did not close promptly: %v", err)
					}
				case <-time.After(time.Second):
					t.Fatal("unfinished upload retained upstream")
				}
			})
		}
	}
}

func TestHTTPHopHeaders(t *testing.T) {
	seen := make(chan *http.Request, 1)
	addr, _ := rawHTTPOrigin(t, func(c net.Conn) {
		r, err := http.ReadRequest(bufio.NewReader(c))
		if err != nil {
			t.Error(err)
			return
		}
		seen <- r
		io.WriteString(c, "HTTP/1.1 200 OK\r\nConnection: X-Secret\r\nX-Secret: hidden\r\nContent-Length: 2\r\n\r\nok")
	})
	s := startTestProxy(t, "")
	c, br := proxyHTTPConn(t, s)
	fmt.Fprintf(c, "GET http://%s/path?a=1%%202 HTTP/1.1\r\nHost: %s\r\nConnection: X-Secret\r\nX-Secret: hidden\r\nProxy-Authorization: secret\r\nX-Forwarded-For: forged\r\nForwarded: forged\r\n\r\n", addr, addr)
	r, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	q := <-seen
	for _, k := range []string{"X-Secret", "Proxy-Authorization", "X-Forwarded-For", "Forwarded"} {
		if q.Header.Get(k) != "" {
			t.Errorf("forwarded %s", k)
		}
	}
	if q.URL.RequestURI() != "/path?a=1%202" || q.Host != addr {
		t.Fatalf("target changed: %s %s", q.Host, q.URL)
	}
	if r.Header.Get("X-Secret") != "" {
		t.Error("response hop header leaked")
	}
}

func TestHTTPUpgradeRejected(t *testing.T) {
	addr, _ := rawHTTPOrigin(t, func(c net.Conn) {
		if _, err := http.ReadRequest(bufio.NewReader(c)); err == nil {
			io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
		}
	})
	s := startTestProxy(t, "")
	c, br := proxyHTTPConn(t, s)
	fmt.Fprintf(c, "GET http://%s/ HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n", addr, addr)
	r, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != 400 {
		t.Fatalf("upgrade=%d", r.StatusCode)
	}
}

func TestHTTPInterimResponses(t *testing.T) {
	addr, _ := rawHTTPOrigin(t, func(c net.Conn) {
		if _, err := http.ReadRequest(bufio.NewReader(c)); err != nil {
			t.Error(err)
			return
		}
		io.WriteString(c, "HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\nHTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})
	s := startTestProxy(t, "")
	c, br := proxyHTTPConn(t, s)
	fmt.Fprintf(c, "GET http://%s/ HTTP/1.1\r\nHost: %s\r\n\r\n", addr, addr)
	for _, code := range []int{103, 100, 200} {
		r, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		if r.StatusCode != code {
			t.Fatalf("status=%d want %d", r.StatusCode, code)
		}
		if code != 103 && r.Header.Get("Link") != "" {
			t.Fatal("interim headers merged into later response")
		}
		b, err := io.ReadAll(r.Body)
		r.Body.Close()
		if err != nil || (code == 200 && strings.TrimSpace(string(b)) != "ok") {
			t.Fatalf("body=%q err=%v", b, err)
		}
	}
}

func TestHTTPFraming(t *testing.T) {
	for _, tc := range []struct {
		method string
		code   int
	}{{"HEAD", 200}, {"GET", 204}, {"GET", 304}} {
		t.Run(fmt.Sprintf("%s/%d", tc.method, tc.code), func(t *testing.T) {
			addr, _ := rawHTTPOrigin(t, func(c net.Conn) {
				if _, err := http.ReadRequest(bufio.NewReader(c)); err != nil {
					t.Error(err)
					return
				}
				fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nContent-Length: 10\r\n\r\n", tc.code, http.StatusText(tc.code))
			})
			c, br := proxyHTTPConn(t, startTestProxy(t, ""))
			fmt.Fprintf(c, "%s http://%s/ HTTP/1.1\r\nHost: %s\r\n\r\n", tc.method, addr, addr)
			r, err := http.ReadResponse(br, &http.Request{Method: tc.method})
			if err != nil {
				t.Fatal(err)
			}
			b, err := io.ReadAll(r.Body)
			r.Body.Close()
			if err != nil || len(b) != 0 || r.StatusCode != tc.code {
				t.Fatalf("status=%d body=%q err=%v", r.StatusCode, b, err)
			}
		})
	}
	t.Run("chunked trailers and TE over CL", func(t *testing.T) {
		seen := make(chan error, 1)
		addr, _ := rawHTTPOrigin(t, func(c net.Conn) {
			r, err := http.ReadRequest(bufio.NewReader(c))
			if err != nil {
				seen <- err
				return
			}
			b, err := io.ReadAll(r.Body)
			if err == nil && (string(b) != "hello" || r.Trailer.Get("X-Checksum") != "value" || r.ContentLength != -1 || r.Header.Get("Content-Length") != "") {
				err = fmt.Errorf("bad framing: body=%q length=%d trailer=%v", b, r.ContentLength, r.Trailer)
			}
			seen <- err
			io.WriteString(c, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Final\r\nContent-Encoding: gzip\r\n\r\n3\r\nabc\r\n0\r\nX-Final: complete\r\n\r\n")
		})
		c, br := proxyHTTPConn(t, startTestProxy(t, ""))
		fmt.Fprintf(c, "POST http://%s/ HTTP/1.1\r\nHost: %s\r\nContent-Length: 999\r\nTransfer-Encoding: chunked\r\nTrailer: X-Checksum\r\n\r\n5\r\nhello\r\n0\r\nX-Checksum: value\r\n\r\n", addr, addr)
		r, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(r.Body)
		r.Body.Close()
		if err != nil || string(b) != "abc" || r.Trailer.Get("X-Final") != "complete" || r.Header.Get("Content-Encoding") != "gzip" {
			t.Fatalf("body=%q headers=%v trailers=%v err=%v", b, r.Header, r.Trailer, err)
		}
		if err := <-seen; err != nil {
			t.Fatal(err)
		}
	})
	t.Run("conflicting content lengths", func(t *testing.T) {
		c, br := proxyHTTPConn(t, startTestProxy(t, ""))
		io.WriteString(c, "POST http://127.0.0.1:9/ HTTP/1.1\r\nHost: 127.0.0.1:9\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n")
		r, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode != 400 {
			t.Fatalf("status=%d", r.StatusCode)
		}
	})
	t.Run("truncated response", func(t *testing.T) {
		addr, _ := rawHTTPOrigin(t, func(c net.Conn) {
			if _, err := http.ReadRequest(bufio.NewReader(c)); err != nil {
				t.Error(err)
				return
			}
			io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 10000\r\n\r\n"+strings.Repeat("a", 6000))
		})
		c, br := proxyHTTPConn(t, startTestProxy(t, ""))
		fmt.Fprintf(c, "GET http://%s/ HTTP/1.1\r\nHost: %s\r\n\r\n", addr, addr)
		r, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(r.Body)
		r.Body.Close()
		if !errors.Is(err, io.ErrUnexpectedEOF) || len(b) == 0 || !bytes.Equal(b, bytes.Repeat([]byte("a"), len(b))) {
			t.Fatalf("partial response len=%d err=%v", len(b), err)
		}
	})
}
