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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// requestTimeout bounds a stalled client in absolute-form mode (request body
// upload and response download). CONNECT tunnels stay unbounded on purpose.
const requestTimeout = 5 * time.Minute

// maxReframedBody bounds the buffer for bodies that must be re-framed with
// Content-Length (chunked or close-delimited): forwarding them requires
// reading the whole body into memory first, so the limit caps the memory a
// single request can make the proxy hold. Larger bodies are rejected with
// 413 rather than buffered unboundedly.
const maxReframedBody = 32 << 20

// HTTPProxyServer is a minimal HTTP forward proxy: CONNECT tunneling plus
// one absolute-form request (GET/POST/...) per connection.
type HTTPProxyServer struct {
	ln        net.Listener
	shutCh    chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup // in-flight handleConn goroutines
	opener    *Opener
}

func NewHTTPProxyServer(listen string, opener *Opener) (*HTTPProxyServer, error) {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}
	return &HTTPProxyServer{
		// keepalive on accepted sockets bounds the lifetime of a
		// half-dead CONNECT relay (see keepAliveListener); the resilient
		// wrapper keeps the accept loop alive through transient errors,
		// so an error here only ever means shutdown.
		ln:     &resilientListener{Listener: keepAliveListener{Listener: ln}},
		shutCh: make(chan struct{}),
		opener: opener,
	}, nil
}

func (s *HTTPProxyServer) Start() {
	log.Info().Str("listen", s.ln.Addr().String()).Msg("HTTP proxy starting")

	go func() {
		for {
			conn, err := s.ln.Accept()
			if err != nil {
				select {
				case <-s.shutCh:
					return
				default:
					log.Error().Err(err).Msg("HTTP proxy accept failed")
					return
				}
			}
			s.wg.Add(1)
			go s.handleConn(conn)
		}
	}()
}

// Shutdown stops accepting, then waits (bounded by ctx) for in-flight
// connections to finish proxying. The listener close runs once; the drain
// wait runs on every call, so a Shutdown that timed out can be retried to
// confirm the remaining relays have finished (nil) or wait again (ctx.Err()).
// Stuck relays left behind at timeout are killed when the SSH dialer stops.
func (s *HTTPProxyServer) Shutdown(ctx context.Context) error {
	var err error
	s.closeOnce.Do(func() {
		close(s.shutCh)
		err = s.ln.Close()
	})
	if err != nil {
		return err
	}
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		// With the shared drain deadline already spent on an earlier
		// server, a server drained at the same instant must report
		// success, not a spurious timeout.
		select {
		case <-done:
			return nil
		default:
			return ctx.Err()
		}
	}
}

func (s *HTTPProxyServer) handleConn(client net.Conn) {
	defer s.wg.Done()
	defer client.Close()

	// One reader for the whole connection: ReadRequest buffers a whole
	// socket segment, so payload pipelined behind the headers (TLS
	// ClientHello right after CONNECT, GET body) lives in this buffer and
	// must be drained by the same reader the relay copies from.
	br := bufio.NewReader(client)
	_ = client.SetReadDeadline(time.Now().Add(30 * time.Second))
	req, err := http.ReadRequest(br)
	if err != nil {
		log.Warn().Str("client", client.RemoteAddr().String()).Err(err).Msg("http: bad request")
		writeHTTPErr(client, http.StatusBadRequest, "Bad Request")
		return
	}
	_ = client.SetReadDeadline(time.Time{})

	switch {
	case req.Method == http.MethodConnect:
		s.handleConnect(client, br, req)
	case req.URL != nil && req.URL.IsAbs() && req.URL.Scheme == "http":
		s.handleHTTP(client, req)
	default:
		writeHTTPErr(client, http.StatusBadRequest, "HTTP absolute-form or CONNECT requests only")
	}
}

// statusForDialErr maps an upstream dial error to a proxy status code:
// timeouts are 504 (Gateway Timeout), anything else 502 (Bad Gateway).
func statusForDialErr(err error) int {
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return http.StatusGatewayTimeout
	}
	return http.StatusBadGateway
}

// openUpstream opens the upstream connection through the shared Opener and
// wraps it for access logging. The access log is emitted on dial failure.
func (s *HTTPProxyServer) openUpstream(ctx context.Context, src, method, host string, port int) (*logConn, error) {
	log.Info().Str("proto", "http").Str("method", method).Str("src", src).Str("host", host).Int("port", port).Msg("request")

	start := time.Now()
	upstream, dst, route, reason, err := s.opener.Open(ctx, src, "http", host, port)
	dialMS := time.Since(start).Milliseconds()

	if err != nil {
		log.Info().Str("proto", "http").Str("src", src).Str("host", host).Int("port", port).
			Str("route", route.String()).Str("reason", reason).Str("dst", dst).Int64("dial_ms", dialMS).Err(err).Msg("access")
		return nil, err
	}

	return &logConn{
		Conn:   upstream,
		proto:  "http",
		t0:     time.Now(),
		src:    src,
		host:   host,
		port:   port,
		dst:    dst,
		route:  route,
		reason: reason,
		family: s.opener.family,
		dialMS: dialMS,
	}, nil
}

// handleConnect relays raw bytes between client and upstream. src is the
// buffered reader the request headers were parsed from: bytes pipelined
// behind them are already in its buffer and would be lost if the relay
// read the raw socket. Writes toward the client still go to client
// directly.
func (s *HTTPProxyServer) handleConnect(client net.Conn, src io.Reader, req *http.Request) {
	host, port, err := net.SplitHostPort(req.URL.Host)
	if err != nil {
		writeHTTPErr(client, http.StatusBadRequest, "Bad CONNECT target")
		return
	}
	portInt, _ := strconv.Atoi(port)

	lc, err := s.openUpstream(context.Background(), client.RemoteAddr().String(), "CONNECT", host, portInt)
	if err != nil {
		writeHTTPErr(client, statusForDialErr(err), "Connect failed")
		return
	}

	io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n")

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(lc, src)
		lc.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		io.Copy(client, lc)
		if cw, ok := client.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
	}()
	wg.Wait()
	lc.Close()
}

func (s *HTTPProxyServer) handleHTTP(client net.Conn, req *http.Request) {
	u := req.URL
	host := u.Hostname()
	port := 80
	if p := u.Port(); p != "" {
		port, _ = strconv.Atoi(p)
	}

	// Only plain "chunked" is re-framable; any other Transfer-Encoding
	// (or chunked not last) would have to be decoded by us (RFC 9112 6.3).
	if len(req.TransferEncoding) > 0 &&
		!(len(req.TransferEncoding) == 1 && req.TransferEncoding[0] == "chunked") {
		writeHTTPErr(client, http.StatusBadRequest, "Unsupported Transfer-Encoding")
		return
	}

	lc, err := s.openUpstream(context.Background(), client.RemoteAddr().String(), req.Method, host, port)
	if err != nil {
		writeHTTPErr(client, statusForDialErr(err), "Connect failed")
		return
	}
	defer lc.Close()

	// One request per connection; bound the stalled-client window.
	_ = client.SetReadDeadline(time.Now().Add(requestTimeout))
	_ = client.SetWriteDeadline(time.Now().Add(requestTimeout))

	// Rewrite the request to origin form. One request per connection: force
	// Connection: close so the upstream closes after replying and the
	// response relay terminates cleanly.
	// ReadRequest removes Transfer-Encoding (and Content-Length when the
	// body is chunked) from req.Header; for requests it leaves Connection
	// in place (shouldClose only strips it on the response path) — the
	// header loop below skips whatever remains of those names anyway.
	// Bodies without Content-Length (chunked, close-delimited) are
	// de-framed and re-sent with Content-Length: the forwarded request
	// stays self-delimiting without chunk re-encoding or close-delimited
	// framing on a channel we keep open for the response.
	chunked := len(req.TransferEncoding) > 0
	closeDelimited := req.ContentLength < 0 // body until connection close
	hasBody := req.ContentLength != 0

	var body []byte
	if hasBody && (chunked || closeDelimited) {
		b, err := io.ReadAll(io.LimitReader(req.Body, maxReframedBody+1))
		if err != nil {
			writeHTTPErr(client, http.StatusRequestEntityTooLarge, "Body read failed")
			return
		}
		if int64(len(b)) > maxReframedBody {
			writeHTTPErr(client, http.StatusRequestEntityTooLarge, "Body too large")
			return
		}
		body = b
	}

	head := &bytes.Buffer{}
	fmt.Fprintf(head, "%s %s HTTP/1.1\r\n", req.Method, u.RequestURI())
	if req.Host == "" {
		req.Host = u.Host
	}
	fmt.Fprintf(head, "Host: %s\r\n", req.Host)
	if body != nil {
		fmt.Fprintf(head, "Content-Length: %d\r\n", len(body))
	}
	for k, vs := range req.Header {
		lk := strings.ToLower(k)
		switch lk {
		case "host", "connection", "proxy-connection", "proxy-authorization", "transfer-encoding":
			continue
		}
		for _, v := range vs {
			fmt.Fprintf(head, "%s: %s\r\n", k, v)
		}
	}
	io.WriteString(head, "Connection: close\r\n\r\n")
	io.WriteString(lc, head.String())

	if body != nil {
		if _, err := lc.Write(body); err != nil {
			writeHTTPErr(client, http.StatusBadGateway, "Body transfer failed")
			return
		}
	} else if hasBody {
		if _, err := io.Copy(lc, req.Body); err != nil {
			writeHTTPErr(client, http.StatusBadGateway, "Body transfer failed")
			return
		}
	}

	io.Copy(client, lc)
}

func writeHTTPErr(w io.Writer, code int, msg string) {
	body := msg + "\r\n"
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, http.StatusText(code), len(body), body)
}
