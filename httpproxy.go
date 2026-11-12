package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	stdlog "log"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

// httpIdleTimeout ends an absolute-form request once no byte has moved in
// either direction for this long (stalled client or stalled upstream). It
// is an idle bound, not a total one: a long download that keeps moving is
// never cut. CONNECT tunnels stay unbounded on purpose. A var so tests can
// shorten it; a server copies it when created.
var httpIdleTimeout = 5 * time.Minute

// headerReadTimeout bounds reading the request line and headers.
const headerReadTimeout = 30 * time.Second

// HTTPProxyServer is a minimal HTTP forward proxy: CONNECT tunneling plus
// one absolute-form request (GET/POST/...) per connection.
type HTTPProxyServer struct {
	srv       *http.Server
	ln        net.Listener
	shutCh    chan struct{}
	closeOnce sync.Once
	clients   *clientRegistry
	opener    *Opener
	// idleTimeout is httpIdleTimeout at construction.
	idleTimeout time.Duration
}

func NewHTTPProxyServer(listen string, opener *Opener) (*HTTPProxyServer, error) {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}
	s := &HTTPProxyServer{
		// keepalive on accepted sockets bounds the lifetime of a
		// half-dead CONNECT relay (see keepAliveListener); the resilient
		// wrapper keeps the accept loop alive through transient errors,
		// so an error here only ever means shutdown.
		ln:          &resilientListener{Listener: keepAliveListener{Listener: ln}},
		shutCh:      make(chan struct{}),
		clients:     newClientRegistry(),
		opener:      opener,
		idleTimeout: httpIdleTimeout,
	}
	s.srv = &http.Server{Handler: http.HandlerFunc(s.serveHTTP), ReadHeaderTimeout: headerReadTimeout, MaxHeaderBytes: http.DefaultMaxHeaderBytes,
		ErrorLog: stdlog.New(httpLogWriter{}, "", 0),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			owned := c.(*clientConn)
			// Keep net/http's server value while forced client close cancels
			// work even before a read detects the closed socket.
			ctx = context.WithValue(owned.ctx, http.ServerContextKey, ctx.Value(http.ServerContextKey))
			return context.WithValue(ctx, httpConnKey{}, owned)
		},
		ConnState: func(c net.Conn, state http.ConnState) {
			if state == http.StateClosed {
				c.(*clientConn).finish()
			}
		},
	}
	s.srv.SetKeepAlivesEnabled(false)
	return s, nil
}

// SetConnLimit applies the shared connection limit. Call before Start.
func (s *HTTPProxyServer) SetConnLimit(l *connLimiter) {
	s.ln = limitConns(s.ln, l)
}

func (s *HTTPProxyServer) Start() {
	log.Info().Str("listen", s.ln.Addr().String()).Msg("HTTP proxy starting")
	s.ln = &clientListener{Listener: s.ln, clients: s.clients}

	go func() {
		if err := s.srv.Serve(s.ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			select {
			case <-s.shutCh:
			default:
				log.Error().Err(err).Msg("HTTP proxy accept failed")
			}
		}
	}()
}

func (s *HTTPProxyServer) StopAccept() error {
	var err error
	s.closeOnce.Do(func() {
		s.clients.stop()
		close(s.shutCh)
		err = s.ln.Close()
	})
	return err
}

func (s *HTTPProxyServer) Drain(ctx context.Context) error { return s.clients.drain(ctx) }

func (s *HTTPProxyServer) ForceClose() {
	s.clients.forceClose()
	_ = s.srv.Close()
}

func (s *HTTPProxyServer) Shutdown(ctx context.Context) error {
	if err := s.StopAccept(); err != nil {
		return err
	}
	if err := s.Drain(ctx); err != nil {
		s.ForceClose()
		return err
	}
	return nil
}

type httpConnKey struct{}

func (s *HTTPProxyServer) serveHTTP(w http.ResponseWriter, req *http.Request) {
	// http.Server must not drain an unfinished upload while finalizing a
	// response. Interrupt reads after the handler, leaving writes available
	// until the server flushes the complete final response.
	client := req.Context().Value(httpConnKey{}).(net.Conn)
	defer func() { _ = client.SetReadDeadline(time.Now()) }()
	if req.Method != http.MethodConnect && (req.URL == nil || !req.URL.IsAbs() || req.URL.Scheme != "http") {
		http.Error(w, "HTTP absolute-form or CONNECT requests only", http.StatusBadRequest)
		return
	}
	if req.Method != http.MethodConnect {
		s.handleHTTP(w, req)
		return
	}
	client, rw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return
	}
	// Hijack transfers completion ownership away from http.Server.
	defer client.(*clientConn).finish()
	_ = client.SetDeadline(time.Time{})
	s.handleConnect(client, rw.Reader, req)
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
// wraps it for access logging. A dial failure is logged here.
func (s *HTTPProxyServer) openUpstream(ctx context.Context, src, method, host string, port int) (*logConn, error) {
	info := connInfo{id: nextConnID(), proto: "http", src: src, host: host, port: port, family: s.opener.family}
	log.Debug().Uint64("conn_id", info.id).Str("proto", "http").Str("method", method).Str("src", src).Str("host", host).Int("port", port).Msg("request")

	start := time.Now()
	upstream, dst, route, reason, err := s.opener.Open(ctx, src, "http", host, port)
	info.dst, info.route, info.reason = dst, route, reason
	info.dialMS = time.Since(start).Milliseconds()

	if err != nil {
		info.logFailure("dial_error", err)
		return nil, err
	}

	return &logConn{
		Conn:     upstream,
		t0:       time.Now(),
		connInfo: info,
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
	portInt, err := strconv.Atoi(port)
	if err != nil || validatePort(portInt) != nil {
		writeHTTPErr(client, http.StatusBadRequest, "Bad CONNECT target port")
		return
	}

	lc, err := s.openUpstream(req.Context(), client.RemoteAddr().String(), "CONNECT", host, portInt)
	if err != nil {
		writeHTTPErr(client, statusForDialErr(err), "Connect failed")
		return
	}

	defer lc.Close()
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		lc.recordError(err)
		client.Close()
		return
	}

	results := make(chan error, 2)
	go func() {
		_, err := io.Copy(lc, src)
		if err == nil {
			err = lc.CloseWrite()
		}
		results <- err
	}()
	go func() {
		_, err := io.Copy(client, lc)
		if err == nil {
			if cw, ok := client.(interface{ CloseWrite() error }); ok {
				err = cw.CloseWrite()
			}
		}
		results <- err
	}()
	failed := false
	for range 2 {
		if err := <-results; err != nil && !failed {
			failed = true
			lc.recordError(err)
			client.Close()
			// Unblock the other direction now; log the final counters only
			// after both copies have finished, in the deferred lc.Close.
			lc.Conn.Close()
		}
	}
}

func (s *HTTPProxyServer) handleHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Header.Get("Upgrade") != "" {
		http.Error(w, "Use CONNECT for protocol upgrades", http.StatusBadRequest)
		return
	}
	u := req.URL
	host := u.Hostname()
	port := 80
	if p := u.Port(); p != "" {
		var err error
		port, err = strconv.Atoi(p)
		if err != nil || validatePort(port) != nil {
			http.Error(w, "Bad target port", http.StatusBadRequest)
			return
		}
	}

	if err := http.NewResponseController(w).EnableFullDuplex(); err != nil {
		http.Error(w, "Full duplex HTTP unavailable", http.StatusInternalServerError)
		return
	}
	client := req.Context().Value(httpConnKey{}).(net.Conn)
	ctx, cancel := context.WithCancel(req.Context())
	defer cancel()
	g := newIdleGuard(s.idleTimeout, func() {
		log.Info().Str("src", req.RemoteAddr).Str("host", host).Msg("http: idle timeout")
		cancel()
		client.Close()
	})
	defer g.stop()
	transport := &http.Transport{
		Proxy: nil, DisableKeepAlives: true, DisableCompression: true,
		ExpectContinueTimeout: time.Second, MaxResponseHeaderBytes: 1 << 20,
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			// Transport detaches dial cancellation. Retain the original
			// request/owner instead so canceled clients cannot leave a dial.
			lc, err := s.openUpstream(ctx, req.RemoteAddr, req.Method, host, port)
			if err != nil {
				return nil, err
			}
			owned := &lifetimeConn{Conn: &guardedConn{Conn: lc, g: g}}
			owned.stop = context.AfterFunc(ctx, func() { lc.Close() })
			if err := ctx.Err(); err != nil {
				owned.Close()
				return nil, err
			}
			return owned, nil
		},
	}
	defer transport.CloseIdleConnections()
	request := req.WithContext(ctx)
	if req.Body != nil && req.Body != http.NoBody {
		// ReverseProxy and Transport both close the outbound body. Reading
		// the remaining inbound body here could block an early final reply.
		// The server owns the real body and closes it after our read deadline.
		request.Body = io.NopCloser(&guardedReader{r: req.Body, g: g})
	}
	proxy := &httputil.ReverseProxy{
		Transport: transport,
		ErrorLog:  stdlog.New(httpLogWriter{}, "", 0),
		Rewrite: func(p *httputil.ProxyRequest) {
			p.Out.URL = req.URL
			p.Out.Host = req.Host
			// Clone snapshots the trailer map before the body has filled it.
			// Transport writes these values only after reading the same body.
			p.Out.Trailer = req.Trailer
			p.Out.Header.Del("Proxy-Authorization")
		},
		ModifyResponse: func(r *http.Response) error {
			if r.StatusCode == http.StatusSwitchingProtocols {
				return errors.New("upstream protocol upgrade not supported")
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			http.Error(w, "Connect failed", statusForDialErr(err))
		},
	}
	proxy.ServeHTTP(&guardedResponseWriter{ResponseWriter: w, g: g}, request)
}

type guardedResponseWriter struct {
	http.ResponseWriter
	g *idleGuard
}

func (w *guardedResponseWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	if n > 0 {
		w.g.touch()
	}
	return n, err
}

func (w *guardedResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

type httpLogWriter struct{}

func (httpLogWriter) Write(p []byte) (int, error) {
	log.Warn().Str("component", "http").Msg(strings.TrimSpace(string(p)))
	return len(p), nil
}

func writeHTTPErr(w io.Writer, code int, msg string) {
	body := msg + "\r\n"
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, http.StatusText(code), len(body), body)
}

// idleGuard runs onIdle once no I/O went through its guarded conns for
// timeout. Progress is an atomic timestamp checked by one goroutine, so the
// relay hot path costs one atomic store per call.
type idleGuard struct {
	last atomic.Int64 // unix nanos of the last progress
	done chan struct{}
	once sync.Once
}

func newIdleGuard(timeout time.Duration, onIdle func()) *idleGuard {
	g := &idleGuard{done: make(chan struct{})}
	g.touch()
	check := timeout / 10
	if check > time.Second {
		check = time.Second
	}
	go func() {
		t := time.NewTicker(check)
		defer t.Stop()
		for {
			select {
			case <-g.done:
				return
			case <-t.C:
				if time.Since(time.Unix(0, g.last.Load())) >= timeout {
					onIdle()
					return
				}
			}
		}
	}()
	return g
}

func (g *idleGuard) touch() { g.last.Store(time.Now().UnixNano()) }

func (g *idleGuard) stop() { g.once.Do(func() { close(g.done) }) }

// guardedConn reports every byte moved to its idleGuard.
type guardedConn struct {
	net.Conn
	g *idleGuard
}

func (c *guardedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.g.touch()
	}
	return n, err
}

func (c *guardedConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.g.touch()
	}
	return n, err
}

// guardedReader reports every byte read to its idleGuard; the request body
// is read through the header reader, not through guardedConn.
type guardedReader struct {
	r io.Reader
	g *idleGuard
}

func (r *guardedReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if n > 0 {
		r.g.touch()
	}
	return n, err
}
