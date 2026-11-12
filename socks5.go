package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	socks5 "github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
)

// SOCKS5Server wraps things-go/go-socks5, opening every connection through
// the shared Opener.
type SOCKS5Server struct {
	srv       *socks5.Server
	ln        net.Listener
	shutCh    chan struct{}
	closeOnce sync.Once
	clients   *clientRegistry
	opener    *Opener
	// handshakeTimeout is socks5HandshakeTimeout at construction.
	handshakeTimeout time.Duration
}

// socks5HandshakeTimeout bounds the SOCKS5 greeting and request: the
// library sets no deadline of its own, so a client that connects and stays
// silent would hold a goroutine and a descriptor forever. A var so tests
// can shorten it; a server copies it when created.
var socks5HandshakeTimeout = 30 * time.Second

// NewSOCKS5Server creates a new SOCKS5 server with routing.
func NewSOCKS5Server(listen string, opener *Opener) (*SOCKS5Server, error) {
	s := &SOCKS5Server{
		shutCh:           make(chan struct{}),
		opener:           opener,
		clients:          newClientRegistry(),
		handshakeTimeout: socks5HandshakeTimeout,
	}

	s.srv = socks5.NewServer(
		socks5.WithDialAndRequest(func(_ context.Context, network, addr string, request *socks5.Request) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("invalid destination address %q: %w", addr, err)
			}

			portInt, _ := strconv.Atoi(port)

			// Prefer original hostname from the SOCKS5 request; fall back to resolved IP.
			if request.RawDestAddr.FQDN != "" {
				host = request.RawDestAddr.FQDN
			}

			src := request.RemoteAddr.String()
			// The handshake is over: the relay that follows is unbounded,
			// like a CONNECT tunnel. Lifted before the dial so a slow dial
			// does not make the reply write fail.
			client := s.clients.find(src)
			if client == nil {
				return nil, context.Canceled
			}
			_ = client.SetDeadline(time.Time{})

			info := connInfo{id: nextConnID(), proto: "socks5", src: src, host: host, port: portInt, family: s.opener.family}
			log.Debug().Uint64("conn_id", info.id).Str("proto", "socks5").Str("src", src).Str("host", host).Int("port", portInt).Msg("request")

			ctx := client.ctx

			start := time.Now()
			upstream, dst, route, reason, err := s.opener.Open(ctx, src, "socks5", host, portInt)
			info.dst, info.route, info.reason = dst, route, reason
			info.dialMS = time.Since(start).Milliseconds()

			if err != nil {
				var dnsErr *DNSError
				if errors.As(err, &dnsErr) {
					info.logFailure("resolve_error", err)
					return nil, errResolveFailed
				}
				info.logFailure("dial_error", err)
				return nil, err
			}

			log.Debug().Uint64("conn_id", info.id).Str("dst", dst).Int64("dial_ms", info.dialMS).Msg("dial done")

			return &logConn{
				Conn:     upstream,
				t0:       time.Now(),
				connInfo: info,
			}, nil
		}),
		// Keep the original FQDN until Open owns route selection and DNS.
		socks5.WithResolver(deferredResolver{}),
		// The library default for ASSOCIATE dials the target with plain
		// net.Dial (it never consults the dial-with-request or resolver
		// hooks), i.e. a direct UDP relay that bypasses the route rules,
		// conntrack and the access log. The direct-tcpip SSH transport
		// cannot carry UDP, so the only honest behavior is rejection.
		socks5.WithAssociateHandle(func(_ context.Context, writer io.Writer, req *socks5.Request) error {
			log.Info().Str("proto", "socks5").Str("src", req.RemoteAddr.String()).
				Str("host", req.RawDestAddr.String()).Msg("udp associate rejected")
			return socks5.SendReply(writer, statute.RepCommandNotSupported, nil)
		}),
	)

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}
	// keepAliveListener bounds the lifetime of a half-dead relay; the
	// resilient wrapper absorbs transient accept errors, so an accept
	// error here only ever means shutdown.
	s.ln = &resilientListener{Listener: keepAliveListener{Listener: ln}}

	return s, nil
}

// SetConnLimit applies the shared connection limit. Call before Start.
func (s *SOCKS5Server) SetConnLimit(l *connLimiter) {
	s.ln = limitConns(s.ln, l)
}

// Start runs the accept loop. It is ours, not the library's Serve: each
// connection gets the handshake deadline before the library reads from it.
func (s *SOCKS5Server) Start() {
	log.Info().Str("listen", s.ln.Addr().String()).Msg("SOCKS5 server starting")
	s.ln = &clientListener{Listener: s.ln, clients: s.clients}

	go func() {
		for {
			conn, err := s.ln.Accept()
			if err != nil {
				select {
				case <-s.shutCh:
				default:
					log.Error().Err(err).Msg("SOCKS5 server failed")
				}
				return
			}
			go s.serveConn(conn.(*clientConn))
		}
	}()
}

func (s *SOCKS5Server) serveConn(conn *clientConn) {
	defer conn.finish()
	src := conn.RemoteAddr().String()
	_ = conn.SetDeadline(time.Now().Add(s.handshakeTimeout))
	// ServeConn closes conn when it returns.
	if err := s.srv.ServeConn(conn); err != nil {
		log.Debug().Str("proto", "socks5").Str("src", src).Err(err).Msg("connection ended")
	}
}

func (s *SOCKS5Server) StopAccept() error {
	var err error
	s.closeOnce.Do(func() {
		s.clients.stop()
		close(s.shutCh)
		err = s.ln.Close()
	})
	return err
}

func (s *SOCKS5Server) Drain(ctx context.Context) error { return s.clients.drain(ctx) }

func (s *SOCKS5Server) ForceClose() { s.clients.forceClose() }

// Shutdown includes handshake and dial work as well as established relays.
func (s *SOCKS5Server) Shutdown(ctx context.Context) error {
	if err := s.StopAccept(); err != nil {
		return err
	}
	if err := s.Drain(ctx); err != nil {
		s.ForceClose()
		return err
	}
	return nil
}

// connIDs numbers proxied connections over both proxies. conn_id links a
// connection's access line to its error in the service log.
var connIDs atomic.Uint64

func nextConnID() uint64 { return connIDs.Add(1) }

// connInfo is what the access log knows about one proxied connection.
type connInfo struct {
	id                            uint64
	proto, src, host, dst, reason string
	port                          int
	route                         Route
	family                        IPFamily
	dialMS                        int64
}

func (c *connInfo) fields(e *zerolog.Event) *zerolog.Event {
	return e.Uint64("conn_id", c.id).
		Str("proto", c.proto).
		Str("src", c.src).
		Str("host", c.host).
		Int("port", c.port).
		Str("route", c.route.String()).
		Str("reason", c.reason).
		Str("family", c.family.String()).
		Str("dst", c.dst).
		Int64("dial_ms", c.dialMS)
}

// logFailure records a connection that never reached the relay: the access
// line only names the failed stage in result, the error itself goes to the
// service log under the same conn_id.
func (c *connInfo) logFailure(result string, err error) {
	c.fields(accessLog.Info()).Str("result", result).Msg("access")
	c.fields(log.Warn()).Str("result", result).Err(err).Msg("connection failed")
}

// relayErr reports whether err from the upstream conn is worth logging.
// net.ErrClosed comes from our own Close racing a pending Read, not from
// the peer.
func relayErr(err error) bool {
	return err != nil && err != io.EOF && !errors.Is(err, net.ErrClosed)
}

// logConn wraps upstream conn to count bytes and emit access log on close.
type logConn struct {
	net.Conn
	mu       sync.Mutex
	up, down int64 // client→upstream / upstream→client
	firstErr error // first relayErr error from Read/Write
	t0       time.Time
	closed   atomic.Bool
	connInfo
}

func (l *logConn) Read(p []byte) (int, error) {
	n, err := l.Conn.Read(p)
	l.mu.Lock()
	l.down += int64(n)
	if relayErr(err) && l.firstErr == nil {
		l.firstErr = err
	}
	l.mu.Unlock()
	return n, err
}

func (l *logConn) Write(p []byte) (int, error) {
	n, err := l.Conn.Write(p)
	l.mu.Lock()
	l.up += int64(n)
	if relayErr(err) && l.firstErr == nil {
		l.firstErr = err
	}
	l.mu.Unlock()
	return n, err
}

func (l *logConn) CloseWrite() error {
	if cw, ok := l.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// recordError includes failures on the client side of a relay, which do
// not pass through this upstream connection's Read or Write methods.
func (l *logConn) recordError(err error) {
	if !relayErr(err) {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.firstErr == nil {
		l.firstErr = err
	}
}

func (l *logConn) Close() error {
	if !l.closed.CompareAndSwap(false, true) {
		return l.Conn.Close()
	}

	err := l.Conn.Close()

	l.mu.Lock()
	up := l.up
	down := l.down
	firstErr := l.firstErr
	ms := time.Since(l.t0).Milliseconds()
	l.mu.Unlock()

	result := "ok"
	if firstErr != nil {
		result = "relay_error"
	}
	l.fields(accessLog.Info()).
		Str("result", result).
		Int64("ms", ms).
		Int64("bytes_up", up).
		Int64("bytes_down", down).
		Msg("access")
	if firstErr != nil {
		l.fields(log.Warn()).
			Str("result", result).
			Int64("ms", ms).
			Int64("bytes_up", up).
			Int64("bytes_down", down).
			Err(firstErr).
			Msg("connection failed")
	}

	return err
}

// errResolveFailed fails the dial of a SOCKS5 request whose name did not
// resolve. Its text has neither "refused" nor "network is unreachable", so
// the library answers host unreachable, as for a failed Resolve.
var errResolveFailed = errors.New("destination name not resolved")

// go-socks5 preserves the FQDN in AddrSpec.String when IP is nil. Every
// CONNECT then reaches WithDialAndRequest; no library DNS or dial is used.
type deferredResolver struct{}

func (deferredResolver) Resolve(ctx context.Context, _ string) (context.Context, net.IP, error) {
	return ctx, nil, nil
}
