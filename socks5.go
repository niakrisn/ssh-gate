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
	conns     sync.WaitGroup // CONNECT relays: one logConn per dial
	opener    *Opener
	// handshakes maps the client address of a connection still in the
	// SOCKS5 handshake to its conn, so the dial callback (which only gets
	// the request) can lift the handshake deadline.
	handshakes sync.Map
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
		handshakeTimeout: socks5HandshakeTimeout,
	}

	s.srv = socks5.NewServer(
		socks5.WithDialAndRequest(func(ctx context.Context, network, addr string, request *socks5.Request) (net.Conn, error) {
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
			if c, ok := s.handshakes.Load(src); ok {
				_ = c.(net.Conn).SetDeadline(time.Time{})
			}

			info := connInfo{id: nextConnID(), proto: "socks5", src: src, host: host, port: portInt, family: s.opener.family}
			log.Debug().Uint64("conn_id", info.id).Str("proto", "socks5").Str("src", src).Str("host", host).Int("port", portInt).Msg("request")

			if rf, ok := ctx.Value(resolveFailureKey{}).(*resolveFailure); ok {
				info.route, info.reason = rf.route, rf.reason
				info.logFailure("resolve_error", rf.err)
				return nil, errResolveFailed
			}

			start := time.Now()
			upstream, dst, route, reason, err := s.opener.Open(ctx, src, "socks5", host, portInt)
			info.dst, info.route, info.reason = dst, route, reason
			info.dialMS = time.Since(start).Milliseconds()

			if err != nil {
				info.logFailure("dial_error", err)
				return nil, err
			}

			log.Debug().Uint64("conn_id", info.id).Str("dst", dst).Int64("dial_ms", info.dialMS).Msg("dial done")

			// The library closes the returned conn when its relay ends,
			// so counting here tracks in-flight relays exactly (UDP
			// ASSOCIATE is rejected, so every logConn is a CONNECT relay).
			s.conns.Add(1)
			return &logConn{
				Conn:     upstream,
				onClose:  s.conns.Done,
				t0:       time.Now(),
				connInfo: info,
			}, nil
		}),
		// FQDNs are resolved through the shared Opener (route policy: direct
		// via local DNS, tunnel via the tunnel resolvers; cached, 5 s lookup
		// timeout) instead of the library default, which is unbounded and
		// uncached.
		socks5.WithResolver(openerResolver{opener: s.opener}),
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
			go s.serveConn(conn)
		}
	}()
}

func (s *SOCKS5Server) serveConn(conn net.Conn) {
	src := conn.RemoteAddr().String()
	_ = conn.SetDeadline(time.Now().Add(s.handshakeTimeout))
	s.handshakes.Store(src, conn)
	defer s.handshakes.Delete(src)
	// ServeConn closes conn when it returns.
	if err := s.srv.ServeConn(conn); err != nil {
		log.Debug().Str("proto", "socks5").Str("src", src).Err(err).Msg("connection ended")
	}
}

// Shutdown stops the accept loop, then waits (bounded by ctx) for
// in-flight CONNECT relays to finish. The listener close runs once; the
// drain wait runs on every call, mirroring HTTPProxyServer.Shutdown. Stuck
// relays left behind at timeout are killed when the SSH dialer stops.
func (s *SOCKS5Server) Shutdown(ctx context.Context) error {
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
		s.conns.Wait()
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
	// onClose runs exactly once, after the first Close (successful or not —
	// a failed Close still retires the relay, otherwise the shutdown drain
	// could wait forever on a dead transport). The SOCKS5 server uses it to
	// retire an in-flight relay from its shutdown drain counter.
	onClose func()
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

func (l *logConn) Close() error {
	if !l.closed.CompareAndSwap(false, true) {
		return l.Conn.Close()
	}

	err := l.Conn.Close()
	if l.onClose != nil {
		l.onClose()
	}

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

type resolveFailureKey struct{}

type resolveFailure struct {
	route  Route
	reason string
	err    error
}

// openerResolver adapts the shared Opener's resolution to the go-socks5
// NameResolver interface. The SOCKS5 handshake must return an IP before the
// dial callback runs, so it resolves per the same route policy Open applies:
// direct hosts through the local resolver, tunnel hosts through the tunnel
// resolvers.
type openerResolver struct {
	opener *Opener
}

func (r openerResolver) Resolve(ctx context.Context, host string) (context.Context, net.IP, error) {
	// Rules do not depend on the port; the interface only carries the name.
	ip, route, reason, err := r.opener.Resolve(ctx, host, 0)
	if err != nil {
		// Not returned to the library: it would answer the client and drop
		// the request before the dial callback, the only place that knows
		// the client address, so the failure would miss the access log.
		// The callback reports it and fails with errResolveFailed.
		rf := &resolveFailure{route: route, reason: reason, err: err}
		return context.WithValue(ctx, resolveFailureKey{}, rf), net.IPv4zero, nil
	}
	return ctx, ip, nil
}
