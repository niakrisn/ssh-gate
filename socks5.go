package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

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
}

// NewSOCKS5Server creates a new SOCKS5 server with routing.
func NewSOCKS5Server(listen string, opener *Opener) (*SOCKS5Server, error) {
	s := &SOCKS5Server{
		shutCh: make(chan struct{}),
		opener: opener,
	}

	s.srv = socks5.NewServer(
		socks5.WithDialAndRequest(func(ctx context.Context, network, addr string, request *socks5.Request) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, NewConfigurationError("destination address", addr, fmt.Sprintf("invalid format: %v", err))
			}

			portInt, _ := strconv.Atoi(port)

			// Prefer original hostname from the SOCKS5 request; fall back to resolved IP.
			if request.RawDestAddr.FQDN != "" {
				host = request.RawDestAddr.FQDN
			}

			src := request.RemoteAddr.String()

			log.Info().Str("proto", "socks5").Str("src", src).Str("host", host).Int("port", portInt).Msg("request")

			start := time.Now()
			upstream, dst, route, reason, err := s.opener.Open(ctx, src, "socks5", host, portInt)
			dialMS := time.Since(start).Milliseconds()

			if err != nil {
				log.Info().Str("proto", "socks5").Str("src", src).Str("host", host).Int("port", portInt).
					Str("route", route.String()).Str("reason", reason).Str("family", s.opener.family.String()).
					Str("dst", dst).Int64("dial_ms", dialMS).Err(err).Msg("access")
				return nil, err
			}

			log.Debug().Str("host", host).Int("port", portInt).Str("dst", dst).Int64("dial_ms", dialMS).Msg("dial done")
			log.Debug().Str("proto", "socks5").Str("host", host).Int("port", portInt).Msg("handshake")

			// The library closes the returned conn when its relay ends,
			// so counting here tracks in-flight relays exactly (UDP
			// ASSOCIATE is rejected, so every logConn is a CONNECT relay).
			s.conns.Add(1)
			return &logConn{
				Conn:    upstream,
				onClose: s.conns.Done,
				proto:   "socks5",
				t0:      time.Now(),
				src:     src,
				host:    host,
				port:    portInt,
				dst:     dst,
				route:   route,
				reason:  reason,
				family:  s.opener.family,
				dialMS:  dialMS,
			}, nil
		}),
		// FQDNs are resolved through the shared Opener (route policy: direct
		// via local DNS, tunnel via DoH; cached, 5 s lookup timeout) instead
		// of the library default, which is unbounded and uncached.
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
	// resilient wrapper absorbs transient accept errors that would end
	// Serve for good, and its idempotent Close swallows the library's
	// deferred Close after our Shutdown closed the listener.
	s.ln = &resilientListener{Listener: keepAliveListener{Listener: ln}}

	return s, nil
}

func (s *SOCKS5Server) Start() {
	log.Info().Str("listen", s.ln.Addr().String()).Msg("SOCKS5 server starting")

	go func() {
		// s.ln already carries keepAliveListener + resilientListener
		// (see NewSOCKS5Server).
		if err := s.srv.Serve(s.ln); err != nil {
			select {
			case <-s.shutCh:
			default:
				log.Error().Err(err).Msg("SOCKS5 server failed")
			}
		}
	}()
}

// Shutdown stops the library's accept loop, then waits (bounded by ctx) for
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

// logConn wraps upstream conn to count bytes and emit access log on close.
type logConn struct {
	net.Conn
	mu       sync.Mutex
	up, down int64 // client→upstream / upstream→client
	firstErr error // first non-EOF error from Read/Write
	t0       time.Time
	closed   atomic.Bool
	// onClose runs exactly once, after the first Close (successful or not —
	// a failed Close still retires the relay, otherwise the shutdown drain
	// could wait forever on a dead transport). The SOCKS5 server uses it to
	// retire an in-flight relay from its shutdown drain counter.
	onClose func()
	// access fields
	proto, src, host, dst, reason string
	port                          int
	route                         Route
	family                        IPFamily
	dialMS                        int64
}

func (l *logConn) Read(p []byte) (int, error) {
	n, err := l.Conn.Read(p)
	if n > 0 {
		l.mu.Lock()
		l.down += int64(n)
		if err != nil && err != io.EOF && l.firstErr == nil {
			l.firstErr = err
		}
		l.mu.Unlock()
	} else if err != nil && err != io.EOF {
		l.mu.Lock()
		if l.firstErr == nil {
			l.firstErr = err
		}
		l.mu.Unlock()
	}
	return n, err
}

func (l *logConn) Write(p []byte) (int, error) {
	n, err := l.Conn.Write(p)
	if n > 0 {
		l.mu.Lock()
		l.up += int64(n)
		if err != nil && err != io.EOF && l.firstErr == nil {
			l.firstErr = err
		}
		l.mu.Unlock()
	} else if err != nil && err != io.EOF {
		l.mu.Lock()
		if l.firstErr == nil {
			l.firstErr = err
		}
		l.mu.Unlock()
	}
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

	event := log.Info().
		Str("proto", l.proto).
		Str("src", l.src).
		Str("host", l.host).
		Int("port", l.port).
		Str("route", l.route.String()).
		Str("reason", l.reason).
		Str("family", l.family.String()).
		Str("dst", l.dst).
		Int64("dial_ms", l.dialMS).
		Int64("ms", ms).
		Int64("bytes_up", up).
		Int64("bytes_down", down)

	if firstErr != nil {
		event.Err(firstErr)
	}

	event.Msg("access")

	return err
}

// openerResolver adapts the shared Opener's resolution to the go-socks5
// NameResolver interface. The SOCKS5 handshake must return an IP before the
// dial callback runs, so it resolves per the same route policy Open applies:
// direct hosts through the local resolver, tunnel hosts through DoH.
type openerResolver struct {
	opener *Opener
}

func (r openerResolver) Resolve(ctx context.Context, host string) (context.Context, net.IP, error) {
	// Rules do not depend on the port; the interface only carries the name.
	ip, _, _, err := r.opener.Resolve(ctx, host, 0)
	if err != nil {
		return ctx, nil, err
	}
	return ctx, ip, nil
}
