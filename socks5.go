package main

import (
	"context"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
	socks5 "github.com/things-go/go-socks5"
)

// SOCKS5Server wraps things-go/go-socks5 with Rule Engine routing.
type SOCKS5Server struct {
	srv       *socks5.Server
	ln        net.Listener
	shutCh    chan struct{}
	closeOnce sync.Once
	rules     *RuleEngine
	d         dialer
	family    IPFamily
}

// NewSOCKS5Server creates a new SOCKS5 server with routing.
func NewSOCKS5Server(listen string, rules *RuleEngine, d dialer, family IPFamily) (*SOCKS5Server, error) {
	s := &SOCKS5Server{
		shutCh: make(chan struct{}),
		rules:  rules,
		d:      d,
		family: family,
	}

	s.srv = socks5.NewServer(
		socks5.WithDialAndRequest(func(ctx context.Context, network, addr string, request *socks5.Request) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}

			portInt, _ := strconv.Atoi(port)

			// Prefer original hostname from the SOCKS5 request; fall back to resolved IP.
			if request.RawDestAddr.FQDN != "" {
				host = request.RawDestAddr.FQDN
			}

			src := request.RemoteAddr.String()

			route, reason := s.rules.Decide(ctx, host, portInt)

			log.Info().Str("proto", "socks5").Str("src", src).Str("host", host).Int("port", portInt).
				Str("route", route.String()).Str("reason", reason).Msg("request")

			start := time.Now()
			var upstream net.Conn
			var dst string

			if route == RouteDirect {
				upstream, dst, err = dialDirect(ctx, host, portInt, s.family)
			} else {
				dst = "ssh"
				upstream, err = s.d.DialContext(ctx, network, addr)
			}

			dialMS := time.Since(start).Milliseconds()

			if err != nil {
				log.Info().Str("proto", "socks5").Str("src", src).Str("host", host).Int("port", portInt).
					Str("route", route.String()).Str("reason", reason).Str("family", s.family.String()).
					Str("dst", dst).Int64("dial_ms", dialMS).Err(err).Msg("access")
				return nil, err
			}

			log.Debug().Str("host", host).Int("port", portInt).Str("dst", dst).Int64("dial_ms", dialMS).Msg("dial done")
			log.Debug().Str("proto", "socks5").Str("host", host).Int("port", portInt).Msg("handshake")

			return &logConn{
				Conn:   upstream,
				t0:     time.Now(),
				src:    src,
				host:   host,
				port:   portInt,
				dst:    dst,
				route:  route,
				reason: reason,
				family: s.family,
				dialMS: dialMS,
			}, nil
		}),
	)

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}
	s.ln = ln

	return s, nil
}

func (s *SOCKS5Server) Start() {
	log.Info().Str("listen", s.ln.Addr().String()).Msg("SOCKS5 server starting")

	go func() {
		if err := s.srv.Serve(s.ln); err != nil {
			select {
			case <-s.shutCh:
			default:
				log.Error().Err(err).Msg("SOCKS5 server failed")
			}
		}
	}()
}

func (s *SOCKS5Server) Shutdown(ctx context.Context) error {
	var err error
	s.closeOnce.Do(func() {
		close(s.shutCh)
		err = s.ln.Close()
	})
	return err
}

// logConn wraps upstream conn to count bytes and emit access log on close.
type logConn struct {
	net.Conn
	mu       sync.Mutex
	up, down int64  // client→upstream / upstream→client
	firstErr error  // first non-EOF error from Read/Write
	t0       time.Time
	closed   atomic.Bool
	// access fields
	src, host, dst, reason string
	port   int
	route  Route
	family IPFamily
	dialMS int64
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

	l.mu.Lock()
	up := l.up
	down := l.down
	firstErr := l.firstErr
	ms := time.Since(l.t0).Milliseconds()
	l.mu.Unlock()

	event := log.Info().
		Str("proto", "socks5").
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
