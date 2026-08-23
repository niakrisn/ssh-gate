package main

import (
	"context"
	"net"
	"strconv"

	"github.com/rs/zerolog/log"
	socks5 "github.com/things-go/go-socks5"
)

// SOCKS5Server wraps things-go/go-socks5 with Rule Engine routing.
type SOCKS5Server struct {
	srv    *socks5.Server
	ln     net.Listener
	shutCh chan struct{}
}

// NewSOCKS5Server creates a new SOCKS5 server with routing.
func NewSOCKS5Server(listen string, rules *RuleEngine, d dialer) (*SOCKS5Server, error) {
	s := &SOCKS5Server{
		shutCh: make(chan struct{}),
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

			if rules.Route(host, portInt) == RouteDirect {
				return net.Dial(network, addr)
			}
			return d.DialContext(ctx, network, addr)
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
	close(s.shutCh)
	return s.ln.Close()
}
