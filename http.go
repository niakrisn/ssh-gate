package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"strconv"

	"github.com/rs/zerolog/log"
)

// HTTPServer handles HTTP CONNECT requests.
type HTTPServer struct {
	server *http.Server
	ln     net.Listener
	rules  *RuleEngine
	d      dialer
}

// NewHTTPServer returns a new HTTP CONNECT proxy server.
func NewHTTPServer(listen string, rules *RuleEngine, d dialer) (*HTTPServer, error) {
	s := &HTTPServer{
		rules: rules,
		d:     d,
	}

	s.server = &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodConnect {
				http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
				return
			}

			hijacker, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "hijack not supported", http.StatusInternalServerError)
				return
			}

			clientConn, _, err := hijacker.Hijack()
			if err != nil {
				log.Debug().Err(err).Msg("hijack failed")
				return
			}

			host, port, _ := net.SplitHostPort(r.Host)
			portInt, _ := strconv.Atoi(port)

			s.handle(clientConn, host, portInt)
		}),
	}

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}
	s.ln = ln

	return s, nil
}

func (s *HTTPServer) Start() error {
	log.Info().Str("listen", s.ln.Addr().String()).Msg("HTTP CONNECT server starting")

	go func() {
		if err := s.server.Serve(s.ln); err != nil && err != http.ErrServerClosed {
			log.Error().Err(err).Msg("HTTP server failed")
		}
	}()

	return nil
}

func (s *HTTPServer) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}

func (s *HTTPServer) handle(clientConn net.Conn, host string, port int) {
	defer clientConn.Close()

	route := s.rules.Route(host, port)

	var upstream net.Conn
	var err error

	addr := net.JoinHostPort(host, strconv.Itoa(port))

	if route == RouteDirect {
		upstream, err = net.Dial("tcp", addr)
	} else {
		upstream, err = s.d.DialContext(context.Background(), "tcp", addr)
	}

	if err != nil {
		log.Debug().Err(err).Str("host", host).Send()
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer upstream.Close()

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	relay(clientConn, upstream)
}

// relay copies data bidirectionally between two connections.
func relay(a, b net.Conn) {
	var err1, err2 error

	ch1 := make(chan error, 1)
	ch2 := make(chan error, 1)

	go func() {
		_, err1 := io.Copy(a, b)
		ch1 <- err1
	}()

	go func() {
		_, err2 := io.Copy(b, a)
		ch2 <- err2
	}()

	<-ch1
	<-ch2

	if err1 != nil && err1 != io.EOF {
		log.Debug().Err(err1).Send()
	}
	if err2 != nil && err2 != io.EOF {
		log.Debug().Err(err2).Send()
	}
}
