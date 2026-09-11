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

// maxReframedBody bounds bodies that must be re-framed with Content-Length
// (chunked or close-delimited). The VPS sshd closes the direct-tcpip channel
// on EOF, so an EOF after a body loses the response; such bodies are buffered
// and re-framed instead.
const maxReframedBody = 32 << 20

// HTTPProxyServer is a minimal HTTP forward proxy: CONNECT tunneling plus
// one absolute-form request (GET/POST/...) per connection.
type HTTPProxyServer struct {
	ln        net.Listener
	shutCh    chan struct{}
	closeOnce sync.Once
	rules     *RuleEngine
	d         dialer
	family    IPFamily
}

func NewHTTPProxyServer(listen string, rules *RuleEngine, d dialer, family IPFamily) (*HTTPProxyServer, error) {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}
	return &HTTPProxyServer{
		ln:     ln,
		shutCh: make(chan struct{}),
		rules:  rules,
		d:      d,
		family: family,
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
			go s.handleConn(conn)
		}
	}()
}

func (s *HTTPProxyServer) Shutdown(ctx context.Context) error {
	var err error
	s.closeOnce.Do(func() {
		close(s.shutCh)
		err = s.ln.Close()
	})
	return err
}

func (s *HTTPProxyServer) handleConn(client net.Conn) {
	defer client.Close()

	_ = client.SetReadDeadline(time.Now().Add(30 * time.Second))
	req, err := http.ReadRequest(bufio.NewReader(client))
	if err != nil {
		log.Warn().Str("client", client.RemoteAddr().String()).Err(err).Msg("http: bad request")
		writeHTTPErr(client, http.StatusBadRequest, "Bad Request")
		return
	}
	_ = client.SetReadDeadline(time.Time{})

	switch {
	case req.Method == http.MethodConnect:
		s.handleConnect(client, req)
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

// dialUpstream dials host:port according to the route decided by the rule engine.
func (s *HTTPProxyServer) dialUpstream(ctx context.Context, host string, port int, route Route) (net.Conn, string, error) {
	if route == RouteDirect {
		return dialDirect(ctx, host, port, s.family)
	}
	conn, err := s.d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, "ssh", err
	}
	return conn, "ssh", nil
}

// openUpstream decides the route for host:port, dials the upstream and wraps
// the connection for access logging. The access log is emitted on dial failure.
func (s *HTTPProxyServer) openUpstream(ctx context.Context, src, method, host string, port int) (*logConn, error) {
	route, reason := s.rules.Decide(ctx, host, port)

	log.Info().Str("proto", "http").Str("method", method).Str("src", src).Str("host", host).Int("port", port).
		Str("route", route.String()).Str("reason", reason).Msg("request")

	start := time.Now()
	upstream, dst, err := s.dialUpstream(ctx, host, port, route)
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
		family: s.family,
		dialMS: dialMS,
	}, nil
}

func (s *HTTPProxyServer) handleConnect(client net.Conn, req *http.Request) {
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
		io.Copy(lc, client)
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
	// req.Header never contains Transfer-Encoding or Connection (ReadRequest
	// moves them into Request fields), so body presence is taken from there.
	// Bodies without Content-Length (chunked, close-delimited) are de-framed
	// and re-sent with Content-Length: never send EOF after a body, the VPS
	// sshd drops the direct-tcpip channel on EOF and the response is lost.
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
