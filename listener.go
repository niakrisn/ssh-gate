package main

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

// keepAliveListener pins an explicit 30 s keepalive idle period on accepted
// connections. The Go runtime turns on its own default keepalive (15 s idle)
// on TCP conns it accepts, so a dead client (crash, pulled cable, expired NAT
// state without RST) is cleaned up eventually - but this wrapper makes the
// bounded lifetime an explicit property of the proxy instead of a runtime
// default that may change. Same reasoning as net/http's internal
// tcpKeepaliveListener. Live-but-idle tunnels stay legitimate: keepalive only
// tears down dead TCP.
type keepAliveListener struct {
	net.Listener
}

func (l keepAliveListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
	return c, nil
}

// resilientListener keeps an accept loop alive through transient accept
// errors (EMFILE/ENFILE storms). The consumers here do not own the listener
// lifecycle: the SOCKS5 library's Serve returns on any Accept error and then
// closes the listener, and the HTTP accept-loop exits on error - either way
// a temporary failure would leave the port open but unserved until restart,
// while net/http would simply retry. So the only terminal state is "closed";
// everything else backs off 5 ms..1 s and keeps trying. Close is idempotent,
// so a repeated Close from a shutdown path is harmless.
type resilientListener struct {
	net.Listener
	closed atomic.Bool
}

func (l *resilientListener) Close() error {
	if l.closed.Swap(true) {
		return nil // already closed: swallow the double close
	}
	return l.Listener.Close()
}

func (l *resilientListener) Accept() (net.Conn, error) {
	delay := 5 * time.Millisecond
	inError := false
	for {
		if l.closed.Load() {
			return nil, net.ErrClosed
		}
		c, err := l.Listener.Accept()
		if err == nil {
			delay = 5 * time.Millisecond
			inError = false // next error burst gets a fresh Warn
			return c, nil
		}
		if errors.Is(err, net.ErrClosed) {
			return nil, err // terminal: closed underneath
		}
		if inError {
			log.Debug().Err(err).Msg("listener accept failed, retrying")
		} else {
			log.Warn().Err(err).Msg("listener accept failed, retrying")
			inError = true
		}
		time.Sleep(delay)
		if delay *= 2; delay > time.Second {
			delay = time.Second
		}
	}
}

// connLimiter caps concurrent client connections shared by all proxy
// listeners: each proxied connection holds at least one file descriptor
// and a goroutine, so an unbounded burst from the network exhausts both.
// A nil limiter means no limit.
type connLimiter struct {
	slots chan struct{}
}

// newConnLimiter returns a limiter for n connections, or nil (no limit)
// for n <= 0.
func newConnLimiter(n int) *connLimiter {
	if n <= 0 {
		return nil
	}
	return &connLimiter{slots: make(chan struct{}, n)}
}

func (l *connLimiter) tryAcquire() bool {
	select {
	case l.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (l *connLimiter) release() { <-l.slots }

// limitListener refuses connections over the limit: it accepts and closes
// them at once, so the client gets an immediate error instead of waiting
// in the kernel backlog. The slot is released when the connection closes.
type limitListener struct {
	net.Listener
	limit   *connLimiter
	refused atomic.Bool // in a refusal burst: Warn once, then Debug
}

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.limit.tryAcquire() {
			l.refused.Store(false)
			return &limitedConn{Conn: c, limit: l.limit}, nil
		}
		ev := log.Debug()
		if !l.refused.Swap(true) {
			ev = log.Warn()
		}
		ev.Str("src", c.RemoteAddr().String()).Int("limit", cap(l.limit.slots)).Msg("connection limit reached, connection refused")
		c.Close()
	}
}

// limitedConn returns its slot on the first Close. Half-close is forwarded:
// both proxies half-close the client side at the end of a relay.
type limitedConn struct {
	net.Conn
	limit *connLimiter
	once  sync.Once
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.limit.release)
	return err
}

func (c *limitedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (c *limitedConn) CloseRead() error {
	if cr, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}

// limitConns wraps ln with limit; a nil limit returns ln unchanged.
func limitConns(ln net.Listener, limit *connLimiter) net.Listener {
	if limit == nil {
		return ln
	}
	return &limitListener{Listener: ln, limit: limit}
}
