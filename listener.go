package main

import (
	"errors"
	"net"
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
// everything else backs off 5 ms..1 s and keeps trying. Close is idempotent
// because the SOCKS5 shutdown closes the listener twice (library defer plus
// our Shutdown).
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
