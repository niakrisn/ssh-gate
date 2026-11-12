package main

import (
	"context"
	"net"
	"sync"
)

// clientRegistry owns clients from Accept until their handlers finish.
// Closing a socket cancels its work but does not declare the handler done.
type clientRegistry struct {
	mu        sync.Mutex
	clients   map[string]*clientConn
	stopping  bool
	accepting int
	done      chan struct{}
	doneOnce  sync.Once
}

func newClientRegistry() *clientRegistry {
	return &clientRegistry{clients: make(map[string]*clientConn), done: make(chan struct{})}
}

func (r *clientRegistry) add(c net.Conn) (*clientConn, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := c.RemoteAddr().String()
	if r.stopping || r.clients[key] != nil {
		return nil, false
	}
	ctx, cancel := context.WithCancel(context.Background())
	owned := &clientConn{Conn: c, registry: r, ctx: ctx, cancel: cancel, key: key}
	r.clients[key] = owned
	return owned, true
}

func (r *clientRegistry) find(src string) *clientConn {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.clients[src]
}

func (r *clientRegistry) stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopping = true
	r.finishIfDrained()
}

// An Accept may already have a socket when stop closes the listener.
// Retain it in the drain until it is registered or rejected and closed.
func (r *clientRegistry) beginAccept() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopping {
		return false
	}
	r.accepting++
	return true
}

func (r *clientRegistry) endAccept() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.accepting--
	r.finishIfDrained()
}

func (r *clientRegistry) finishIfDrained() {
	if r.stopping && r.accepting == 0 && len(r.clients) == 0 {
		r.doneOnce.Do(func() { close(r.done) })
	}
}

func (r *clientRegistry) drain(ctx context.Context) error {
	select {
	case <-r.done:
		return nil
	default:
	}
	select {
	case <-r.done:
		return nil
	case <-ctx.Done():
		select {
		case <-r.done:
			return nil
		default:
			return ctx.Err()
		}
	}
}

func (r *clientRegistry) forceClose() {
	r.mu.Lock()
	clients := make([]*clientConn, 0, len(r.clients))
	for _, c := range r.clients {
		clients = append(clients, c)
	}
	r.mu.Unlock()
	for _, c := range clients {
		c.Close()
	}
}

type clientConn struct {
	net.Conn
	registry   *clientRegistry
	ctx        context.Context
	cancel     context.CancelFunc
	key        string
	closeOnce  sync.Once
	finishOnce sync.Once
	closeErr   error
}

func (c *clientConn) Close() error {
	c.closeOnce.Do(func() { c.cancel(); c.closeErr = c.Conn.Close() })
	return c.closeErr
}

func (c *clientConn) finish() {
	c.finishOnce.Do(func() {
		c.Close()
		r := c.registry
		r.mu.Lock()
		delete(r.clients, c.key)
		r.finishIfDrained()
		r.mu.Unlock()
	})
}

func (c *clientConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (c *clientConn) CloseRead() error {
	if cr, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}

type clientListener struct {
	net.Listener
	clients *clientRegistry
}

func (l *clientListener) Accept() (net.Conn, error) {
	if !l.clients.beginAccept() {
		return nil, net.ErrClosed
	}
	defer l.clients.endAccept()
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	owned, ok := l.clients.add(c)
	if !ok {
		c.Close()
		return nil, net.ErrClosed
	}
	return owned, nil
}
