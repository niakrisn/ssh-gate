package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ConnState is the lifecycle state of a tracked SSH-tunneled connection.
type ConnState string

const (
	StateDialing ConnState = "dialing"
	StateActive  ConnState = "active"
	StateClosed  ConnState = "closed"
	StateError   ConnState = "error"
)

// ConnMeta carries proxy-side connection metadata through the dial context.
type ConnMeta struct {
	Proto string
	Src   string
	Host  string
	// DstIP is the IP the tunnel is actually dialed to (filled by trackDial
	// when the dial address is an IP literal); empty when the destination is
	// an FQDN resolved on the VPS side.
	DstIP string
}

// ConnView is the JSON representation of a connection record.
type ConnView struct {
	ID         uint64    `json:"id"`
	Proto      string    `json:"proto"`
	Src        string    `json:"src"`
	Host       string    `json:"host"`
	DstIP      string    `json:"dst_ip"`
	Port       int       `json:"port"`
	Status     ConnState `json:"status"`
	StartedAt  int64     `json:"started_at"`
	DurationMs int64     `json:"duration_ms"`
	BytesUp    int64     `json:"bytes_up"`
	BytesDown  int64     `json:"bytes_down"`
	Reason     string    `json:"reason"`
}

type connRecord struct {
	id        uint64
	proto     string
	src       string
	host      string
	dstIP     string
	port      int
	status    ConnState
	startedAt time.Time
	closedAt  time.Time
	bytesUp   int64
	bytesDown int64
	reason    string
	live      *trackedConn
}

// ConnTracker keeps active SSH-tunneled connections and a ring buffer of
// finished ones. In-memory only: everything is lost on restart.
type ConnTracker struct {
	mu        sync.Mutex
	active    map[uint64]*connRecord
	ring      []connRecord
	ringHead  int
	ringCount int
	capacity  int
	maxAge    time.Duration
	nextID    uint64
}

func NewConnTracker(capacity int, maxAge time.Duration) *ConnTracker {
	if capacity <= 0 {
		capacity = 1000
	}
	return &ConnTracker{
		active:   make(map[uint64]*connRecord),
		ring:     make([]connRecord, capacity),
		capacity: capacity,
		maxAge:   maxAge,
	}
}

// Begin registers a connection in dialing state and returns its id.
func (t *ConnTracker) Begin(meta ConnMeta, host string, port int) uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.nextID++
	t.active[t.nextID] = &connRecord{
		id:        t.nextID,
		proto:     meta.Proto,
		src:       meta.Src,
		host:      host,
		dstIP:     meta.DstIP,
		port:      port,
		status:    StateDialing,
		startedAt: time.Now(),
	}
	return t.nextID
}

// Done marks the connection active and returns it wrapped for byte counting
// and close tracking. If the record left the active map while the dial was
// in flight (dropStalled), the connection is returned untracked: there is no
// record left to resurrect.
func (t *ConnTracker) Done(id uint64, conn net.Conn) net.Conn {
	if conn == nil {
		return conn
	}
	tc := &trackedConn{t: t, id: id, Conn: conn}
	t.mu.Lock()
	rec, ok := t.active[id]
	if ok {
		rec.status = StateActive
		rec.live = tc
	}
	t.mu.Unlock()
	if !ok {
		return conn
	}
	return tc
}

// Fail records a dial error and moves the record to history.
func (t *ConnTracker) Fail(id uint64, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	rec, ok := t.active[id]
	if !ok {
		return
	}
	delete(t.active, id)
	rec.status = StateError
	rec.reason = err.Error()
	rec.closedAt = time.Now()
	t.pushRing(rec)
}

// ActiveByProto returns the number of active connections (dialing or
// established) per protocol. Stalled dials are moved to history first,
// matching the "active" view of List.
func (t *ConnTracker) ActiveByProto() map[string]int {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.dropStalled(time.Now())
	m := make(map[string]int)
	for _, r := range t.active {
		m[r.proto]++
	}
	return m
}

// List returns a page of connections: "active" (live) or "history"
// (ring buffer) tab. q is a case-insensitive substring filter on host,
// dialed IP and source address; proto is an exact protocol filter
// (socks5, http, mtproto); empty values disable the filters.
func (t *ConnTracker) List(tab, q, proto string, page, pageSize int) ([]ConnView, int, error) {
	if tab != "active" && tab != "history" {
		return nil, 0, fmt.Errorf("invalid tab %q (active|history)", tab)
	}
	if page < 1 {
		return nil, 0, fmt.Errorf("page must be >= 1")
	}
	if pageSize < 1 || pageSize > 200 {
		return nil, 0, fmt.Errorf("page_size must be in 1..200")
	}

	t.mu.Lock()
	now := time.Now()
	t.pruneRing(now)
	t.dropStalled(now)
	recs := make([]connRecord, 0, len(t.active)+t.ringCount)
	if tab == "active" {
		for _, r := range t.active {
			recs = append(recs, *r)
		}
	} else {
		for i := 0; i < t.ringCount; i++ {
			recs = append(recs, t.ring[(t.ringHead+i)%t.capacity])
		}
	}
	t.mu.Unlock()

	if q != "" {
		fq := strings.ToLower(q)
		filtered := make([]connRecord, 0, len(recs))
		for _, r := range recs {
			if strings.Contains(strings.ToLower(r.host), fq) ||
				strings.Contains(strings.ToLower(r.dstIP), fq) ||
				strings.Contains(strings.ToLower(r.src), fq) {
				filtered = append(filtered, r)
			}
		}
		recs = filtered
	}
	if proto != "" {
		filtered := make([]connRecord, 0, len(recs))
		for _, r := range recs {
			if r.proto == proto {
				filtered = append(filtered, r)
			}
		}
		recs = filtered
	}

	sort.Slice(recs, func(i, j int) bool {
		if !recs[i].startedAt.Equal(recs[j].startedAt) {
			return recs[i].startedAt.After(recs[j].startedAt)
		}
		return recs[i].id > recs[j].id
	})

	total := len(recs)
	start := (page - 1) * pageSize
	if start >= total {
		return []ConnView{}, total, nil
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	views := make([]ConnView, 0, end-start)
	for _, r := range recs[start:end] {
		views = append(views, toView(r, now))
	}
	return views, total, nil
}

// pushRing appends a record to the ring buffer, overwriting the oldest.
// Call with mu held.
func (t *ConnTracker) pushRing(rec *connRecord) {
	t.pruneRing(time.Now())
	idx := (t.ringHead + t.ringCount) % t.capacity
	if t.ringCount == t.capacity {
		idx = t.ringHead
		t.ringHead = (t.ringHead + 1) % t.capacity
	} else {
		t.ringCount++
	}
	t.ring[idx] = *rec
}

// pruneRing drops history records older than maxAge.
// Call with mu held.
func (t *ConnTracker) pruneRing(now time.Time) {
	for t.ringCount > 0 {
		oldest := t.ring[t.ringHead]
		if now.Sub(oldest.closedAt) <= t.maxAge {
			break
		}
		t.ringHead = (t.ringHead + 1) % t.capacity
		t.ringCount--
	}
}

// dropStalled moves dialing records older than maxAge to history as errors.
// It does not cancel the dial itself (the dialer owns that); it only bounds
// the active view and the in-memory state. Call with mu held.
func (t *ConnTracker) dropStalled(now time.Time) {
	for id, rec := range t.active {
		if rec.status == StateDialing && now.Sub(rec.startedAt) > t.maxAge {
			delete(t.active, id)
			rec.status = StateError
			rec.reason = "dial timeout"
			rec.closedAt = now
			t.pushRing(rec)
		}
	}
}

// finish moves a finished connection to history.
func (t *ConnTracker) finish(id uint64, bytesUp, bytesDown int64, firstErr error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	rec, ok := t.active[id]
	if !ok {
		return
	}
	delete(t.active, id)
	rec.status = StateClosed
	if firstErr != nil {
		rec.status = StateError
		rec.reason = firstErr.Error()
	}
	rec.bytesUp = bytesUp
	rec.bytesDown = bytesDown
	rec.closedAt = time.Now()
	t.pushRing(rec)
}

// trackedConn wraps a tunneled connection: counts bytes, remembers the first
// I/O error, and moves the record to history on Close.
type trackedConn struct {
	net.Conn
	t        *ConnTracker
	id       uint64
	mu       sync.Mutex
	up       int64
	down     int64
	firstErr error
	closed   atomic.Bool
}

func (c *trackedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.mu.Lock()
		c.down += int64(n)
		c.mu.Unlock()
	}
	if !isBenignCloseErr(err) {
		c.mu.Lock()
		if c.firstErr == nil {
			c.firstErr = err
		}
		c.mu.Unlock()
	}
	return n, err
}

func (c *trackedConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.mu.Lock()
		c.up += int64(n)
		c.mu.Unlock()
	}
	if !isBenignCloseErr(err) {
		c.mu.Lock()
		if c.firstErr == nil {
			c.firstErr = err
		}
		c.mu.Unlock()
	}
	return n, err
}

// Close is idempotent: a second call delegates to the base conn, and the
// history record is created once.
func (c *trackedConn) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return c.Conn.Close()
	}
	err := c.Conn.Close()
	c.mu.Lock()
	up, down, firstErr := c.up, c.down, c.firstErr
	c.mu.Unlock()
	c.t.finish(c.id, up, down, firstErr)
	return err
}

// CloseRead forwards to the base conn if it supports half-close;
// netConnToEssentials (dialer.go) relies on these methods for MTProto.
func (c *trackedConn) CloseRead() error {
	if cr, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}

// CloseWrite forwards to the base conn if it supports half-close.
func (c *trackedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// isBenignCloseErr reports routine close errors that should not mark a
// connection as failed.
func isBenignCloseErr(err error) bool {
	if err == nil {
		return true
	}
	return errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed)
}

// bytes returns the current byte counters.
func (c *trackedConn) bytes() (int64, int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.up, c.down
}

func toView(r connRecord, now time.Time) ConnView {
	up, down := r.bytesUp, r.bytesDown
	if r.live != nil && (r.status == StateActive || r.status == StateDialing) {
		up, down = r.live.bytes()
	}
	dur := now.Sub(r.startedAt).Milliseconds()
	if r.status == StateClosed || r.status == StateError {
		dur = r.closedAt.Sub(r.startedAt).Milliseconds()
	}
	return ConnView{
		ID:         r.id,
		Proto:      r.proto,
		Src:        r.src,
		Host:       r.host,
		DstIP:      r.dstIP,
		Port:       r.port,
		Status:     r.status,
		StartedAt:  r.startedAt.Unix(),
		DurationMs: dur,
		BytesUp:    up,
		BytesDown:  down,
		Reason:     r.reason,
	}
}

type connMetaKey struct{}

// ctxWithConnMeta attaches connection metadata to the dial context.
func ctxWithConnMeta(ctx context.Context, meta ConnMeta) context.Context {
	return context.WithValue(ctx, connMetaKey{}, meta)
}

// connMetaFromCtx returns the metadata attached by ctxWithConnMeta.
func connMetaFromCtx(ctx context.Context) (ConnMeta, bool) {
	meta, ok := ctx.Value(connMetaKey{}).(ConnMeta)
	return meta, ok
}
