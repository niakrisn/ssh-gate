package main

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// fakeHalfCloseConn is a net.Conn fake with half-close methods.
type fakeHalfCloseConn struct {
	readClosed  bool
	writeClosed bool
	closed      bool
	readErr     error
}

func (f *fakeHalfCloseConn) Read(p []byte) (int, error) {
	if f.readClosed {
		return 0, io.EOF
	}
	if f.readErr != nil {
		return 0, f.readErr
	}
	return copy(p, []byte("xy")), nil
}

func (f *fakeHalfCloseConn) Write(p []byte) (int, error) {
	if f.writeClosed {
		return 0, net.ErrClosed
	}
	return len(p), nil
}

func (f *fakeHalfCloseConn) Close() error                       { f.closed = true; return nil }
func (f *fakeHalfCloseConn) CloseRead() error                   { f.readClosed = true; return nil }
func (f *fakeHalfCloseConn) CloseWrite() error                  { f.writeClosed = true; return nil }
func (f *fakeHalfCloseConn) LocalAddr() net.Addr                { return nil }
func (f *fakeHalfCloseConn) RemoteAddr() net.Addr               { return nil }
func (f *fakeHalfCloseConn) SetDeadline(t time.Time) error      { return nil }
func (f *fakeHalfCloseConn) SetReadDeadline(t time.Time) error  { return nil }
func (f *fakeHalfCloseConn) SetWriteDeadline(t time.Time) error { return nil }

func TestConnTrackerLifecycleClosed(t *testing.T) {
	tr := NewConnTracker(8, time.Minute)
	id := tr.Begin(ConnMeta{Proto: "socks5", Src: "127.0.0.1:1234"}, "example.com", 443)

	active, total, err := tr.List("active", "", "", 1, 50)
	if err != nil || total != 1 || active[0].Status != StateDialing {
		t.Fatalf("dialing list: total=%d err=%v", total, err)
	}

	base := &fakeHalfCloseConn{}
	conn := tr.Done(id, base)
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 16)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	hist, total, err := tr.List("history", "", "", 1, 50)
	if err != nil || total != 1 {
		t.Fatalf("history total=%d err=%v", total, err)
	}
	v := hist[0]
	if v.Status != StateClosed || v.Proto != "socks5" || v.Src != "127.0.0.1:1234" ||
		v.Host != "example.com" || v.Port != 443 || v.Reason != "" {
		t.Fatalf("unexpected record: %+v", v)
	}
	if v.BytesUp != 5 || v.BytesDown != 2 {
		t.Fatalf("bytes: up=%d down=%d", v.BytesUp, v.BytesDown)
	}
	if v.DurationMs < 0 {
		t.Fatalf("duration: %d", v.DurationMs)
	}

	if _, total, _ := tr.List("active", "", "", 1, 50); total != 0 {
		t.Fatalf("active after close: %d", total)
	}
}

func TestConnTrackerErrorOnClose(t *testing.T) {
	tr := NewConnTracker(8, time.Minute)
	id := tr.Begin(ConnMeta{Proto: "http", Src: "127.0.0.1:1"}, "example.com", 443)
	base := &fakeHalfCloseConn{readErr: errors.New("read: connection reset")}
	conn := tr.Done(id, base)
	conn.Read(make([]byte, 4))
	conn.Close()

	hist, total, err := tr.List("history", "", "", 1, 50)
	if err != nil || total != 1 {
		t.Fatalf("history total=%d err=%v", total, err)
	}
	if hist[0].Status != StateError || hist[0].Reason != "read: connection reset" {
		t.Fatalf("record: %+v", hist[0])
	}
}

func TestTrackedConnLiveBytes(t *testing.T) {
	tr := NewConnTracker(8, time.Minute)
	id := tr.Begin(ConnMeta{Proto: "socks5", Src: "127.0.0.1:1"}, "example.com", 443)
	conn := tr.Done(id, &fakeHalfCloseConn{})
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 16)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}

	// the active view must expose live byte counters, not zeros.
	active, total, err := tr.List("active", "", "", 1, 50)
	if err != nil || total != 1 {
		t.Fatalf("active: total=%d err=%v", total, err)
	}
	if active[0].BytesUp != 5 || active[0].BytesDown != 2 {
		t.Fatalf("live bytes: up=%d down=%d, want 5/2", active[0].BytesUp, active[0].BytesDown)
	}
	conn.Close()
}

func TestConnTrackerStalledDialPrune(t *testing.T) {
	tr := NewConnTracker(8, 30*time.Millisecond)
	id := tr.Begin(ConnMeta{}, "stalled.example.com", 443)
	_ = id

	// a dial that neither completes nor fails must not stay active forever.
	time.Sleep(40 * time.Millisecond)

	if _, total, _ := tr.List("active", "", "", 1, 50); total != 0 {
		t.Fatalf("active after stall prune: %d", total)
	}
	hist, total, err := tr.List("history", "", "", 1, 50)
	if err != nil || total != 1 {
		t.Fatalf("history: total=%d err=%v", total, err)
	}
	if hist[0].Status != StateError || hist[0].Reason != "dial timeout" {
		t.Fatalf("record: %+v", hist[0])
	}
}

// TestConnTrackerDoneAfterStalledDrop: a dial that completes after its
// record was pruned by dropStalled must not resurrect a ghost record or
// wrap the connection for a record that no longer exists.
func TestConnTrackerDoneAfterStalledDrop(t *testing.T) {
	tr := NewConnTracker(8, 30*time.Millisecond)
	id := tr.Begin(ConnMeta{}, "stalled.example.com", 443)

	time.Sleep(40 * time.Millisecond)
	if _, total, _ := tr.List("active", "", "", 1, 50); total != 0 {
		t.Fatalf("active after stall prune: %d", total)
	}

	base := &fakeHalfCloseConn{}
	conn := tr.Done(id, base)
	if _, ok := conn.(*trackedConn); ok {
		t.Fatal("late Done wrapped a connection with no record")
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// history keeps the single "dial timeout" record; the late completion
	// must not add a second one.
	hist, total, err := tr.List("history", "", "", 1, 50)
	if err != nil || total != 1 {
		t.Fatalf("history: total=%d err=%v", total, err)
	}
	if hist[0].Status != StateError || hist[0].Reason != "dial timeout" {
		t.Fatalf("record: %+v", hist[0])
	}
}

func TestConnTrackerDialFail(t *testing.T) {
	tr := NewConnTracker(8, time.Minute)
	id := tr.Begin(ConnMeta{Proto: "socks5", Src: "127.0.0.1:1"}, "1.2.3.4", 8443)
	tr.Fail(id, errors.New("dial tcp: connection refused"))

	hist, total, err := tr.List("history", "", "", 1, 50)
	if err != nil || total != 1 {
		t.Fatalf("history total=%d err=%v", total, err)
	}
	if hist[0].Status != StateError || hist[0].Reason != "dial tcp: connection refused" {
		t.Fatalf("record: %+v", hist[0])
	}
}

func TestConnTrackerRingEviction(t *testing.T) {
	tr := NewConnTracker(4, time.Minute)
	for i := 0; i < 6; i++ {
		id := tr.Begin(ConnMeta{Proto: "socks5", Src: "s"}, "h", 1)
		tr.Fail(id, errors.New("boom"))
	}
	hist, total, err := tr.List("history", "", "", 1, 50)
	if err != nil || total != 4 {
		t.Fatalf("total=%d err=%v, want 4", total, err)
	}
	// sorted desc: newest (id 6) first, ids 1 and 2 evicted.
	if hist[0].ID != 6 || hist[3].ID != 3 {
		t.Fatalf("ids: %d..%d, want 6..3", hist[0].ID, hist[3].ID)
	}
}

func TestConnTrackerPruneByAge(t *testing.T) {
	tr := NewConnTracker(8, 30*time.Millisecond)
	id := tr.Begin(ConnMeta{}, "h", 1)
	tr.Fail(id, errors.New("boom"))
	if _, total, _ := tr.List("history", "", "", 1, 50); total != 1 {
		t.Fatalf("before prune: %d", total)
	}
	time.Sleep(40 * time.Millisecond)
	if _, total, _ := tr.List("history", "", "", 1, 50); total != 0 {
		t.Fatalf("after prune: %d", total)
	}
}

func TestConnTrackerListSortDesc(t *testing.T) {
	tr := NewConnTracker(8, time.Minute)
	for i := 0; i < 3; i++ {
		id := tr.Begin(ConnMeta{}, "h", 1)
		tr.Fail(id, errors.New("boom"))
	}
	hist, total, err := tr.List("history", "", "", 1, 50)
	if err != nil || total != 3 {
		t.Fatalf("total=%d err=%v", total, err)
	}
	for i := 1; i < len(hist); i++ {
		if hist[i-1].ID < hist[i].ID {
			t.Fatalf("not sorted desc: %v", hist)
		}
	}
}

func TestConnTrackerQueryFilter(t *testing.T) {
	tr := NewConnTracker(8, time.Minute)
	for _, h := range []string{"Example.com", "example.org", "other.net"} {
		id := tr.Begin(ConnMeta{}, h, 443)
		tr.Fail(id, errors.New("boom"))
	}
	views, total, err := tr.List("history", "EXAMPLE", "", 1, 50)
	if err != nil || total != 2 {
		t.Fatalf("total=%d err=%v, want 2", total, err)
	}
	for _, v := range views {
		if v.Host == "other.net" {
			t.Fatalf("unexpected host %s in results", v.Host)
		}
	}
}

func TestConnTrackerPagination(t *testing.T) {
	tr := NewConnTracker(8, time.Minute)
	for i := 0; i < 3; i++ {
		id := tr.Begin(ConnMeta{}, "h", 1)
		tr.Fail(id, errors.New("boom"))
	}
	views, total, err := tr.List("history", "", "", 2, 2)
	if err != nil || total != 3 || len(views) != 1 {
		t.Fatalf("page 2: total=%d len=%d err=%v", total, len(views), err)
	}
	views, total, err = tr.List("history", "", "", 99, 2)
	if err != nil || total != 3 || len(views) != 0 {
		t.Fatalf("beyond end: total=%d len=%d err=%v", total, len(views), err)
	}
}

func TestConnTrackerActiveByProto(t *testing.T) {
	tr := NewConnTracker(8, time.Minute)
	for _, p := range []string{"socks5", "socks5", "http"} {
		tr.Begin(ConnMeta{Proto: p}, "h", 443)
	}
	if got := tr.ActiveByProto(); got["socks5"] != 2 || got["http"] != 1 || len(got) != 2 {
		t.Fatalf("active by proto: %v", got)
	}
}

// TestConnTrackerActiveByProtoStalledDial: the status counts must not
// include dials that dropStalled has moved to history.
func TestConnTrackerActiveByProtoStalledDial(t *testing.T) {
	tr := NewConnTracker(8, 30*time.Millisecond)
	tr.Begin(ConnMeta{Proto: "socks5"}, "stalled.example.com", 443)
	id := tr.Begin(ConnMeta{Proto: "http"}, "live.example.com", 443)
	tr.Done(id, &fakeHalfCloseConn{})

	time.Sleep(40 * time.Millisecond)

	got := tr.ActiveByProto()
	if got["http"] != 1 || got["socks5"] != 0 || len(got) != 1 {
		t.Fatalf("active by proto after stall: %v", got)
	}
	if _, total, _ := tr.List("active", "", "", 1, 50); total != 1 {
		t.Fatalf("active list after stall: %d", total)
	}
}

func TestConnTrackerProtoFilter(t *testing.T) {
	tr := NewConnTracker(8, time.Minute)
	for _, p := range []string{"socks5", "http", "socks5"} {
		id := tr.Begin(ConnMeta{Proto: p}, "h", 443)
		tr.Fail(id, errors.New("boom"))
	}

	views, total, err := tr.List("history", "", "socks5", 1, 50)
	if err != nil || total != 2 {
		t.Fatalf("socks5: total=%d err=%v, want 2", total, err)
	}
	for _, v := range views {
		if v.Proto != "socks5" {
			t.Fatalf("unexpected proto %s", v.Proto)
		}
	}
	if _, total, _ := tr.List("history", "", "http", 1, 50); total != 1 {
		t.Fatalf("http: total=%d, want 1", total)
	}
	if _, total, _ := tr.List("history", "", "mtproto", 1, 50); total != 0 {
		t.Fatalf("mtproto: total=%d, want 0", total)
	}
}

func TestConnTrackerListValidation(t *testing.T) {
	tr := NewConnTracker(4, time.Minute)
	for _, tc := range []struct {
		tab  string
		page int
		size int
	}{
		{"bogus", 1, 10},
		{"active", 0, 10},
		{"active", 1, 0},
		{"active", 1, 201},
	} {
		if _, _, err := tr.List(tc.tab, "", "", tc.page, tc.size); err == nil {
			t.Fatalf("expected error for tab=%s page=%d size=%d", tc.tab, tc.page, tc.size)
		}
	}
}

func TestTrackedConnHalfCloseForwarding(t *testing.T) {
	tr := NewConnTracker(4, time.Minute)
	id := tr.Begin(ConnMeta{}, "h", 1)
	base := &fakeHalfCloseConn{}
	conn := tr.Done(id, base)

	cw, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("trackedConn lacks CloseWrite")
	}
	if err := cw.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	if !base.writeClosed {
		t.Fatal("CloseWrite not forwarded to base conn")
	}

	cr, ok := conn.(interface{ CloseRead() error })
	if !ok {
		t.Fatal("trackedConn lacks CloseRead")
	}
	if err := cr.CloseRead(); err != nil {
		t.Fatalf("CloseRead: %v", err)
	}
	if !base.readClosed {
		t.Fatal("CloseRead not forwarded to base conn")
	}
}

func TestTrackedConnCloseIdempotent(t *testing.T) {
	tr := NewConnTracker(4, time.Minute)
	id := tr.Begin(ConnMeta{}, "h", 1)
	base := &fakeHalfCloseConn{}
	conn := tr.Done(id, base)
	if err := conn.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if _, total, _ := tr.List("history", "", "", 1, 50); total != 1 {
		t.Fatalf("history=%d, want 1", total)
	}
}

func TestConnMetaCtx(t *testing.T) {
	ctx := ctxWithConnMeta(context.Background(), ConnMeta{Proto: "socks5", Src: "s", Host: "h"})
	meta, ok := connMetaFromCtx(ctx)
	if !ok || meta.Proto != "socks5" || meta.Src != "s" || meta.Host != "h" {
		t.Fatalf("meta=%+v ok=%v", meta, ok)
	}
	if _, ok := connMetaFromCtx(context.Background()); ok {
		t.Fatal("unexpected meta on empty ctx")
	}
}
