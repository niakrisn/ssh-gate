package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type poolTestDialer struct {
	calls atomic.Int32
	peers []net.Conn
}

func (d *poolTestDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	a, b := net.Pipe()
	d.peers = append(d.peers, b)
	d.calls.Add(1)
	return a, nil
}
func (*poolTestDialer) Connected() bool { return true }
func (d *poolTestDialer) stop() {
	for _, p := range d.peers {
		_ = p.Close()
	}
}

func TestSSHTransportPoolChoosesLeastLoadedSlot(t *testing.T) {
	a, b := &poolTestDialer{}, &poolTestDialer{}
	p := newSSHTransportPool(a, b)
	c1, err := p.DialContext(context.Background(), "tcp", "example:443")
	if err != nil {
		t.Fatal(err)
	}
	c2, err := p.DialContext(context.Background(), "tcp", "example:443")
	if err != nil {
		t.Fatal(err)
	}
	if a.calls.Load() != 1 || b.calls.Load() != 1 {
		t.Fatalf("first two dials: slot loads %d/%d", a.calls.Load(), b.calls.Load())
	}
	_ = c1.Close()
	c3, err := p.DialContext(context.Background(), "tcp", "example:443")
	if err != nil {
		t.Fatal(err)
	}
	if a.calls.Load() != 2 || b.calls.Load() != 1 {
		t.Fatalf("after release: slot dials %d/%d", a.calls.Load(), b.calls.Load())
	}
	_ = c2.Close()
	_ = c3.Close()
	a.stop()
	b.stop()
}

// scriptedSlotDialer fails the opens listed in errs, one per call, then
// succeeds. It counts what it was given, so a test can see whether the pool
// retried on the next transport.
type scriptedSlotDialer struct {
	errs  []error
	calls atomic.Int32
}

func (d *scriptedSlotDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	if n := int(d.calls.Add(1)) - 1; n < len(d.errs) {
		return nil, d.errs[n]
	}
	return &fakeHalfCloseConn{}, nil
}
func (*scriptedSlotDialer) Connected() bool { return true }
func (*scriptedSlotDialer) stop()           {}

// TestSSHTransportPoolTriesNextTransport: a transport can still report itself
// connected when one channel open fails, because it dies between the check and
// the open. The request must reach the next live transport of the same server.
func TestSSHTransportPoolTriesNextTransport(t *testing.T) {
	bad := &scriptedSlotDialer{errs: []error{errors.New("connection is shut down")}}
	good := &scriptedSlotDialer{}
	p := newSSHTransportPool(bad, good)
	conn, err := p.DialContext(context.Background(), "tcp", "example:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()
	if bad.calls.Load() != 1 || good.calls.Load() != 1 {
		t.Fatalf("opens bad=%d good=%d, want 1/1", bad.calls.Load(), good.calls.Load())
	}
}

// TestSSHTransportPoolKeepsServerLimitErrors: the pending-open and client-tunnel
// limits belong to the server, so every transport refuses the same way. Passing
// such an open to the next transport only burns the dial budget.
func TestSSHTransportPoolKeepsServerLimitErrors(t *testing.T) {
	first := &scriptedSlotDialer{errs: []error{&pendingOpenLimitError{limit: 2}}}
	second := &scriptedSlotDialer{}
	p := newSSHTransportPool(first, second)
	_, err := p.DialContext(context.Background(), "tcp", "example:443")
	var limit *pendingOpenLimitError
	if !errors.As(err, &limit) {
		t.Fatalf("error = %v, want the pending-open limit", err)
	}
	if second.calls.Load() != 0 {
		t.Fatalf("second transport opened %d times, want 0", second.calls.Load())
	}
}

// TestSSHTransportPoolReturnsLastFailure: when every transport fails, the
// caller gets a failure rather than an empty result, and the search stops after
// one pass over the slots.
func TestSSHTransportPoolReturnsLastFailure(t *testing.T) {
	first := &scriptedSlotDialer{errs: []error{errors.New("first transport down")}}
	second := &scriptedSlotDialer{errs: []error{errors.New("second transport down")}}
	p := newSSHTransportPool(first, second)
	_, err := p.DialContext(context.Background(), "tcp", "example:443")
	if err == nil || err.Error() != "second transport down" {
		t.Fatalf("error = %v, want the last transport failure", err)
	}
	if first.calls.Load() != 1 || second.calls.Load() != 1 {
		t.Fatalf("opens %d/%d, want 1/1", first.calls.Load(), second.calls.Load())
	}
}

// blockingSlotDialer holds every open until the test releases them, so the test
// can see how a burst was spread over the transports.
type blockingSlotDialer struct {
	id      string
	calls   atomic.Int32
	arrived chan<- string
	release <-chan struct{}
}

func (d *blockingSlotDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	d.calls.Add(1)
	select {
	case d.arrived <- d.id:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	<-d.release
	return &fakeHalfCloseConn{}, nil
}
func (*blockingSlotDialer) Connected() bool { return true }
func (*blockingSlotDialer) stop()           {}

// TestSSHTransportPoolSpreadsBurstOverTransports: while one transport is busy,
// the next request must see it busy. Reading the loads and booking the open are
// one step, otherwise a burst reads the same idle counts and piles onto the
// first transport while the others wait.
func TestSSHTransportPoolSpreadsBurstOverTransports(t *testing.T) {
	arrived := make(chan string, 4)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	var dialers []*blockingSlotDialer
	for _, id := range []string{"0", "1"} {
		dialers = append(dialers, &blockingSlotDialer{id: id, arrived: arrived, release: release})
	}
	p := newSSHTransportPool(dialers[0], dialers[1])
	for range 4 {
		go func() {
			if conn, err := p.DialContext(context.Background(), "tcp", "example:443"); err == nil {
				_ = conn.Close()
			}
		}()
	}
	deadline := time.After(5 * time.Second)
	for range 4 {
		select {
		case <-arrived:
		case <-deadline:
			t.Fatal("the burst never reached every transport")
		}
	}
	if a, b := dialers[0].calls.Load(), dialers[1].calls.Load(); a != 2 || b != 2 {
		t.Fatalf("burst spread %d/%d, want 2/2", a, b)
	}
}

func TestSSHDialerSetUsesConnectedPool(t *testing.T) {
	dead := &disconnectedDialer{}
	live := &poolTestDialer{}
	s := &sshDialerSet{pools: []*sshTransportPool{newSSHTransportPool(dead), newSSHTransportPool(live)}}
	c, err := s.DialContext(context.Background(), "tcp", "example:443")
	if err != nil {
		t.Fatal(err)
	}
	if live.calls.Load() != 1 {
		t.Fatalf("live pool calls=%d", live.calls.Load())
	}
	_ = c.Close()
	live.stop()
}

type alwaysConnectedDialer struct{ poolTestDialer }

func (*alwaysConnectedDialer) Connected() bool { return true }

type healthStateDialer struct{ connected atomic.Bool }

func (d *healthStateDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, net.ErrClosed
}
func (d *healthStateDialer) Connected() bool { return d.connected.Load() }
func (*healthStateDialer) stop()             {}

func TestServerSelectionIsStableAndIgnoresClientPort(t *testing.T) {
	makeSet := func(ids ...string) *sshDialerSet {
		s := &sshDialerSet{}
		for _, id := range ids {
			p := newSSHTransportPool(&alwaysConnectedDialer{})
			p.id = id
			s.pools = append(s.pools, p)
		}
		return s
	}
	one := makeSet("edge-a", "edge-b", "edge-c")
	want := one.selectPool("192.0.2.8:41000", "EXAMPLE.COM.", "client_ip_destination")
	if want == nil {
		t.Fatal("no pool selected")
	}
	if got := one.selectPool("192.0.2.8:55000", "example.com", "client_ip_destination"); got != want {
		t.Fatalf("selection changed with client port or host case: %s -> %s", want.id, got.id)
	}
	two := makeSet("edge-c", "edge-a", "edge-b")
	if got := two.selectPool("192.0.2.8:55000", "example.com", "client_ip_destination"); got == nil || got.id != want.id {
		t.Fatalf("selection changed after reorder: got %v, want %s", got, want.id)
	}
}

func TestServerSelectionCanUseClientIPOnly(t *testing.T) {
	s := &sshDialerSet{}
	for _, id := range []string{"edge-a", "edge-b"} {
		p := newSSHTransportPool(&alwaysConnectedDialer{})
		p.id = id
		s.pools = append(s.pools, p)
	}
	if a, b := s.selectPool("192.0.2.8:41000", "one.example", "client_ip"), s.selectPool("192.0.2.8:55000", "two.example", "client_ip"); a != b {
		t.Fatal("client_ip mode changed with destination")
	}
}

func TestPassiveHealthExcludesAfterConfirmedFailures(t *testing.T) {
	h := newServerHealth(3, 30*time.Second, 30*time.Second, 3, 2)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	h.recordProbe(true)
	h.recordProbe(true)
	if excluded, _ := h.confirmedFailure(base); excluded {
		t.Fatal("excluded after one failure")
	}
	if excluded, _ := h.confirmedFailure(base.Add(10 * time.Second)); excluded {
		t.Fatal("excluded after two failures")
	}
	if excluded, _ := h.confirmedFailure(base.Add(20 * time.Second)); !excluded {
		t.Fatal("not excluded after third failure")
	}
	if h.eligible(base.Add(40 * time.Second)) {
		t.Fatal("server became eligible before unhealthy period")
	}
	h.recordProbe(true)
	h.recordProbe(true)
	if !h.eligible(base.Add(51 * time.Second)) {
		t.Fatal("server did not return after unhealthy period")
	}
}

func TestPassiveHealthFailureWindowExpires(t *testing.T) {
	h := newServerHealth(3, 30*time.Second, 30*time.Second, 3, 2)
	base := time.Now()
	if excluded, _ := h.confirmedFailure(base); excluded {
		t.Fatal("excluded after first failure")
	}
	if excluded, _ := h.confirmedFailure(base.Add(31 * time.Second)); excluded {
		t.Fatal("old failure was not discarded")
	}
}

func TestActiveHealthRequiresSuccessesAndExcludesAfterFailures(t *testing.T) {
	h := newServerHealth(3, 30*time.Second, 30*time.Second, 3, 2)
	now := time.Now()
	if h.eligible(now) {
		t.Fatal("server was eligible before active checks")
	}
	h.recordProbe(true)
	if h.eligible(now) {
		t.Fatal("server was eligible after one success")
	}
	h.recordProbe(true)
	if !h.eligible(now) {
		t.Fatal("server was not eligible after two successes")
	}
	h.recordProbe(false)
	h.recordProbe(false)
	if !h.eligible(now) {
		t.Fatal("server was excluded before three failed checks")
	}
	h.recordProbe(false)
	if h.eligible(now) {
		t.Fatal("server remained eligible after three failed checks")
	}
	h.recordProbe(true)
	if h.eligible(now) {
		t.Fatal("server was eligible after one recovery success")
	}
	h.recordProbe(true)
	if !h.eligible(now) {
		t.Fatal("server was not eligible after two recovery successes")
	}
}

func TestSSHServerStatusIncludesLimitsAndTransportStats(t *testing.T) {
	p := &sshTransportPool{
		id: "edge-a", host: "ssh-a.example.net", port: 22, user: "tunnel",
		quota:  newServerQuota(4096, 256, 32),
		health: newServerHealth(3, 30*time.Second, 30*time.Second, 3, 2),
		slots:  []*transportSlot{{dialer: testDialer{}, index: 0}},
	}
	p.health.recordProbe(true)
	p.health.recordProbe(true)
	status := p.status()
	if status.ID != "edge-a" || status.Address != "tunnel@ssh-a.example.net:22" || !status.Eligible || status.State != "healthy" {
		t.Fatalf("server status = %+v", status)
	}
	if status.Limits.ClientTunnels != 4096 || status.Limits.PendingOpens != 256 || status.Limits.ServiceOpens != 32 {
		t.Fatalf("limits = %+v", status.Limits)
	}
	if len(status.Transports) != 1 || !status.Transports[0].Connected || status.Transports[0].TCP == nil || status.Transports[0].TCP.RTTMs != 42 {
		t.Fatalf("transport status = %+v", status.Transports)
	}
}

func TestLosingLastTransportRequiresNewHealthChecks(t *testing.T) {
	h := newServerHealth(3, 30*time.Second, 30*time.Second, 3, 2)
	h.recordProbe(true)
	h.recordProbe(true)
	d := &healthStateDialer{}
	d.connected.Store(true)
	p := &sshTransportPool{id: "edge-a", health: h, slots: []*transportSlot{{dialer: d}}}
	if !p.eligible() {
		t.Fatal("connected and checked pool should be eligible before loss")
	}
	d.connected.Store(false)
	p.transportFailed(0)
	if p.eligible() {
		t.Fatal("pool became eligible after losing its last transport")
	}
	if h.probeSuccesses != 0 {
		t.Fatalf("probe successes = %d, want reset after last transport loss", h.probeSuccesses)
	}
}

func TestStartProxiesWithTransportsDroppingDuringStartup(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	server := &ssh.ServerConfig{NoClientAuth: true}
	server.AddHostKey(newTestHostSigner(t))
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				ssh.NewServerConn(conn, server)
			}()
		}
	}()

	dataDir := t.TempDir()
	if err := os.Rename(writeTestKey(t), filepath.Join(dataDir, sshKeyFile)); err != nil {
		t.Fatal(err)
	}
	host, port := splitTestAddr(t, ln.Addr().String())
	cfg := config{dataDir: dataDir, passiveMaxFails: 1000, passiveFailTimeout: time.Minute}
	cfg.sshServers = []sshServerConfig{{
		id: "edge-a", host: host, port: port, user: "test", transports: 128,
		maxClientTunnels: 1, maxPendingOpens: 1, maxPendingServiceOpens: 1,
	}}
	lost := make(chan struct{}, 1)
	status := &sdStatus{notify: func(message string) error {
		if strings.Contains(message, "lost, reconnecting") {
			select {
			case lost <- struct{}{}:
			default:
			}
		}
		return nil
	}}
	d, rules, _ := startProxies(cfg, nil, status)
	t.Cleanup(rules.Stop)
	t.Cleanup(d.stop)
	select {
	case <-lost:
	case <-time.After(3 * time.Second):
		t.Fatal("none of the transports reported a lost connection")
	}
}
