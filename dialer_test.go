package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

// startTestSSHServer starts an in-process SSH server. It accepts any
// publickey; when acceptChannels is true it accepts incoming channels
// (without forwarding), otherwise it leaves channel open requests pending
// forever — a model of a VPS sshd stuck in its destination dial. When
// drainRequests is true global requests get the default reply (a failure
// response, proving liveness); when false they are never answered — a model
// of a transport with a live TCP but a stuck request layer.
func startTestSSHServer(t *testing.T, listenAddr string, acceptChannels, drainRequests bool) (addr string, clientSigner ssh.Signer) {
	t.Helper()

	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromSigner(hostPriv)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}
	_, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	clientSigner, err = ssh.NewSignerFromSigner(clientPriv)
	if err != nil {
		t.Fatalf("client signer: %v", err)
	}

	serverCfg := &ssh.ServerConfig{
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, nil
		},
	}
	serverCfg.AddHostKey(hostSigner)

	if listenAddr == "" {
		listenAddr = "127.0.0.1:0"
	}
	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { l.Close() })

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				sconn, chans, reqs, err := ssh.NewServerConn(conn, serverCfg)
				if err != nil {
					return
				}
				defer sconn.Close()
				if drainRequests {
					go ssh.DiscardRequests(reqs)
				}
				for newCh := range chans {
					if !acceptChannels {
						continue // leave the open request pending
					}
					ch, requests, err := newCh.Accept()
					if err != nil {
						return
					}
					go ssh.DiscardRequests(requests)
					_ = ch
				}
			}()
		}
	}()

	return l.Addr().String(), clientSigner
}

func connectTestSSHClient(t *testing.T, addr string, signer ssh.Signer) *ssh.Client {
	t.Helper()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
		User:            "test",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatalf("client conn: %v", err)
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	t.Cleanup(func() { client.Close() })
	return client
}

func TestTrackDialMetaHostPriority(t *testing.T) {
	tr := NewConnTracker(8, time.Minute)
	d := &sshDialer{cfg: sshDialerCfg{tracker: tr}}
	ctx := ctxWithConnMeta(context.Background(), ConnMeta{Proto: "socks5", Src: "10.0.0.5:4321", Host: "example.com"})

	if _, err := d.DialContext(ctx, "tcp", "1.2.3.4:443"); err == nil {
		t.Fatal("want dial error (no SSH client)")
	}

	hist, total, err := tr.List("history", "", "", 1, 50)
	if err != nil || total != 1 {
		t.Fatalf("history total=%d err=%v", total, err)
	}
	v := hist[0]
	// meta.Host wins over the resolved IP from addr; port comes from addr.
	if v.Host != "example.com" || v.Port != 443 || v.Proto != "socks5" || v.Src != "10.0.0.5:4321" {
		t.Fatalf("record: %+v", v)
	}
	if v.Status != StateError || v.Reason == "" {
		t.Fatalf("record: %+v", v)
	}
}

func TestTrackDialAddrFallback(t *testing.T) {
	tr := NewConnTracker(8, time.Minute)
	d := &sshDialer{cfg: sshDialerCfg{tracker: tr}}

	if _, err := d.DialContext(context.Background(), "tcp", "9.9.9.9:53"); err == nil {
		t.Fatal("want dial error (no SSH client)")
	}

	hist, total, err := tr.List("history", "", "", 1, 50)
	if err != nil || total != 1 {
		t.Fatalf("history total=%d err=%v", total, err)
	}
	// no metadata: host and port come from addr.
	if hist[0].Host != "9.9.9.9" || hist[0].Port != 53 {
		t.Fatalf("record: %+v", hist[0])
	}
}

// TestTrackDialV6DstIP: a bracketed IPv6 dial address must land in history
// as the dialed IP (the tunnel resolves client-side, so the VPS dials this
// literal and the tracker must record it).
func TestTrackDialV6DstIP(t *testing.T) {
	tr := NewConnTracker(8, time.Minute)
	d := &sshDialer{cfg: sshDialerCfg{tracker: tr}}
	// DstIP is only filled for tracked proxy dials, which always carry
	// ConnMeta; an empty Host keeps the literal as the record host.
	ctx := ctxWithConnMeta(context.Background(), ConnMeta{Proto: "socks5", Src: "10.0.0.5:4321"})

	if _, err := d.DialContext(ctx, "tcp", "[2001:db8::1]:443"); err == nil {
		t.Fatal("want dial error (no SSH client)")
	}

	hist, total, err := tr.List("history", "", "", 1, 50)
	if err != nil || total != 1 {
		t.Fatalf("history total=%d err=%v", total, err)
	}
	if hist[0].Host != "2001:db8::1" || hist[0].Port != 443 || hist[0].DstIP != "2001:db8::1" {
		t.Fatalf("record: %+v", hist[0])
	}
}

func TestTrackDialNoTracker(t *testing.T) {
	d := &sshDialer{cfg: sshDialerCfg{}}

	// tracker == nil: the dial goes through without the tracker, without a panic.
	if _, err := d.DialContext(context.Background(), "tcp", "9.9.9.9:53"); err == nil {
		t.Fatal("want dial error (no SSH client)")
	}
}

// TestTrackDialNoTrack: a dial marked with ctxWithNoTrack (the DoH
// transport) must not register a tracker record.
func TestTrackDialNoTrack(t *testing.T) {
	tr := NewConnTracker(8, time.Minute)
	d := &sshDialer{cfg: sshDialerCfg{tracker: tr}}

	if _, err := d.DialContext(ctxWithNoTrack(context.Background()), "tcp", "9.9.9.9:53"); err == nil {
		t.Fatal("want dial error (no SSH client)")
	}

	hist, total, err := tr.List("history", "", "", 1, 50)
	if err != nil || total != 0 || len(hist) != 0 {
		t.Fatalf("history total=%d err=%v, want none", total, err)
	}
}

func TestTrackDialSuccessLifecycle(t *testing.T) {
	addr, signer := startTestSSHServer(t, "", true, true)
	client := connectTestSSHClient(t, addr, signer)
	tr := NewConnTracker(8, time.Minute)
	d := &sshDialer{client: client, cfg: sshDialerCfg{tracker: tr}}

	ctx := ctxWithConnMeta(context.Background(), ConnMeta{Proto: "socks5", Src: "10.0.0.5:4321", Host: "example.com"})
	conn, err := d.DialContext(ctx, "tcp", "127.0.0.1:9")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	active, total, err := tr.List("active", "", "", 1, 50)
	if err != nil || total != 1 || active[0].Status != StateActive {
		t.Fatalf("active: total=%d err=%v", total, err)
	}
	if active[0].Host != "example.com" || active[0].Port != 9 {
		t.Fatalf("active record: %+v", active[0])
	}
	// the dial address is an IP literal: the record must keep it as DstIP.
	if active[0].DstIP != "127.0.0.1" {
		t.Fatalf("dst_ip = %q, want 127.0.0.1", active[0].DstIP)
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	hist, total, err := tr.List("history", "", "", 1, 50)
	if err != nil || total != 1 || hist[0].Status != StateClosed {
		t.Fatalf("history: total=%d err=%v", total, err)
	}
}

// TestSSHDialerDialTimeout: a destination dial that never completes
// (channel open left pending by the "sshd") must be cut off by the
// configured timeout and land in history as an error, not hang forever.
func TestSSHDialerDialTimeout(t *testing.T) {
	addr, signer := startTestSSHServer(t, "", false, true)
	client := connectTestSSHClient(t, addr, signer)
	tr := NewConnTracker(8, time.Minute)
	d := &sshDialer{client: client, cfg: sshDialerCfg{tracker: tr, dialTimeout: 300 * time.Millisecond}}

	start := time.Now()
	_, err := d.DialContext(context.Background(), "tcp", "10.255.255.1:443")
	elapsed := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("dial took %s, timeout not enforced promptly", elapsed)
	}

	hist, total, err := tr.List("history", "", "", 1, 50)
	if err != nil || total != 1 {
		t.Fatalf("history: total=%d err=%v", total, err)
	}
	if hist[0].Status != StateError || hist[0].Reason == "" {
		t.Fatalf("record: %+v", hist[0])
	}
}

// TestSSHDialerDialTimeoutSurvivingConn: the dial timeout bounds the dial
// only; a connection established before the deadline must stay usable after
// the deadline passes (the dial context must not outlive the dial).
func TestSSHDialerDialTimeoutSurvivingConn(t *testing.T) {
	addr, signer := startTestSSHServer(t, "", true, true)
	client := connectTestSSHClient(t, addr, signer)
	tr := NewConnTracker(8, time.Minute)
	d := &sshDialer{client: client, cfg: sshDialerCfg{tracker: tr, dialTimeout: 200 * time.Millisecond}}

	conn, err := d.DialContext(context.Background(), "tcp", "127.0.0.1:9")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Past the dial deadline: the channel must still accept writes.
	time.Sleep(300 * time.Millisecond)
	if _, err := conn.Write([]byte("alive")); err != nil {
		t.Fatalf("write after deadline: %v", err)
	}
}

// TestTunnelTCPStatsAbsent: without a tunnel connection the stats must be
// nil, not a zero-value struct (the status API reports "tcp": null).
func TestTunnelTCPStatsAbsent(t *testing.T) {
	d := &sshDialer{}
	if s := d.TunnelTCPStats(); s != nil {
		t.Fatalf("stats = %+v, want nil", s)
	}
}

// TestConnectSSHCapturesRawConn: the SSH dial must capture the TCP
// connection's RawConn — the handle /api/status reads tcp_info through.
// A regression to a plain net.DialTimeout would silently yield a nil
// handle and "tcp": null in the status API.
func TestConnectSSHCapturesRawConn(t *testing.T) {
	addr, _ := startTestSSHServer(t, "", false, true)

	// The test server accepts any publickey, so a freshly generated
	// client key is fine; connectSSH reads it from disk.
	_, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	keyBlock, err := ssh.MarshalPrivateKey(clientPriv, "test")
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(keyBlock)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port: %v", err)
	}

	client, fp, raw, err := connectSSH(sshDialerCfg{
		host:    host,
		port:    port,
		user:    "test",
		keyPath: keyPath,
	})
	if err != nil {
		t.Fatalf("connectSSH: %v", err)
	}
	defer client.Close()

	if fp == "" {
		t.Fatal("fingerprint empty, want the host key")
	}
	if raw == nil {
		t.Fatal("RawConn nil, want the captured tunnel fd handle")
	}
}

// TestConnectSSHKeepaliveProbeOpts: connectSSH must apply the configured
// keepalive retransmission parameters to the tunnel socket — Go's net
// package exposes only the idle period, so a regression here would silently
// fall back to the kernel's 75 s / 9 probes.
func TestConnectSSHKeepaliveProbeOpts(t *testing.T) {
	addr, _ := startTestSSHServer(t, "", false, true)

	_, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	keyBlock, err := ssh.MarshalPrivateKey(clientPriv, "test")
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(keyBlock), 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port: %v", err)
	}

	client, _, raw, err := connectSSH(sshDialerCfg{
		host:              host,
		port:              port,
		user:              "test",
		keyPath:           keyPath,
		keepalivePeriod:   10 * time.Second,
		keepaliveInterval: 1,
		keepaliveProbes:   5,
	})
	if err != nil {
		t.Fatalf("connectSSH: %v", err)
	}
	defer client.Close()

	if raw == nil {
		t.Fatal("RawConn nil, want the captured tunnel fd handle")
	}
	var interval, probes int
	var getErr error
	err = raw.Control(func(fd uintptr) {
		i, e := unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_KEEPINTVL)
		if e != nil {
			getErr = e
			return
		}
		interval = i
		p, e := unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_KEEPCNT)
		if e != nil {
			getErr = e
			return
		}
		probes = p
	})
	if err != nil || getErr != nil {
		t.Fatalf("read back keepalive options: %v %v", err, getErr)
	}
	// The raw option value uses the platform unit (seconds on Linux,
	// milliseconds on macOS); convert to seconds before comparing.
	if got := time.Duration(interval) * keepaliveIntervalUnit(); got != time.Second {
		t.Errorf("TCP_KEEPINTVL = %v, want 1s", got)
	}
	if probes != 5 {
		t.Errorf("TCP_KEEPCNT = %d, want 5", probes)
	}
}

// TestMonitorSurvivesReconnectFailure: a dropped tunnel followed by failing
// reconnect rounds must not crash the process. A regression to reading
// d.client.Conn (nil embedded deref after a failed reconnect) panics on the
// second monitor iteration and kills the whole test binary.
func TestMonitorSurvivesReconnectFailure(t *testing.T) {
	addr, signer := startTestSSHServer(t, "", true, true)
	client := connectTestSSHClient(t, addr, signer)

	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("dead listener: %v", err)
	}
	deadAddr := dead.Addr().String()
	dead.Close()
	deadHost, deadPortStr, err := net.SplitHostPort(deadAddr)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	deadPort, err := strconv.Atoi(deadPortStr)
	if err != nil {
		t.Fatalf("port: %v", err)
	}

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519")
	_, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	keyBlock, err := ssh.MarshalPrivateKey(clientPriv, "test")
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(keyBlock), 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	d := &sshDialer{cfg: sshDialerCfg{
		host:    deadHost,
		port:    deadPort,
		user:    "test",
		keyPath: keyPath,
	}}
	d.client = client
	go d.monitor()
	t.Cleanup(d.stop)

	client.Close() // tunnel drops: monitor must survive nil-client reconnect rounds

	// Two backoff rounds (1 s, then 2 s, each + jitter) fail against the
	// dead address; the old code panicked already on the first round.
	time.Sleep(3500 * time.Millisecond)
	if d.Connected() {
		t.Fatal("want disconnected against a dead address")
	}
}

// writeTestKey generates a throwaway ed25519 private key in a temp dir and
// returns its path (connectSSH reads the key from disk).
func writeTestKey(t *testing.T) string {
	t.Helper()
	_, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	keyBlock, err := ssh.MarshalPrivateKey(clientPriv, "test")
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(keyBlock), 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return keyPath
}

// TestConnectSSHHandshakeTimeout: a server that accepts TCP but never
// speaks the SSH version string must not wedge connectSSH forever.
// x/crypto bounds only the TCP dial, so without the explicit handshake
// deadline connectSSH blocks until the test timeout.
func TestConnectSSHHandshakeTimeout(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	// Accept and hold the connection silently — no SSH ident, no KEX.
	held := make(chan net.Conn, 1)
	go func() {
		conn, err := l.Accept()
		if err == nil {
			held <- conn
		}
	}()

	host, portStr, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port: %v", err)
	}

	start := time.Now()
	client, _, _, err := connectSSH(sshDialerCfg{
		host:             host,
		port:             port,
		user:             "test",
		keyPath:          writeTestKey(t),
		handshakeTimeout: 200 * time.Millisecond,
	})
	elapsed := time.Since(start)

	select {
	case c := <-held:
		c.Close()
	case <-time.After(2 * time.Second):
	}

	if err == nil {
		client.Close()
		t.Fatal("want handshake error, got nil")
	}
	if elapsed > 3*time.Second {
		t.Fatalf("handshake timeout not enforced: took %s", elapsed)
	}
	if !strings.Contains(err.Error(), "handshake") {
		t.Errorf("err = %v, want it to mention handshake", err)
	}
}

func TestParseDialAddr(t *testing.T) {
	for _, tc := range []struct {
		addr, host string
		port       int
	}{
		{"1.2.3.4:443", "1.2.3.4", 443},
		{"[::1]:80", "::1", 80},
		{"[2001:db8::1]:443", "2001:db8::1", 443},
		{"example.com", "example.com", 0},
		{"example.com:bad", "example.com", 0},
	} {
		host, port := parseDialAddr(tc.addr)
		if host != tc.host || port != tc.port {
			t.Fatalf("parseDialAddr(%q) = (%q, %d), want (%q, %d)", tc.addr, host, port, tc.host, tc.port)
		}
	}
}

// TestKeepaliveKeepsLiveTunnel: with a server that answers global requests,
// the app-level keepalive probe must keep the transport alive across several
// probe cycles (a false-positive drop would kill a healthy tunnel).
func TestKeepaliveKeepsLiveTunnel(t *testing.T) {
	addr, signer := startTestSSHServer(t, "", true, true)
	client := connectTestSSHClient(t, addr, signer)

	d := &sshDialer{cfg: sshDialerCfg{keepalivePeriod: 50 * time.Millisecond}}
	d.client = client
	go d.keepalive(client)

	waited := make(chan struct{})
	go func() {
		client.Wait()
		close(waited)
	}()
	select {
	case <-waited:
		t.Fatal("transport closed: keepalive dropped a live tunnel")
	case <-time.After(300 * time.Millisecond):
		// 5-6 probe cycles survived: the tunnel is healthy.
	}
}

// TestKeepaliveDropsStuckTransport: when global requests go unanswered,
// the probe must get no reply within one period and close the transport, so
// Connected()/readyz stop lying about a dead tunnel.
func TestKeepaliveDropsStuckTransport(t *testing.T) {
	addr, signer := startTestSSHServer(t, "", true, false)
	client := connectTestSSHClient(t, addr, signer)

	d := &sshDialer{cfg: sshDialerCfg{keepalivePeriod: 50 * time.Millisecond}}
	d.client = client
	go d.keepalive(client)

	waited := make(chan struct{})
	go func() {
		client.Wait()
		close(waited)
	}()
	select {
	case <-waited:
		// the stuck transport was dropped as required
	case <-time.After(2 * time.Second):
		t.Fatal("stuck transport still open after 2 s, keepalive never dropped it")
	}
}

// TestDialerLazyStartAndRecovery: a dead VPS at construction time must not
// fail newSSHDialer (on v0.1.0 this is the fatal-restart path: the proxies
// and the Web UI never start and compose loops the container). The dialer
// must come up disconnected and the monitor must connect on its own once
// the endpoint appears.
func TestDialerLazyStartAndRecovery(t *testing.T) {
	// Occupy a port and free it: an address with nothing listening.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	host, portStr, err := net.SplitHostPort(probe.Addr().String())
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	probe.Close()
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port: %v", err)
	}

	d, err := newSSHDialer(sshDialerCfg{
		host:    host,
		port:    port,
		user:    "test",
		keyPath: writeTestKey(t),
	})
	if err != nil {
		t.Fatalf("newSSHDialer against a dead endpoint: %v", err)
	}
	t.Cleanup(d.stop)
	if d.Connected() {
		t.Fatal("Connected() true before any SSH server exists")
	}

	// The endpoint appears: the monitor's backoff must pick it up.
	startTestSSHServer(t, net.JoinHostPort(host, portStr), true, true)
	deadline := time.Now().Add(5 * time.Second)
	for !d.Connected() && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if !d.Connected() {
		t.Fatal("monitor did not connect within 5 s of the endpoint appearing")
	}
}

// TestReconnectDelayBounds: the backoff must stay positive and capped for
// any attempt number. The v0.1.0 expression `baseDelay << uint(attempt)`
// overflows int64 nanoseconds from attempt 34 on (1s<<34 wraps negative,
// >=64 shifts to 0), so the cap test below fails on it; a negative delay
// makes the monitor's Sleep return instantly and turns reconnect against a
// day-long VPS outage into a busy loop that floods the log and hammers the
// moment the VPS is back.
func TestReconnectDelayBounds(t *testing.T) {
	// Monotone, > 0, and never above the cap across the overflow boundary.
	prev := time.Duration(0)
	for _, attempt := range []int{0, 1, 5, 6, 33, 34, 1000} {
		delay := reconnectDelay(attempt)
		if delay <= 0 {
			t.Fatalf("reconnectDelay(%d) = %v, want > 0", attempt, delay)
		}
		if delay > 60*time.Second {
			t.Fatalf("reconnectDelay(%d) = %v, want <= 60 s", attempt, delay)
		}
		if attempt > 0 && delay < prev {
			t.Fatalf("reconnectDelay(%d) = %v shrank from %v", attempt, delay, prev)
		}
		prev = delay
	}

	// Exact steps below the cap: doubling per attempt.
	for attempt, want := range map[int]time.Duration{0: 1 * time.Second, 1: 2 * time.Second, 5: 32 * time.Second} {
		if got := reconnectDelay(attempt); got != want {
			t.Fatalf("reconnectDelay(%d) = %v, want %v", attempt, got, want)
		}
	}
	// At and beyond the shift cap: pinned at maxDelay (1s<<6 = 64 s > 60 s).
	for _, attempt := range []int{6, 7, 34, 1000} {
		if got := reconnectDelay(attempt); got != 60*time.Second {
			t.Fatalf("reconnectDelay(%d) = %v, want 60 s", attempt, got)
		}
	}
}

// TestMonitorStopsDuringBackoff: stop() landing inside the backoff sleep
// window must retire the monitor when it wakes, not start one more SSH
// round — the process is on its way out and the connection would be an
// orphan. The fake connect counts rounds; on v0.1.0 (no done-check after
// Sleep) the monitor dials again after stop() and never exits, so the test
// times out with calls = 2.
func TestMonitorStopsDuringBackoff(t *testing.T) {
	var calls atomic.Int32
	firstRound := make(chan struct{})
	var once sync.Once

	d := &sshDialer{
		cfg: sshDialerCfg{host: "127.0.0.1", port: 1, user: "test"},
		connect: func(sshDialerCfg) (*ssh.Client, string, syscall.RawConn, error) {
			calls.Add(1)
			once.Do(func() { close(firstRound) })
			return nil, "", nil, errors.New("dial refused")
		},
	}

	monitorDone := make(chan struct{})
	go func() {
		d.monitor()
		close(monitorDone)
	}()

	<-firstRound // attempt 1 runs with no delay; the retry then sleeps ~2 s
	d.stop()     // simulate SIGTERM inside the backoff window

	select {
	case <-monitorDone:
	case <-time.After(5 * time.Second):
		t.Fatalf("monitor still reconnecting after stop(): %d connect calls", calls.Load())
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("connect calls after stop = %d, want 1 (no reconnect round may start)", n)
	}
}

// TestReadKnownHostFingerprint: the stored fingerprint must be trimmed and
// an existing-but-empty ssh_known_hosts must be a loud config error — a
// blank file silently disables host-key pinning (any key accepted, TOFU
// rewrite), exactly the downgrade known_hosts exists to prevent. On v0.1.0
// the empty-file cases return "" with no error and the newline stays.
func TestReadKnownHostFingerprint(t *testing.T) {
	t.Run("missing file is first run", func(t *testing.T) {
		fp, err := readKnownHostFingerprint(t.TempDir())
		if err != nil || fp != "" {
			t.Fatalf("= (%q, %v), want (\"\", nil)", fp, err)
		}
	})

	cases := []struct {
		name    string
		content string
		want    string
		wantErr bool
	}{
		{"trimmed", "SHA256:abc\n", "SHA256:abc", false},
		{"plain text passes through", "SHA256:xyz", "SHA256:xyz", false},
		{"empty file is fatal", "", "", true},
		{"whitespace-only file is fatal", "   \n", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, sshKnownHostsFile), []byte(tc.content), 0600); err != nil {
				t.Fatalf("write: %v", err)
			}
			fp, err := readKnownHostFingerprint(dir)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("readKnownHostFingerprint(%q) = (%q, nil), want error", tc.content, fp)
				}
				return
			}
			if err != nil || fp != tc.want {
				t.Fatalf("readKnownHostFingerprint(%q) = (%q, %v), want (%q, nil)", tc.content, fp, err, tc.want)
			}
		})
	}
}
