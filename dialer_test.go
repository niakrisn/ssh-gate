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
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// startTestSSHServer starts an in-process SSH server. It accepts any
// publickey; when acceptChannels is true it accepts incoming channels
// (without forwarding), otherwise it leaves channel open requests pending
// forever — a model of a VPS sshd stuck in its destination dial.
func startTestSSHServer(t *testing.T, acceptChannels bool) (addr string, clientSigner ssh.Signer) {
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

	l, err := net.Listen("tcp", "127.0.0.1:0")
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
				go ssh.DiscardRequests(reqs)
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
	addr, signer := startTestSSHServer(t, true)
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
	addr, signer := startTestSSHServer(t, false)
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
	addr, signer := startTestSSHServer(t, true)
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

func TestNetworkDialerWrapperMeta(t *testing.T) {
	tr := NewConnTracker(8, time.Minute)
	d := &sshDialer{cfg: sshDialerCfg{tracker: tr}}
	w := d.NetworkDialer()

	if _, err := w.DialContext(context.Background(), "tcp", "149.154.175.50:443"); err == nil {
		t.Fatal("want dial error (no SSH client)")
	}
	if _, err := w.Dial("tcp", "149.154.165.22:443"); err == nil {
		t.Fatal("want dial error (no SSH client)")
	}

	hist, total, err := tr.List("history", "", "", 1, 50)
	if err != nil || total != 2 {
		t.Fatalf("history total=%d err=%v", total, err)
	}
	for _, v := range hist {
		if v.Proto != "mtproto" || v.Src != "-" {
			t.Fatalf("record: %+v", v)
		}
		if v.Port != 443 || (v.Host != "149.154.175.50" && v.Host != "149.154.165.22") {
			t.Fatalf("record: %+v", v)
		}
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
	addr, _ := startTestSSHServer(t, false)

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
