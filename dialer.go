package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
)

// dialer abstracts SSH tunnel dialing — allows mocking in tests.
type dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
	Connected() bool
	stop()
}

type sshDialer struct {
	mu      sync.Mutex
	client  *ssh.Client
	rawConn syscall.RawConn
	cfg     sshDialerCfg
	done    atomic.Bool
}

type sshDialerCfg struct {
	host            string
	port            int
	user            string
	keyPath         string
	fingerprint     string
	keepalivePeriod time.Duration
	tracker         *ConnTracker
	// dialTimeout bounds a single destination dial (channel open through
	// the SSH tunnel). A blackholed destination keeps the open request
	// pending on the VPS sshd side until this deadline cancels it.
	dialTimeout time.Duration
}

func newSSHDialer(cfg sshDialerCfg) (*sshDialer, error) {
	knownHostsPath := filepath.Join(filepath.Dir(cfg.keyPath), sshKnownHostsFile)
	if data, err := os.ReadFile(knownHostsPath); err == nil {
		cfg.fingerprint = string(data)
	}

	client, fp, raw, err := connectSSH(cfg)
	if err != nil {
		return nil, NewSSHError("connection", cfg.host, cfg.port, err)
	}

	log.Info().Str("host", cfg.host).Int("port", cfg.port).Str("fingerprint", fp).Msg("SSH connected")

	cfg.fingerprint = fp
	d := &sshDialer{
		client:  client,
		rawConn: raw,
		cfg:     cfg,
	}

	go d.monitor()
	return d, nil
}

func (d *sshDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.trackDial(ctx, network, addr)
}

type noTrackKey struct{}

// ctxWithNoTrack marks an internal dial (the DoH transport) that must not
// appear in the connection tracker.
func ctxWithNoTrack(ctx context.Context) context.Context {
	return context.WithValue(ctx, noTrackKey{}, true)
}

// tunnelHTTPClient builds an HTTP client whose dials go through the SSH
// tunnel (untracked), for internal clients like DoH transports. A timeout
// of 0 leaves requests unbounded; a nil tlsCfg uses the system roots.
func tunnelHTTPClient(d dialer, timeout time.Duration, tlsCfg *tls.Config) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return d.DialContext(ctxWithNoTrack(ctx), network, addr)
			},
		},
	}
}

// trackDial performs the dial and, when a tracker is set, registers the
// connection: host comes from ctx metadata (the original hostname), falling
// back to parsing addr.
func (d *sshDialer) trackDial(ctx context.Context, network, addr string) (net.Conn, error) {
	if ctx.Value(noTrackKey{}) != nil {
		return d.dial(ctx, network, addr)
	}
	tr := d.cfg.tracker
	if tr == nil {
		return d.dial(ctx, network, addr)
	}

	dialHost, port := parseDialAddr(addr)
	meta, ok := connMetaFromCtx(ctx)
	host := dialHost
	if ok && meta.Host != "" {
		host = meta.Host
	}
	if ok {
		// SOCKS5 and HTTP resolve FQDNs client-side, so the dial address is
		// an IP whenever it parses as one; the original hostname arrives
		// through meta.Host.
		if ip, err := netip.ParseAddr(dialHost); err == nil {
			meta.DstIP = ip.String()
		}
	}

	id := tr.Begin(meta, host, port)
	conn, err := d.dial(ctx, network, addr)
	if err != nil {
		tr.Fail(id, err)
		return nil, err
	}
	return tr.Done(id, conn), nil
}

func (d *sshDialer) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	c := d.client
	d.mu.Unlock()

	if c == nil {
		return nil, fmt.Errorf("SSH client not connected")
	}

	if d.cfg.dialTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d.cfg.dialTimeout)
		defer cancel()
	}

	conn, err := c.DialContext(ctx, network, addr)
	if err != nil {
		return nil, NewNetworkError("SSH dial", addr, err)
	}
	return conn, nil
}

// parseDialAddr splits an addr in host:port form into host and port.
func parseDialAddr(addr string) (string, int) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 0
	}
	port, _ := strconv.Atoi(portStr)
	return host, port
}

// TunnelTCPStats returns the live tcp_info counters for the tunnel
// connection, or nil when the connection is absent or the platform lacks
// tcp_info (see tcpinfo_linux.go / tcpinfo_other.go).
func (d *sshDialer) TunnelTCPStats() *tcpStats {
	d.mu.Lock()
	rc := d.rawConn
	d.mu.Unlock()
	if rc == nil {
		return nil
	}
	return readTCPStats(rc)
}

func (d *sshDialer) monitor() {
	attempt := 0
	baseDelay := time.Second
	maxDelay := 60 * time.Second

	for {
		d.mu.Lock()
		conn := d.client.Conn
		d.mu.Unlock()

		if conn != nil {
			conn.Wait()

			if d.done.Load() {
				return
			}

			d.mu.Lock()
			d.client = nil
			d.mu.Unlock()
		}

		delay := baseDelay
		if attempt > 0 {
			delay = baseDelay << uint(attempt)
			if delay > maxDelay {
				delay = maxDelay
			}
		}
		jitter := time.Duration(rand.Intn(500)) * time.Millisecond
		delay += jitter

		log.Warn().Int("attempt", attempt+1).Dur("delay", delay).Msg("SSH connection lost, reconnecting...")
		time.Sleep(delay)

		newClient, fp, newRaw, err := connectSSH(d.cfg)
		if err != nil {
			log.Error().Err(err).Int("attempt", attempt+1).Msg("SSH reconnect failed")
			attempt++
			continue
		}

		d.mu.Lock()
		oldClient := d.client
		d.client = newClient
		d.rawConn = newRaw
		d.mu.Unlock()

		if oldClient != nil {
			oldClient.Close()
		}
		attempt = 0
		log.Info().Str("fingerprint", fp).Msg("SSH reconnected")
	}
}

func (d *sshDialer) stop() {
	d.done.Store(true)
	d.mu.Lock()
	c := d.client
	d.mu.Unlock()
	if c != nil {
		c.Close()
	}
}

// Connected returns true if the SSH client is connected and ready to dial.
func (d *sshDialer) Connected() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.client != nil
}

const sshKnownHostsFile = "ssh_known_hosts"

// connectSSH establishes the tunnel connection and returns the client, the
// host key fingerprint and the syscall.RawConn of the TCP connection (the
// handle readTCPStats uses to fetch SOL_TCP/TCP_INFO for /api/status).
func connectSSH(cfg sshDialerCfg) (*ssh.Client, string, syscall.RawConn, error) {
	keyData, err := os.ReadFile(cfg.keyPath)
	if err != nil {
		return nil, "", nil, fmt.Errorf("read SSH key: %w", err)
	}

	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		return nil, "", nil, fmt.Errorf("parse SSH key: %w", err)
	}

	addr := net.JoinHostPort(cfg.host, strconv.Itoa(cfg.port))

	var remoteKey ssh.PublicKey
	callback := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		remoteKey = key
		if cfg.fingerprint != "" {
			got := sshFingerprint(key)
			if got != cfg.fingerprint {
				return fmt.Errorf("host key mismatch: expected %s, got %s", cfg.fingerprint, got)
			}
		}
		return nil
	}

	sshConfig := &ssh.ClientConfig{
		User:            cfg.user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: callback,
		Timeout:         10 * time.Second,
	}

	// VPS access is IPv4-only by design; destination IPv6 is resolved on the VPS side.
	var raw syscall.RawConn
	// Control captures the fd's RawConn; it is called for the exact
	// connection that is returned, so it stays valid for the connection's life.
	dl := net.Dialer{
		Timeout: sshConfig.Timeout,
		Control: func(_, _ string, c syscall.RawConn) error {
			raw = c
			return nil
		},
	}
	rawConn, err := dl.Dial("tcp4", addr)
	if err != nil {
		return nil, "", nil, fmt.Errorf("SSH dial to %s: %w", addr, err)
	}
	// OS-level TCP keepalive detects silent (half-open) dead paths without
	// relying on SSH cooperation; SSH_KEEPALIVE_PERIOD=0 disables it.
	if tc, ok := rawConn.(*net.TCPConn); ok {
		if cfg.keepalivePeriod > 0 {
			_ = tc.SetKeepAlive(true)
			_ = tc.SetKeepAlivePeriod(cfg.keepalivePeriod)
		} else {
			_ = tc.SetKeepAlive(false)
		}
	} else {
		log.Warn().Str("type", fmt.Sprintf("%T", rawConn)).Msg("raw TCPConn unavailable; OS keepalive skipped")
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(rawConn, addr, sshConfig)
	if err != nil {
		rawConn.Close()
		return nil, "", nil, fmt.Errorf("SSH handshake to %s: %w", addr, err)
	}
	client := ssh.NewClient(sshConn, chans, reqs)

	if remoteKey != nil {
		fp := sshFingerprint(remoteKey)
		if cfg.fingerprint == "" {
			if err := os.WriteFile(filepath.Join(filepath.Dir(cfg.keyPath), sshKnownHostsFile), []byte(fp), 0600); err != nil {
				log.Warn().Err(err).Msg("save SSH host key fingerprint")
			}
		}
		return client, fp, raw, nil
	}

	return client, "", raw, nil
}

func sshFingerprint(key ssh.PublicKey) string {
	hash := sha256.Sum256(key.Marshal())
	return "SHA256:" + base64.StdEncoding.EncodeToString(hash[:])
}
