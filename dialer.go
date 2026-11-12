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
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

// dialer abstracts SSH tunnel dialing — allows mocking in tests.
type dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
	Connected() bool
	stop()
}

type sshDialer struct {
	mu          sync.Mutex
	client      *ssh.Client
	rawConn     syscall.RawConn
	cfg         sshDialerCfg
	done        atomic.Bool
	ctx         context.Context
	cancel      context.CancelFunc
	monitorDone chan struct{}
	stopped     chan struct{}
	stopOnce    sync.Once
	opens       sync.WaitGroup
	keepalives  sync.WaitGroup
	// Unlike accepted-client slots, these tokens remain held after a caller
	// times out, until the underlying SSH open and any late close finish.
	// They belong to the dialer, so reconnect cannot reset the limit.
	pending    chan struct{}
	pendingDNS chan struct{}
	// status is the tunnel state for Status(); only the monitor and the
	// constructor change it, through setStatus.
	status tunnelStatus
	// connect establishes one tunnel connection; the monitor calls it
	// instead of connectSSH directly so tests can observe and control
	// reconnect rounds. The constructor sets connectSSH; a nil value (test
	// literals built by hand) falls back to connectSSH in the monitor.
	connect func(context.Context, sshDialerCfg) (*ssh.Client, string, syscall.RawConn, error)
}

type sshDialerCfg struct {
	host            string
	port            int
	user            string
	keyPath         string
	fingerprint     string
	keepalivePeriod time.Duration
	// keepaliveInterval / keepaliveProbes set TCP_KEEPINTVL / TCP_KEEPCNT
	// (whole seconds) — Go does not expose them; 0 keeps the kernel
	// defaults.
	keepaliveInterval int
	keepaliveProbes   int
	tracker           *ConnTracker
	// dialTimeout bounds a single destination dial (channel open through
	// the SSH tunnel). It bounds only OUR wait for the channel-open reply:
	// there is no wire cancellation for direct-tcpip, so a blackholed
	// destination keeps sshd on the VPS busy connecting until its own
	// timeout, and the pending request plus its channel live on until the
	// transport dies.
	dialTimeout time.Duration
	// handshakeTimeout bounds the TCP dial plus the SSH handshake (version
	// exchange and KEX). x/crypto applies Config.Timeout to the dial only,
	// so the handshake gets an explicit socket deadline. <= 0 uses 10 s.
	handshakeTimeout time.Duration
	// onStatus, when set, gets every tunnel state change (main sets the
	// systemd status line from it). It is called from the monitor
	// goroutine, one call at a time.
	onStatus func(tunnelStatus)
}

// newSSHDialer builds the dialer and starts the connection lifecycle in the
// background. The start is deliberately lazy: a VPS that is down at process
// start must not take the proxies, the Web UI or readyz down with it (a
// fatal exit under `restart: unless-stopped` loops the container and buries
// the first-run key output in the restart noise). The monitor dials
// immediately on its first pass, then retries with backoff; Connected()
// reports liveness and only connect/known_hosts config errors can fail the
// constructor.
func newSSHDialer(cfg sshDialerCfg) (*sshDialer, error) {
	fp, err := readKnownHostFingerprint(filepath.Dir(cfg.keyPath))
	if err != nil {
		return nil, err
	}
	if fp != "" {
		cfg.fingerprint = fp
	}

	d := &sshDialer{cfg: cfg, connect: connectSSH, monitorDone: make(chan struct{})}
	d.lifetimeContext()
	d.setStatus(tunnelStatus{State: stateConnecting})
	go d.monitor()
	return d, nil
}

// setStatus stores the tunnel state and reports it to onStatus.
func (d *sshDialer) setStatus(st tunnelStatus) {
	d.mu.Lock()
	d.status = st
	d.mu.Unlock()
	if d.cfg.onStatus != nil {
		d.cfg.onStatus(st)
	}
}

// Status returns the current tunnel state.
func (d *sshDialer) Status() tunnelStatus {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.status
}

// readKnownHostFingerprint returns the stored SSH host key fingerprint from
// dir/ssh_known_hosts. A missing file is a first run: ("", nil) leaves TOFU
// to connectSSH. Surrounding whitespace is trimmed (hand-edited files get
// trailing newlines; an untrimmed fingerprint would never match). An
// existing file that is empty after trimming is a config error, not a
// first run: a blank fingerprint accepts any host key and silently re-does
// TOFU — the exact downgrade known_hosts prevents — so the operator must
// delete the file to re-trust deliberately.
func readKnownHostFingerprint(dir string) (string, error) {
	data, err := os.ReadFile(filepath.Join(dir, sshKnownHostsFile))
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read %s: %w", sshKnownHostsFile, err)
	}
	fp := strings.TrimSpace(string(data))
	if fp == "" {
		return "", fmt.Errorf("%s exists but is empty — delete the file to re-trust the host key", sshKnownHostsFile)
	}
	return fp, nil
}

func (d *sshDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.trackDial(ctx, network, addr)
}

type noTrackKey struct{}

// ctxWithNoTrack marks an internal dial (a tunnel DNS query) that must not
// appear in the connection tracker.
func ctxWithNoTrack(ctx context.Context) context.Context {
	return context.WithValue(ctx, noTrackKey{}, true)
}

// tunnelHTTPClient builds an HTTP client whose dials go through the SSH
// tunnel (untracked), for internal clients like DoH transports. A timeout
// of 0 disables the overall request timeout; connection setup stays bounded.
// A nil tlsCfg uses the system roots.
func tunnelHTTPClient(lifetime context.Context, d dialer, timeout time.Duration, tlsCfg *tls.Config) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:     tlsCfg,
			TLSHandshakeTimeout: 3 * time.Second,
			IdleConnTimeout:     30 * time.Second,
			MaxConnsPerHost:     32,
			MaxIdleConnsPerHost: 8,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				// Transport detaches this context from the request. Bound
				// our wait even after the original caller has returned.
				ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
				defer cancel()
				stop := context.AfterFunc(lifetime, cancel)
				defer stop()
				if err := lifetime.Err(); err != nil {
					return nil, err
				}
				conn, err := d.DialContext(ctxWithNoTrack(ctx), network, addr)
				if err != nil {
					return nil, err
				}
				// Keep an established connection tied to its owner, not to
				// the request or the shorter dial context.
				owned := &lifetimeConn{Conn: conn}
				owned.stop = context.AfterFunc(lifetime, func() { conn.Close() })
				if err := lifetime.Err(); err != nil {
					owned.Close()
					return nil, err
				}
				return owned, nil
			},
		},
	}
}

// lifetimeConn releases its owner's close callback when the connection
// closes normally, so the owner does not retain dead connections.
type lifetimeConn struct {
	net.Conn
	stop func() bool
}

func (c *lifetimeConn) Close() error {
	c.stop()
	return c.Conn.Close()
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
	if d.cfg.dialTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d.cfg.dialTimeout)
		defer cancel()
	}
	if err := ctx.Err(); err != nil {
		return nil, NewNetworkError("SSH dial", addr, err)
	}
	d.mu.Lock()
	c := d.client
	if d.done.Load() || c == nil {
		d.mu.Unlock()
		return nil, fmt.Errorf("SSH client not connected")
	}
	if d.pending == nil {
		d.pending = make(chan struct{}, 256)
	}
	pool := d.pending
	if ctx.Value(noTrackKey{}) != nil {
		if d.pendingDNS == nil {
			d.pendingDNS = make(chan struct{}, 32)
		}
		pool = d.pendingDNS
	}
	select {
	case pool <- struct{}{}:
		d.opens.Add(1)
		d.mu.Unlock()
	default:
		d.mu.Unlock()
		return nil, NewNetworkError("SSH dial", addr, &pendingOpenLimitError{limit: cap(pool)})
	}
	type result struct {
		conn net.Conn
		err  error
	}
	// An unbuffered handoff gives the result and its token a single owner.
	// Cancellation does not cancel CHANNEL_OPEN on the SSH transport.
	results := make(chan result)
	go func() {
		conn, err := c.Dial(network, addr)
		select {
		case results <- result{conn, err}:
			// The receiver releases the token after checking cancellation.
		case <-ctx.Done():
			if conn != nil {
				conn.Close()
			}
			<-pool
			d.opens.Done()
		}
	}()
	select {
	case r := <-results:
		defer func() { <-pool; d.opens.Done() }()
		if err := ctx.Err(); err != nil {
			if r.conn != nil {
				r.conn.Close()
			}
			return nil, NewNetworkError("SSH dial", addr, err)
		}
		if r.err != nil {
			return nil, NewNetworkError("SSH dial", addr, r.err)
		}
		return r.conn, nil
	case <-ctx.Done():
		return nil, NewNetworkError("SSH dial", addr, ctx.Err())
	}
}

type pendingOpenLimitError struct{ limit int }

func (e *pendingOpenLimitError) Error() string {
	return fmt.Sprintf("SSH pending-open limit reached (%d)", e.limit)
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

// reconnectDelay is the monitor's backoff base for a retry attempt:
// baseDelay doubled per attempt, capped at maxDelay. The shift is capped
// first (1s << 6 = 64s already exceeds maxDelay) because an uncapped shift
// overflows int64 from attempt 34 on and the delay turns negative, which
// makes the monitor spin with no wait at all. Jitter is added by the caller
// so this stays a pure, testable step.
func reconnectDelay(attempt int) time.Duration {
	const (
		baseDelay = time.Second
		maxDelay  = 60 * time.Second
	)
	shift := attempt
	if shift > 6 {
		shift = 6
	}
	delay := baseDelay << uint(shift)
	if delay > maxDelay {
		delay = maxDelay
	}
	return delay
}

// lifetimeContext also supports dialers whose connected client was supplied
// directly. All lifetime state is initialized under the admission lock.
func (d *sshDialer) lifetimeContext() context.Context {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ctx == nil {
		d.ctx, d.cancel = context.WithCancel(context.Background())
		d.stopped = make(chan struct{})
		if d.done.Load() {
			d.cancel()
		}
	}
	return d.ctx
}

func (d *sshDialer) monitor() {
	ctx := d.lifetimeContext()
	d.mu.Lock()
	if d.monitorDone == nil {
		d.monitorDone = make(chan struct{})
	}
	done := d.monitorDone
	d.mu.Unlock()
	defer close(done)
	var cancelGeneration context.CancelFunc
	defer func() {
		if cancelGeneration != nil {
			cancelGeneration()
		}
	}()
	attempt := 0
	// The first pass dials immediately (the constructor is lazy, a
	// startup delay would only slow the healthy path); backoff and jitter
	// apply from the first retry on. The delay is set right after a failed
	// connect, so the status line can tell when the next attempt runs.
	var delay time.Duration
	connect := d.connect
	if connect == nil {
		connect = connectSSH
	}
	// pinned is the trusted host key fingerprint. It starts from
	// ssh_known_hosts and is set by the first TOFU connect, so every later
	// reconnect in this process checks the key. Only the monitor connects,
	// so a local is enough.
	pinned := d.cfg.fingerprint

	for {
		if ctx.Err() != nil {
			return
		}
		// Capture the client under the lock and wait on the local: after a
		// failed reconnect d.client is nil, and d.client.Conn would then
		// dereference nil and crash the process.
		d.mu.Lock()
		client := d.client
		d.mu.Unlock()

		if client != nil {
			client.Wait() // the reconnect log below reports the loss
			if cancelGeneration != nil {
				cancelGeneration()
				cancelGeneration = nil
			}

			if d.done.Load() {
				return
			}

			d.mu.Lock()
			d.client = nil
			d.rawConn = nil
			d.mu.Unlock()
			d.setStatus(tunnelStatus{State: stateReconnecting})
		}

		log.Warn().Int("attempt", attempt+1).Dur("delay", delay).Msg("SSH not connected, dialing...")
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if ctx.Err() != nil {
			return
		}

		cfg := d.cfg
		cfg.fingerprint = pinned
		newClient, fp, newRaw, err := connect(ctx, cfg)
		if ctx.Err() != nil {
			if newClient != nil {
				newClient.Close()
			}
			return
		}
		if err != nil {
			log.Error().Err(err).Int("attempt", attempt+1).Msg("SSH connect failed")
			attempt++
			delay = reconnectDelay(attempt) + time.Duration(rand.Intn(500))*time.Millisecond
			d.setStatus(tunnelStatus{State: failState(err), Err: err, Attempt: attempt, Retry: delay})
			continue
		}
		d.mu.Lock()
		if d.done.Load() {
			d.mu.Unlock()
			newClient.Close()
			return
		}
		oldClient := d.client
		d.client = newClient
		d.rawConn = newRaw
		generation, cancel := context.WithCancel(ctx)
		cancelGeneration = cancel
		if d.cfg.keepalivePeriod > 0 {
			d.keepalives.Add(1)
		}
		d.mu.Unlock()

		if oldClient != nil {
			oldClient.Close()
		}
		if d.cfg.keepalivePeriod > 0 {
			go func() { defer d.keepalives.Done(); d.keepalive(generation, newClient) }()
		}

		if pinned == "" {
			pinned = fp
		}
		attempt = 0
		delay = 0
		d.setStatus(tunnelStatus{State: stateConnected})
		log.Info().Str("host", d.cfg.host).Int("port", d.cfg.port).Str("fingerprint", fp).Msg("SSH connected")
	}
}

// keepalive probes tunnel liveness at the SSH layer for the whole life of
// one client. OS TCP keepalive only detects dead TCP (and with kernel
// defaults, after ~2 hours); a half-dead transport (live TCP, stuck
// peer) would keep Connected()/readyz green forever while every dial times
// out. x/crypto sends no client keepalive, so the probe is ours: a global
// request with wantReply - any reply (accept or reject) proves liveness, no
// reply within one period means the peer is stuck; drop the transport and
// let the monitor reconnect. Loops until its client is replaced or the
// dialer stops, so old goroutines self-retire after a reconnect.
func (d *sshDialer) keepalive(ctx context.Context, client *ssh.Client) {
	period := d.cfg.keepalivePeriod
	tick := time.NewTicker(period)
	defer tick.Stop()
	defer log.Debug().Msg("SSH keepalive loop stopped")
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		d.mu.Lock()
		current := d.client == client && !d.done.Load()
		d.mu.Unlock()
		if !current || ctx.Err() != nil {
			return
		}
		alive := make(chan error, 1)
		go func() {
			_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
			alive <- err
		}()
		timeout := time.NewTimer(period)
		select {
		case err := <-alive:
			timeout.Stop()
			if err == nil {
				continue
			}
		case <-ctx.Done():
			timeout.Stop()
			client.Close()
			<-alive
			return
		case <-timeout.C:
			client.Close()
			<-alive
		}
		log.Warn().Msg("SSH keepalive unanswered, dropping tunnel")
		client.Close()
		return
	}
}

func (d *sshDialer) stop() {
	d.stopOnce.Do(func() {
		d.lifetimeContext()
		d.mu.Lock()
		d.done.Store(true)
		d.cancel()
		c, monitorDone := d.client, d.monitorDone
		d.client, d.rawConn = nil, nil
		d.mu.Unlock()
		if c != nil {
			c.Close()
		}
		// One completion waiter per owner, never one per stop/drain call.
		go func() {
			if monitorDone != nil {
				<-monitorDone
			}
			d.keepalives.Wait()
			d.opens.Wait()
			close(d.stopped)
		}()
	})
}

func (d *sshDialer) waitStopped(ctx context.Context) error {
	d.lifetimeContext()
	select {
	case <-d.stopped:
		return nil
	default:
	}
	select {
	case <-d.stopped:
		return nil
	case <-ctx.Done():
		return ctx.Err()
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
func connectSSH(ctx context.Context, cfg sshDialerCfg) (*ssh.Client, string, syscall.RawConn, error) {
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
				return &hostKeyMismatchError{want: cfg.fingerprint, got: got}
			}
		}
		return nil
	}

	hs := cfg.handshakeTimeout
	if hs <= 0 {
		hs = 10 * time.Second
	}

	sshConfig := &ssh.ClientConfig{
		User:            cfg.user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: callback,
		Timeout:         hs,
	}

	// VPS access is IPv4-only by design; destination IPv6 is resolved on the VPS side.
	var raw syscall.RawConn
	// Control captures the fd's RawConn; it is called for the exact
	// connection that is returned, so it stays valid for the connection's life.
	dl := net.Dialer{
		Timeout: hs,
		Control: func(_, _ string, c syscall.RawConn) error {
			raw = c
			return nil
		},
	}
	rawConn, err := dl.DialContext(ctx, "tcp4", addr)
	if err != nil {
		return nil, "", nil, &connectError{state: stateUnreachable, err: fmt.Errorf("SSH dial to %s: %w", addr, err)}
	}
	stopClose := context.AfterFunc(ctx, func() { rawConn.Close() })
	defer stopClose()
	// OS-level TCP keepalive detects silent (half-open) dead paths without
	// relying on SSH cooperation; SSH_KEEPALIVE_PERIOD=0 disables it.
	if tc, ok := rawConn.(*net.TCPConn); ok {
		if cfg.keepalivePeriod > 0 {
			_ = tc.SetKeepAlive(true)
			_ = tc.SetKeepAlivePeriod(cfg.keepalivePeriod)
			if err := setKeepaliveProbeOpts(raw, cfg.keepaliveInterval, cfg.keepaliveProbes); err != nil {
				log.Warn().Err(err).Msg("set TCP keepalive probe parameters")
			}
		} else {
			_ = tc.SetKeepAlive(false)
		}
	} else {
		log.Warn().Str("type", fmt.Sprintf("%T", rawConn)).Msg("raw TCPConn unavailable; OS keepalive skipped")
	}
	// x/crypto applies Config.Timeout to the TCP dial only; bound the
	// handshake itself on the established socket, then clear the deadline
	// so the live transport is not killed by it (OS keepalive and the
	// app-level probe own transport liveness from here on).
	if err := rawConn.SetDeadline(time.Now().Add(hs)); err != nil {
		rawConn.Close()
		return nil, "", nil, fmt.Errorf("SSH handshake deadline to %s: %w", addr, err)
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(rawConn, addr, sshConfig)
	if err != nil {
		rawConn.Close()
		return nil, "", nil, &connectError{state: handshakeState(err), err: fmt.Errorf("SSH handshake to %s: %w", addr, err)}
	}
	if err := rawConn.SetDeadline(time.Time{}); err != nil {
		rawConn.Close()
		return nil, "", nil, fmt.Errorf("clear SSH handshake deadline on %s: %w", addr, err)
	}
	client := ssh.NewClient(sshConn, chans, reqs)

	if remoteKey != nil {
		fp := sshFingerprint(remoteKey)
		if cfg.fingerprint == "" {
			// TOFU: the key is trusted only once it is saved. A connect
			// that cannot pin the key fails, otherwise the next process
			// start would trust whatever key the network presents.
			if err := writeFileAtomic(filepath.Join(filepath.Dir(cfg.keyPath), sshKnownHostsFile), []byte(fp), 0600); err != nil {
				client.Close()
				return nil, "", nil, fmt.Errorf("save SSH host key fingerprint: %w", err)
			}
		}
		if !stopClose() || ctx.Err() != nil {
			client.Close()
			return nil, "", nil, ctx.Err()
		}
		return client, fp, raw, nil
	}

	if !stopClose() || ctx.Err() != nil {
		client.Close()
		return nil, "", nil, ctx.Err()
	}
	return client, "", raw, nil
}

// keepaliveIntervalUnit is the unit of the TCP_KEEPINTVL socket option
// value: seconds on Linux, milliseconds on macOS.
func keepaliveIntervalUnit() time.Duration {
	if runtime.GOOS == "darwin" {
		return time.Millisecond
	}
	return time.Second
}

// setKeepaliveProbeOpts sets the keepalive retransmission parameters
// (TCP_KEEPINTVL / TCP_KEEPCNT) that Go's net package does not expose.
// The kernel defaults (75 s / 9 probes) extend silent-death detection to
// tens of minutes; a zero argument leaves that parameter at the kernel
// default. intervalSecs is in seconds; the platform unit of TCP_KEEPINTVL
// is applied internally (it takes milliseconds on macOS).
func setKeepaliveProbeOpts(raw syscall.RawConn, intervalSecs, probes int) error {
	if intervalSecs == 0 && probes == 0 {
		return nil
	}
	var firstErr error
	setErr := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if err := raw.Control(func(fd uintptr) {
		if intervalSecs > 0 {
			value := int(time.Duration(intervalSecs) * time.Second / keepaliveIntervalUnit())
			setErr(unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_KEEPINTVL, value))
		}
		if probes > 0 {
			setErr(unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_KEEPCNT, probes))
		}
	}); err != nil {
		return err
	}
	return firstErr
}

func sshFingerprint(key ssh.PublicKey) string {
	hash := sha256.Sum256(key.Marshal())
	return "SHA256:" + base64.StdEncoding.EncodeToString(hash[:])
}
