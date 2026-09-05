package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/9seconds/mtg/v2/essentials"
	"github.com/9seconds/mtg/v2/network"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
)

// dialer abstracts SSH tunnel dialing — allows mocking in tests.
type dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
	NetworkDialer() network.Dialer
	Connected() bool
	stop()
}

type sshDialer struct {
	mu     sync.Mutex
	client *ssh.Client
	cfg    sshDialerCfg
	done   atomic.Bool
}

type sshDialerCfg struct {
	host            string
	port            int
	user            string
	keyPath         string
	fingerprint     string
	keepalivePeriod time.Duration
}

// netConnToEssentials wraps net.Conn into essentials.Conn (adds CloseRead/CloseWrite).
type netConnToEssentials struct {
	net.Conn
}

func (n netConnToEssentials) CloseRead() error {
	if cr, ok := n.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}

func (n netConnToEssentials) CloseWrite() error {
	if cw, ok := n.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func newSSHDialer(cfg sshDialerCfg) (*sshDialer, error) {
	knownHostsPath := filepath.Join(filepath.Dir(cfg.keyPath), sshKnownHostsFile)
	if data, err := os.ReadFile(knownHostsPath); err == nil {
		cfg.fingerprint = string(data)
	}

	client, fp, err := connectSSH(cfg)
	if err != nil {
		return nil, NewSSHError("connection", cfg.host, cfg.port, err)
	}

	log.Info().Str("host", cfg.host).Int("port", cfg.port).Str("fingerprint", fp).Msg("SSH connected")

	cfg.fingerprint = fp
	d := &sshDialer{
		client: client,
		cfg:    cfg,
	}

	go d.monitor()
	return d, nil
}

func (d *sshDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	c := d.client
	d.mu.Unlock()

	if c == nil {
		return nil, fmt.Errorf("SSH client not connected")
	}

	conn, err := c.DialContext(ctx, network, addr)
	if err != nil {
		return nil, NewNetworkError("SSH dial", addr, err)
	}
	return conn, nil
}

// NetworkDialer returns a dialer compatible with mtg network.Dialer interface.
func (d *sshDialer) NetworkDialer() network.Dialer {
	return &networkDialerWrapper{d: d}
}

type networkDialerWrapper struct {
	d *sshDialer
}

func (w *networkDialerWrapper) Dial(network_, addr string) (essentials.Conn, error) {
	conn, err := w.d.DialContext(context.Background(), network_, addr)
	if err != nil {
		return nil, err
	}
	return netConnToEssentials{conn}, nil
}

func (w *networkDialerWrapper) DialContext(ctx context.Context, network_, addr string) (essentials.Conn, error) {
	conn, err := w.d.DialContext(ctx, network_, addr)
	if err != nil {
		return nil, err
	}
	return netConnToEssentials{conn}, nil
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

		newClient, fp, err := connectSSH(d.cfg)
		if err != nil {
			log.Error().Err(err).Int("attempt", attempt+1).Msg("SSH reconnect failed")
			attempt++
			continue
		}

		d.mu.Lock()
		oldClient := d.client
		d.client = newClient
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

func connectSSH(cfg sshDialerCfg) (*ssh.Client, string, error) {
	keyData, err := os.ReadFile(cfg.keyPath)
	if err != nil {
		return nil, "", fmt.Errorf("read SSH key: %w", err)
	}

	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		return nil, "", fmt.Errorf("parse SSH key: %w", err)
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
	rawConn, err := net.DialTimeout("tcp4", addr, sshConfig.Timeout)
	if err != nil {
		return nil, "", fmt.Errorf("SSH dial to %s: %w", addr, err)
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
		return nil, "", fmt.Errorf("SSH handshake to %s: %w", addr, err)
	}
	client := ssh.NewClient(sshConn, chans, reqs)

	if remoteKey != nil {
		fp := sshFingerprint(remoteKey)
		if cfg.fingerprint == "" {
			if err := os.WriteFile(filepath.Join(filepath.Dir(cfg.keyPath), sshKnownHostsFile), []byte(fp), 0600); err != nil {
				log.Warn().Err(err).Msg("save SSH host key fingerprint")
			}
		}
		return client, fp, nil
	}

	return client, "", nil
}

func sshFingerprint(key ssh.PublicKey) string {
	hash := sha256.Sum256(key.Marshal())
	return "SHA256:" + base64.StdEncoding.EncodeToString(hash[:])
}
