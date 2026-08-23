package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/9seconds/mtg/v2/essentials"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
)

type sshDialer struct {
	mu        sync.Mutex
	client    *ssh.Client
	fallback  *net.Dialer
	cfg       sshDialerCfg
	allowlist []netip.Prefix
	done      atomic.Bool
}

type sshDialerCfg struct {
	host        string
	port        int
	user        string
	keyPath     string
	fingerprint string
}

func newSSHDialer(cfg sshDialerCfg, allowlist []netip.Prefix) (*sshDialer, error) {
	// Load saved host key fingerprint
	knownHostsPath := filepath.Join(filepath.Dir(cfg.keyPath), sshKnownHostsFile)
	if data, err := os.ReadFile(knownHostsPath); err == nil {
		cfg.fingerprint = string(bytes.TrimSpace(data))
	}

	client, fp, err := connectSSH(cfg)
	if err != nil {
		return nil, fmt.Errorf("connect SSH: %w", err)
	}

	log.Info().Str("host", cfg.host).Int("port", cfg.port).Str("fingerprint", fp).Msg("SSH connected")

	// Store fingerprint for reconnects
	cfg.fingerprint = fp

	d := &sshDialer{
		client:    client,
		fallback:  &net.Dialer{Timeout: 10 * time.Second},
		cfg:       cfg,
		allowlist: allowlist,
	}

	go d.monitor()
	return d, nil
}

func (d *sshDialer) Dial(network_, address string) (essentials.Conn, error) {
	return d.DialContext(context.Background(), network_, address)
}

func (d *sshDialer) DialContext(ctx context.Context, network_, address string) (essentials.Conn, error) {
	// Resolve hostname to IP
	host, _, sepErr := net.SplitHostPort(address)
	if sepErr != nil {
		host = address
	}

	ip, err := resolveIP(ctx, host)
	if err == nil && d.inAllowlist(ip) {
		// Direct dial for allowlisted IPs
		conn, err := d.fallback.DialContext(ctx, network_, address)
		if err != nil {
			return nil, fmt.Errorf("direct dial %s %s: %w", network_, address, err)
		}
		return essentials.WrapNetConn(conn), nil
	}

	// Fall back to SSH tunnel
	d.mu.Lock()
	c := d.client
	d.mu.Unlock()

	if c == nil {
		return nil, fmt.Errorf("SSH client not connected")
	}

	conn, err := c.DialContext(ctx, network_, address)
	if err != nil {
		return nil, fmt.Errorf("SSH dial %s %s: %w", network_, address, err)
	}
	return essentials.WrapNetConn(conn), nil
}

func resolveIP(ctx context.Context, host string) (netip.Addr, error) {
	// Fast path: host is already an IP
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip, nil
	}

	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, a := range addrs {
		if ip, ok := netip.AddrFromSlice(a.IP); ok && ip.Is4() {
			return ip, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("no IPv4 address for %s", host)
}

func (d *sshDialer) inAllowlist(ip netip.Addr) bool {
	for _, p := range d.allowlist {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func (d *sshDialer) monitor() {
	for {
		d.mu.Lock()
		conn := d.client.Conn
		d.mu.Unlock()

		conn.Wait()

		if d.done.Load() {
			return
		}

		log.Warn().Msg("SSH connection lost, reconnecting...")

		backoff := jitteredBackoff()
		time.Sleep(backoff)

		newClient, fp, err := connectSSH(d.cfg)
		if err != nil {
			log.Error().Err(err).Msg("SSH reconnect failed")
			continue
		}

		d.mu.Lock()
		oldClient := d.client
		d.client = newClient
		d.mu.Unlock()

		// Close old client so the Wait() above returns.
		oldClient.Close()
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

	addr := fmt.Sprintf("%s:%d", cfg.host, cfg.port)

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

	conn, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return nil, "", fmt.Errorf("SSH dial to %s: %w", addr, err)
	}

	if remoteKey != nil {
		fp := sshFingerprint(remoteKey)
		// Save fingerprint for future reconnects
		if cfg.fingerprint == "" {
			if err := os.WriteFile(filepath.Join(filepath.Dir(cfg.keyPath), sshKnownHostsFile), []byte(fp), 0600); err != nil {
				log.Warn().Err(err).Msg("save SSH host key fingerprint")
			}
		}
		return conn, fp, nil
	}

	return conn, "", nil
}

func sshFingerprint(key ssh.PublicKey) string {
	hash := sha256.Sum256(key.Marshal())
	return "SHA256:" + base64.StdEncoding.EncodeToString(hash[:])
}

func jitteredBackoff() time.Duration {
	base := 500 * time.Millisecond
	jitter := time.Duration(rand.Intn(500)) * time.Millisecond
	return base + jitter
}
