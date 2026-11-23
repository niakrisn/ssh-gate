package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Tunnel states. statusText turns a transport state into the systemd line;
// /api/status reports the states per server and transport.
const (
	stateNotConfigured   = "not_configured"
	stateConnecting      = "connecting"
	stateConnected       = "connected"
	stateReconnecting    = "reconnecting"
	stateKeyRejected     = "key_rejected"
	stateUnreachable     = "unreachable"
	stateHostKeyMismatch = "host_key_mismatch"
	stateSSHError        = "ssh_error"
)

// tunnelStatus is a snapshot of the SSH tunnel lifecycle.
type tunnelStatus struct {
	State string
	// Err, Attempt and Retry are set in the failure states: the last
	// connect error, failed attempts in a row and the delay before the
	// next attempt.
	Err     error
	Attempt int
	Retry   time.Duration
}

// statusProvider is implemented by dialers that report the tunnel state.
type statusProvider interface {
	Status() tunnelStatus
}

// connectError tags a connect failure with the failure state it leads to.
type connectError struct {
	state string
	err   error
}

func (e *connectError) Error() string { return e.err.Error() }
func (e *connectError) Unwrap() error { return e.err }

// hostKeyMismatchError is the host key callback error when the server key
// differs from the pinned fingerprint.
type hostKeyMismatchError struct {
	want, got string
}

func (e *hostKeyMismatchError) Error() string {
	return fmt.Sprintf("host key mismatch: expected %s, got %s", e.want, e.got)
}

// failState returns the failure state of a connect error; an untagged
// error is a generic SSH error.
func failState(err error) string {
	var ce *connectError
	if errors.As(err, &ce) {
		return ce.state
	}
	return stateSSHError
}

// handshakeState classifies an SSH handshake error. x/crypto has no error
// type for a rejected key, only the message text.
func handshakeState(err error) string {
	var mismatch *hostKeyMismatchError
	switch {
	case errors.As(err, &mismatch):
		return stateHostKeyMismatch
	case strings.Contains(err.Error(), "ssh: unable to authenticate"):
		return stateKeyRejected
	}
	return stateSSHError
}

// statusText is the systemd status line for st. It names the files the
// operator has to act on, so `systemctl status` alone tells what to do.
func statusText(cfg sshDialerCfg, st tunnelStatus) string {
	ep := cfg.user + "@" + net.JoinHostPort(cfg.host, strconv.Itoa(cfg.port))
	retry := fmt.Sprintf("retry in %s (attempt %d)", st.Retry.Round(time.Second), st.Attempt)
	switch st.State {
	case stateConnecting:
		return "Connecting to " + ep
	case stateConnected:
		return "Connected to " + ep
	case stateReconnecting:
		return "Tunnel to " + ep + " lost, reconnecting"
	case stateKeyRejected:
		return fmt.Sprintf("Key not accepted by %s: add %s.pub to authorized_keys; %s", ep, cfg.keyPath, retry)
	case stateUnreachable:
		return fmt.Sprintf("Cannot reach %s: %s; %s", ep, dialCause(st.Err), retry)
	case stateHostKeyMismatch:
		knownHosts := filepath.Join(filepath.Dir(cfg.keyPath), sshKnownHostsFile)
		entry := "the fingerprint"
		if cfg.serverID != "" {
			entry = fmt.Sprintf("the %q entry", cfg.serverID)
		}
		message := "Host key of " + ep + " changed"
		var m *hostKeyMismatchError
		if errors.As(st.Err, &m) {
			message += fmt.Sprintf(" (expected %s, got %s)", m.want, m.got)
		}
		return fmt.Sprintf("%s: independently verify the new fingerprint, then replace %s in %s and restart the service", message, entry, knownHosts)
	}
	return fmt.Sprintf("SSH error: %v; %s", st.Err, retry)
}

// dialCause returns the short reason of a dial error ("connect: connection
// refused", "i/o timeout") without the repeated address prefixes.
func dialCause(err error) string {
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Err != nil {
		return opErr.Err.Error()
	}
	if err == nil {
		return "unknown error"
	}
	return err.Error()
}

// notConfiguredText is the status line while no SSH server is configured.
func notConfiguredText(missing []string) string {
	return "Not configured: set " + strings.Join(missing, " and ") + " in /etc/ssh-gate/config.yaml, then restart the service"
}

// unconfiguredDialer stands in for the SSH dialer when no SSH server is
// configured: the health server and the Web UI run and report the
// state, the proxies stay off.
type unconfiguredDialer struct{}

func (unconfiguredDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("not configured: ssh.servers is empty")
}

func (unconfiguredDialer) Connected() bool { return false }
func (unconfiguredDialer) stop()           {}

func (unconfiguredDialer) Status() tunnelStatus {
	return tunnelStatus{State: stateNotConfigured}
}
