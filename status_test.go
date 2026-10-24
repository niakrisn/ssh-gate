package main

import (
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// TestSDNotify: the message reaches the socket named by NOTIFY_SOCKET as
// one datagram; without the variable the call does nothing.
func TestSDNotify(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	if err := sdNotify("READY=1"); err != nil {
		t.Fatalf("no NOTIFY_SOCKET: err = %v, want nil", err)
	}

	sock := filepath.Join(t.TempDir(), "notify")
	l, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	t.Setenv("NOTIFY_SOCKET", sock)

	if err := sdNotify("STATUS=Connected to u@h:22"); err != nil {
		t.Fatalf("sdNotify: %v", err)
	}
	buf := make([]byte, 256)
	l.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := l.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := string(buf[:n]); got != "STATUS=Connected to u@h:22" {
		t.Fatalf("datagram = %q", got)
	}
}

// TestSDStatusStop: after stop no update may replace the stopping line -
// the tunnel can drop while the proxies drain.
func TestSDStatusStop(t *testing.T) {
	var mu sync.Mutex
	var got []string
	s := &sdStatus{notify: func(msg string) error {
		mu.Lock()
		got = append(got, msg)
		mu.Unlock()
		return nil
	}}
	s.set("Connected to u@h:22")
	s.ready()
	s.stop("Stopping, draining connections")
	s.set("Tunnel to u@h:22 lost, reconnecting")
	s.ready()

	want := []string{
		"STATUS=Connected to u@h:22",
		"READY=1",
		"STOPPING=1\nSTATUS=Stopping, draining connections",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("messages = %q, want %q", got, want)
	}
}

// startRejectingSSHServer starts an SSH server that rejects every client
// key: the VPS without our key in authorized_keys.
func startRejectingSSHServer(t *testing.T) (string, int) {
	t.Helper()
	serverCfg := &ssh.ServerConfig{
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, errors.New("unknown key")
		},
	}
	serverCfg.AddHostKey(newTestHostSigner(t))
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
				defer conn.Close()
				ssh.NewServerConn(conn, serverCfg)
			}()
		}
	}()
	return splitTestAddr(t, l.Addr().String())
}

func splitTestAddr(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port: %v", err)
	}
	return host, port
}

// TestConnectSSHFailStates: each connect failure maps to its own state, and
// the status line names what the operator has to do.
func TestConnectSSHFailStates(t *testing.T) {
	t.Run("key rejected", func(t *testing.T) {
		host, port := startRejectingSSHServer(t)
		cfg := sshDialerCfg{host: host, port: port, user: "test", keyPath: writeTestKey(t)}
		_, _, _, err := connectSSH(cfg)
		if got := failState(err); got != stateKeyRejected {
			t.Fatalf("state = %q, want %q (err %v)", got, stateKeyRejected, err)
		}
		text := statusText(cfg, tunnelStatus{State: failState(err), Err: err, Attempt: 1, Retry: 2 * time.Second})
		if !strings.Contains(text, cfg.keyPath+".pub") || !strings.Contains(text, "retry in 2s (attempt 1)") {
			t.Fatalf("status = %q", text)
		}
	})

	t.Run("host key mismatch", func(t *testing.T) {
		addr, _ := startStoppableSSHServer(t, "127.0.0.1:0", newTestHostSigner(t))
		host, port := splitTestAddr(t, addr)
		cfg := sshDialerCfg{host: host, port: port, user: "test", keyPath: writeTestKey(t), fingerprint: "SHA256:old"}
		_, _, _, err := connectSSH(cfg)
		if got := failState(err); got != stateHostKeyMismatch {
			t.Fatalf("state = %q, want %q (err %v)", got, stateHostKeyMismatch, err)
		}
		text := statusText(cfg, tunnelStatus{State: failState(err), Err: err})
		knownHosts := filepath.Join(filepath.Dir(cfg.keyPath), sshKnownHostsFile)
		if !strings.Contains(text, "expected SHA256:old") || !strings.Contains(text, "delete "+knownHosts) {
			t.Fatalf("status = %q", text)
		}
	})

	t.Run("unreachable", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		host, port := splitTestAddr(t, l.Addr().String())
		l.Close()
		cfg := sshDialerCfg{host: host, port: port, user: "test", keyPath: writeTestKey(t)}
		_, _, _, err = connectSSH(cfg)
		if got := failState(err); got != stateUnreachable {
			t.Fatalf("state = %q, want %q (err %v)", got, stateUnreachable, err)
		}
		text := statusText(cfg, tunnelStatus{State: failState(err), Err: err, Attempt: 3, Retry: 8 * time.Second})
		want := "Cannot reach test@" + net.JoinHostPort(host, strconv.Itoa(port)) + ": connect: connection refused; retry in 8s (attempt 3)"
		if text != want {
			t.Fatalf("status = %q, want %q", text, want)
		}
	})

	t.Run("unreadable key", func(t *testing.T) {
		cfg := sshDialerCfg{host: "127.0.0.1", port: 1, user: "test", keyPath: filepath.Join(t.TempDir(), "none")}
		_, _, _, err := connectSSH(cfg)
		if got := failState(err); got != stateSSHError {
			t.Fatalf("state = %q, want %q (err %v)", got, stateSSHError, err)
		}
	})
}

// TestMonitorReportsStatus: the dialer reports connecting at start, the
// failure state with its retry delay after a failed attempt, and connected
// once the endpoint appears.
func TestMonitorReportsStatus(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	host, port := splitTestAddr(t, addr)
	l.Close()

	var mu sync.Mutex
	var states []tunnelStatus
	d, err := newSSHDialer(sshDialerCfg{
		host:    host,
		port:    port,
		user:    "test",
		keyPath: writeTestKey(t),
		onStatus: func(st tunnelStatus) {
			mu.Lock()
			states = append(states, st)
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatalf("newSSHDialer: %v", err)
	}
	t.Cleanup(d.stop)

	waitState := func(want string) tunnelStatus {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if st := d.Status(); st.State == want {
				return st
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("state %q not reached, now %q", want, d.Status().State)
		return tunnelStatus{}
	}

	st := waitState(stateUnreachable)
	if st.Attempt != 1 || st.Retry < 2*time.Second || st.Retry >= 3*time.Second {
		t.Fatalf("after the first failure: attempt %d, retry %s; want 1, 2 s + jitter", st.Attempt, st.Retry)
	}

	startStoppableSSHServer(t, addr, newTestHostSigner(t))
	waitState(stateConnected)

	mu.Lock()
	defer mu.Unlock()
	if states[0].State != stateConnecting {
		t.Fatalf("first state = %q, want %q", states[0].State, stateConnecting)
	}
}

// TestHealthNotConfigured: without SSH_HOST the health server runs, readyz
// says why it is not ready and /api/status reports the state.
func TestHealthNotConfigured(t *testing.T) {
	addr := startTestHealth(t, unconfiguredDialer{}, nil, "", 22)

	resp, err := http.Get("http://" + addr + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable || !strings.HasPrefix(string(body), "not configured") {
		t.Fatalf("/readyz: code=%d body=%q", resp.StatusCode, body)
	}

	resp, err = http.Get("http://" + addr + "/api/status")
	if err != nil {
		t.Fatalf("GET /api/status: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), `"state":"not_configured"`) {
		t.Fatalf("/api/status = %s", body)
	}
}

// TestLoadConfigNotConfigured: empty SSH_HOST and SSH_USER are not a config
// error; missing names them for the status line.
func TestLoadConfigNotConfigured(t *testing.T) {
	t.Setenv("SSH_HOST", "")
	t.Setenv("SSH_USER", "")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if got := strings.Join(cfg.missing(), ","); got != "SSH_HOST,SSH_USER" {
		t.Fatalf("missing = %q", got)
	}
	if got := notConfiguredText(cfg.missing()); !strings.Contains(got, "set SSH_HOST and SSH_USER in /etc/default/ssh-gate") {
		t.Fatalf("status = %q", got)
	}

	t.Setenv("SSH_HOST", "h")
	if cfg, err = loadConfig(); err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if got := strings.Join(cfg.missing(), ","); got != "SSH_USER" {
		t.Fatalf("missing = %q, want SSH_USER", got)
	}
}
