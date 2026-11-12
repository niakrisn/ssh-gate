package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// forwardingSSH runs real direct-tcpip channels to one local test server.
// Completion is reported only after both socket copies have exited.
type forwardingSSH struct {
	d      *sshDialer
	opens  atomic.Int64
	active atomic.Int64
	closed chan struct{}
}

func startForwardingSSH(t *testing.T, target string) *forwardingSSH {
	t.Helper()
	f := &forwardingSSH{closed: make(chan struct{}, 64)}
	addr, signer := startTestSSHServerWithChannelHandler(t, "", true, func(open ssh.NewChannel) error {
		var dest struct {
			Host       string
			Port       uint32
			OriginHost string
			OriginPort uint32
		}
		if err := ssh.Unmarshal(open.ExtraData(), &dest); err != nil || open.ChannelType() != "direct-tcpip" ||
			net.JoinHostPort(dest.Host, fmt.Sprint(dest.Port)) != target {
			t.Errorf("unexpected SSH destination: %+v (%v)", dest, err)
			return open.Reject(ssh.Prohibited, "unexpected destination")
		}
		conn, err := net.DialTimeout("tcp", target, time.Second)
		if err != nil {
			return open.Reject(ssh.ConnectionFailed, err.Error())
		}
		ch, requests, err := open.Accept()
		if err != nil {
			conn.Close()
			return err
		}
		f.opens.Add(1)
		f.active.Add(1)
		go ssh.DiscardRequests(requests)
		go func() {
			copied := make(chan struct{})
			go func() {
				io.Copy(conn, ch)
				conn.Close()
				close(copied)
			}()
			io.Copy(ch, conn)
			ch.Close()
			conn.Close()
			<-copied
			f.active.Add(-1)
			f.closed <- struct{}{}
		}()
		return nil
	})
	f.d = &sshDialer{client: connectTestSSHClient(t, addr, signer)}
	return f
}

func startSilentTLSPeer(t *testing.T, count int) (string, <-chan struct{}, <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	hellos := make(chan struct{}, count)
	closed := make(chan struct{}, count)
	go func() {
		for range count {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				var first [1]byte
				if _, err := io.ReadFull(conn, first[:]); err == nil {
					hellos <- struct{}{}
				}
				// Consume ClientHello, but never send the TLS response.
				io.Copy(io.Discard, conn)
				closed <- struct{}{}
			}()
		}
	}()
	return ln.Addr().String(), hellos, closed
}

func TestDoHTLSHandshakeBounded(t *testing.T) {
	const count = 3
	// Detached TLS dials must finish within their own handshake deadline.
	const channels = count
	target, hellos, closed := startSilentTLSPeer(t, channels)
	f := startForwardingSSH(t, target)
	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatal(err)
	}
	rules.SetDOH(target, f.d)
	rules.dns.dohClient.Timeout = 100 * time.Millisecond
	rules.dns.localLookup = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("198.51.100.1")}}, nil
	}
	t.Cleanup(func() {
		f.d.stop()
		rules.Stop()
	})
	results := make(chan error, count)
	for i := range count {
		go func() {
			addrs, err := rules.ResolveAll(context.Background(), fmt.Sprintf("tls-%d.example", i))
			if err == nil && (len(addrs) != 1 || addrs[0].String() != "198.51.100.1") {
				err = fmt.Errorf("unexpected fallback: %v", addrs)
			}
			results <- err
		}()
	}
	for range channels {
		select {
		case <-hellos:
		case <-time.After(time.Second):
			t.Fatal("TLS handshake did not start")
		}
	}
	for range count {
		select {
		case err := <-results:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("lookup did not return its local fallback promptly")
		}
	}
	deadline := time.NewTimer(4 * time.Second)
	defer deadline.Stop()
	for range channels {
		select {
		case <-f.closed:
		case <-deadline.C:
			t.Fatal("canceled DoH requests retained SSH/TLS channels")
		}
		select {
		case <-closed:
		case <-time.After(time.Second):
			t.Fatal("TLS server connection remained open")
		}
	}
	if got := f.active.Load(); got != 0 {
		t.Fatalf("active SSH channels = %d", got)
	}
}

type waitingDoHDialer struct{ stopped chan struct{} }

func (d waitingDoHDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	<-ctx.Done()
	close(d.stopped)
	return nil, ctx.Err()
}
func (waitingDoHDialer) Connected() bool { return true }
func (waitingDoHDialer) stop()           {}

func TestDoHDialWaitBounded(t *testing.T) {
	d := waitingDoHDialer{stopped: make(chan struct{})}
	client := tunnelHTTPClient(context.Background(), d, 100*time.Millisecond, nil)
	t.Cleanup(client.CloseIdleConnections)
	if resp, err := client.Get("https://dns.example/dns-query"); err == nil {
		resp.Body.Close()
		t.Fatal("unexpected response from blocked dial")
	}
	select {
	case <-d.stopped:
	case <-time.After(4 * time.Second):
		t.Fatal("request returned but background dial had no deadline")
	}
}

func TestDoHTransportReuse(t *testing.T) {
	srv := startFakeDoHServer(t, func(_, _ string) dohAnswer {
		return dohAnswer{a: []string{"198.51.100.1"}}
	})
	f := startForwardingSSH(t, srv.Listener.Addr().String())
	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatal(err)
	}
	rules.SetDOH(srv.Listener.Addr().String(), f.d)
	rules.dns.dohClient.Transport.(*http.Transport).TLSClientConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig
	t.Cleanup(rules.Stop)
	for _, host := range []string{"first.example", "second.example"} {
		ctx, cancel := context.WithCancel(context.Background())
		addrs, err := rules.ResolveAll(ctx, host)
		cancel()
		if err != nil || len(addrs) != 1 || addrs[0] != netip.MustParseAddr("198.51.100.1") {
			t.Fatalf("lookup %s: %v, %v", host, addrs, err)
		}
	}
	if f.opens.Load() != 1 || f.active.Load() != 1 {
		t.Fatalf("finished request killed pooled connection: opens=%d active=%d", f.opens.Load(), f.active.Load())
	}
}

func TestDoHTransportStop(t *testing.T) {
	for _, phase := range []string{"idle", "response", "handshake"} {
		t.Run(phase, func(t *testing.T) {
			started := make(chan struct{}, 1)
			var srv *httptest.Server
			var target string
			var hello <-chan struct{}
			if phase == "handshake" {
				target, hello, _ = startSilentTLSPeer(t, 1)
			} else {
				srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					started <- struct{}{}
					if phase == "response" {
						<-r.Context().Done()
						return
					}
					w.WriteHeader(http.StatusNoContent)
				}))
				target = srv.Listener.Addr().String()
				t.Cleanup(srv.Close)
			}
			f := startForwardingSSH(t, target)
			rules, err := NewRuleEngine("")
			if err != nil {
				t.Fatal(err)
			}
			rules.SetDOH(target, f.d)
			if srv != nil {
				rules.dns.dohClient.Transport.(*http.Transport).TLSClientConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig
			}
			t.Cleanup(func() {
				rules.Stop()
				f.d.stop()
			})
			result := make(chan error, 1)
			go func() {
				resp, err := rules.dns.dohClient.Get("https://" + target + "/dns-query")
				if err == nil {
					resp.Body.Close()
				}
				result <- err
			}()
			if phase == "handshake" {
				select {
				case <-hello:
				case <-time.After(time.Second):
					t.Fatal("TLS handshake did not start")
				}
			} else {
				select {
				case <-started:
				case <-time.After(time.Second):
					t.Fatal("HTTPS request did not arrive")
				}
			}
			if phase == "idle" {
				if err := <-result; err != nil {
					t.Fatal(err)
				}
			}
			rules.Stop()
			rules.Stop()
			select {
			case <-f.closed:
			case <-time.After(time.Second):
				t.Fatalf("Stop retained %s SSH connection", phase)
			}
			if phase != "idle" {
				select {
				case err := <-result:
					if err == nil {
						t.Fatal("stopped request unexpectedly succeeded")
					}
				case <-time.After(time.Second):
					t.Fatal("request did not exit after Stop")
				}
			}
			if _, err := rules.ResolveAll(context.Background(), "198.51.100.1"); !errors.Is(err, context.Canceled) {
				t.Fatalf("stopped cache accepted a new lookup: %v", err)
			}
		})
	}
}

func TestDNSStopCancelsSharedLookup(t *testing.T) {
	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatal(err)
	}
	started, finished, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	rules.dns.localLookup = func(ctx context.Context, _ string) ([]net.IPAddr, error) {
		close(started)
		defer close(finished)
		select {
		case <-ctx.Done():
		case <-release:
		}
		return nil, context.Canceled
	}
	t.Cleanup(func() {
		close(release)
		rules.Stop()
		<-finished
	})
	result := make(chan error, 1)
	go func() {
		_, err := rules.dns.localResolveAll(context.Background(), "blocked.example")
		result <- err
	}()
	<-started
	rules.Stop()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("stopped lookup error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cache stop did not cancel detached DNS work")
	}
}

func TestDNSStopWaitsForSharedLookupCleanup(t *testing.T) {
	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatal(err)
	}
	started, canceled, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	rules.dns.localLookup = func(ctx context.Context, _ string) ([]net.IPAddr, error) {
		close(started)
		<-ctx.Done()
		close(canceled)
		<-release
		close(finished)
		return nil, ctx.Err()
	}
	t.Cleanup(func() { close(release); rules.Stop(); <-finished })
	caller := make(chan struct{})
	go func() { defer close(caller); rules.dns.localResolveAll(context.Background(), "cleanup.example") }()
	<-started
	rules.Stop()
	<-canceled
	<-caller
	short, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := rules.dns.waitStopped(short); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("reported DNS stopped before lookup cleanup: %v", err)
	}
	// Release cleanup explicitly, then prove completion before the test cleanup.
	release <- struct{}{}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("lookup cleanup retained")
	}
	ctx, done := context.WithTimeout(context.Background(), time.Second)
	defer done()
	if err := rules.dns.waitStopped(ctx); err != nil {
		t.Fatal(err)
	}
}
