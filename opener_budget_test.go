package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type stalledDestinationDialer struct{ calls atomic.Int64 }

func (d *stalledDestinationDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	d.calls.Add(1)
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestOpenProxyBudget(t *testing.T) {
	for _, proto := range []string{"http", "socks5"} {
		t.Run(proto, func(t *testing.T) {
			d, live, pending := pendingSSH(t)
			rules, err := NewRuleEngine("")
			if err != nil {
				t.Fatal(err)
			}
			defer rules.Stop()
			o := &Opener{rules: rules, d: d, dialTimeout: 30 * time.Millisecond}
			var address string
			var shutdown func(context.Context) error
			if proto == "http" {
				s, err := NewHTTPProxyServer("127.0.0.1:0", o)
				if err != nil {
					t.Fatal(err)
				}
				s.Start()
				address = s.ln.Addr().String()
				shutdown = s.Shutdown
			} else {
				s, err := NewSOCKS5Server("127.0.0.1:0", o)
				if err != nil {
					t.Fatal(err)
				}
				s.Start()
				address = s.ln.Addr().String()
				shutdown = s.Shutdown
			}
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				shutdown(ctx)
			})
			c, err := net.Dial("tcp", address)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(300 * time.Millisecond))
			if proto == "http" {
				io.WriteString(c, "CONNECT 203.0.113.1:443 HTTP/1.1\r\nHost: 203.0.113.1:443\r\n\r\n")
				resp, err := http.ReadResponse(bufio.NewReader(c), nil)
				if err != nil || resp.StatusCode != 504 {
					t.Fatalf("HTTP timeout reply=%v error=%v", resp, err)
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			} else {
				c.Write([]byte{5, 1, 0})
				if _, err := io.ReadFull(c, make([]byte, 2)); err != nil {
					t.Fatal(err)
				}
				c.Write([]byte{5, 1, 0, 1, 203, 0, 113, 1, 1, 187})
				reply := make([]byte, 10)
				if _, err := io.ReadFull(c, reply); err != nil || reply[1] == 0 {
					t.Fatalf("SOCKS timeout reply=%x error=%v", reply, err)
				}
			}
			var open ssh.NewChannel
			select {
			case open = <-pending:
			case <-time.After(time.Second):
				t.Fatal("missing channel open")
			}
			// Server confirms only after the client received its timeout.
			ch, requests, err := open.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer ch.Close()
			select {
			case <-requests:
			case <-time.After(time.Second):
				t.Fatal("late connection was not closed")
			}
			waitPendingSSH(t, d, 0)
			checkSSHRelay(t, live)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := shutdown(ctx); err != nil {
				t.Fatalf("client retained after error: %v", err)
			}
		})
	}
}
func (*stalledDestinationDialer) Connected() bool { return true }
func (*stalledDestinationDialer) stop()           {}

func TestOpenTotalBudget(t *testing.T) {
	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatal(err)
	}
	defer rules.Stop()
	rules.dns.tunnelUp = func() bool { return true }
	rules.dns.tunnel = []*upstream{{name: "test", lookup: func(context.Context, string) ([]netip.Addr, time.Time, error) {
		return []netip.Addr{netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("203.0.113.2"), netip.MustParseAddr("203.0.113.3")}, time.Now(), nil
	}}}
	d := &stalledDestinationDialer{}
	o := &Opener{rules: rules, d: d, dialTimeout: 50 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, _, _, _, err := o.Open(ctx, "client", "http", "budget.example", 443); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("error=%v", err)
		}
		if d.calls.Load() != 1 {
			t.Fatalf("started %d attempts after shared deadline", d.calls.Load())
		}
	case <-time.After(300 * time.Millisecond):
		cancel()
		<-done
		t.Fatal("dial did not use the one configured budget")
	}
}

func TestOpenPrepareTotalBudget(t *testing.T) {
	rules, err := NewRuleEngine("ip:203.0.113.0/24")
	if err != nil {
		t.Fatal(err)
	}
	defer rules.Stop()
	rules.dns.tunnelUp = func() bool { return true }
	rules.dns.tunnel = []*upstream{{name: "test", lookup: func(ctx context.Context, _ string) ([]netip.Addr, time.Time, error) {
		timer := time.NewTimer(2500 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return nil, time.Time{}, ctx.Err()
		}
		return []netip.Addr{netip.MustParseAddr("203.0.113.1")}, time.Now(), nil
	}}}
	rules.dns.localLookup = func(ctx context.Context, _ string) ([]net.IPAddr, error) { <-ctx.Done(); return nil, ctx.Err() }
	d := &stalledDestinationDialer{}
	o := &Opener{rules: rules, d: d}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, _, _, _, err := o.Open(ctx, "client", "http", "prepare.example", 443); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("error=%v", err)
		}
	case <-time.After(5500 * time.Millisecond):
		cancel()
		<-done
		t.Fatal("CIDR and local lookup renewed the prepare budget")
	}
	if d.calls.Load() != 0 {
		t.Fatal("dial started after failed preparation")
	}
}

func TestOpenParentDeadline(t *testing.T) {
	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatal(err)
	}
	defer rules.Stop()
	d := &stalledDestinationDialer{}
	o := &Opener{rules: rules, d: d, dialTimeout: time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, _, _, _, err = o.Open(ctx, "client", "http", "203.0.113.1", 443)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error=%v", err)
	}
	_, _, _, _, err = o.Open(ctx, "client", "http", "203.0.113.2", 443)
	if !errors.Is(err, context.DeadlineExceeded) || d.calls.Load() != 1 {
		t.Fatalf("canceled Open started a dial: calls=%d err=%v", d.calls.Load(), err)
	}
	if strings.Contains(err.Error(), "addresses tried") {
		t.Fatalf("counted attempts before dial: %v", err)
	}
}
