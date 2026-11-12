package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func candidateIPs(n int) []netip.Addr {
	var out []netip.Addr
	for i := 1; i <= n; i++ {
		out = append(out, netip.AddrFrom4([4]byte{203, 0, 113, byte(i)}))
	}
	return out
}

func TestOpenFallbackDelay(t *testing.T) {
	ips := candidateIPs(2)
	first, second := make(chan struct{}), make(chan struct{})
	winner, peer := net.Pipe()
	defer peer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		c, ip, n, err := dialCandidates(ctx, ips, time.Second, 20*time.Millisecond, func(ctx context.Context, ip netip.Addr) (net.Conn, error) {
			if ip == ips[0] {
				close(first)
				<-ctx.Done()
				return nil, ctx.Err()
			}
			close(second)
			return winner, nil
		})
		if c != nil {
			c.Close()
		}
		if err == nil && (ip != ips[1] || n != 2) {
			err = errors.New("wrong winner or attempt count")
		}
		done <- err
	}()
	<-first
	select {
	case <-second:
	case <-time.After(300 * time.Millisecond):
		cancel()
		<-done
		winner.Close()
		t.Fatal("second candidate waited for first timeout")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestOpenThirdAddressAfterTwoStalls(t *testing.T) {
	ips := candidateIPs(3)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan netip.Addr, 3)
	winner, peer := net.Pipe()
	defer peer.Close()
	var active, peak atomic.Int64
	done := make(chan error, 1)
	go func() {
		c, ip, n, err := dialCandidates(ctx, ips, 4*time.Second, 20*time.Millisecond, func(ctx context.Context, ip netip.Addr) (net.Conn, error) {
			now := active.Add(1)
			defer active.Add(-1)
			for old := peak.Load(); now > old && !peak.CompareAndSwap(old, now); old = peak.Load() {
			}
			started <- ip
			if ip == ips[2] {
				return winner, nil
			}
			<-ctx.Done()
			return nil, ctx.Err()
		})
		if c != nil {
			c.Close()
		}
		if err == nil && (ip != ips[2] || n != 3) {
			err = errors.New("third candidate was not the winner")
		}
		done <- err
	}()
	for range 3 {
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			cancel()
			<-done
			winner.Close()
			t.Fatal("two stalled addresses hid the third")
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if peak.Load() > 2 {
		t.Fatalf("concurrent attempts=%d", peak.Load())
	}
}

func TestOpenClosesLosingSuccess(t *testing.T) {
	ips := candidateIPs(2)
	late, latePeer := net.Pipe()
	defer latePeer.Close()
	winner, winnerPeer := net.Pipe()
	defer winnerPeer.Close()
	release := make(chan struct{})
	returned := make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	type result struct {
		conn     net.Conn
		ip       netip.Addr
		attempts int
		err      error
	}
	results := make(chan result, 1)
	go func() {
		c, ip, n, err := dialCandidates(ctx, ips, time.Second, 10*time.Millisecond, func(ctx context.Context, ip netip.Addr) (net.Conn, error) {
			if ip == ips[0] {
				<-release
				close(returned)
				return late, nil
			}
			return winner, nil
		})
		results <- result{c, ip, n, err}
	}()
	var r result
	select {
	case r = <-results:
		close(release)
	case <-time.After(300 * time.Millisecond):
		close(release)
		r = <-results
		if r.conn != nil {
			r.conn.Close()
		}
		winner.Close()
		late.Close()
		t.Fatal("winner waited for the stalled losing attempt")
	}
	if r.conn != nil {
		r.conn.Close()
	}
	if r.err != nil || r.ip != ips[1] || r.attempts != 2 {
		late.Close()
		t.Fatalf("winner=%v attempts=%d error=%v", r.ip, r.attempts, r.err)
	}

	<-returned
	latePeer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := latePeer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		late.Close()
		t.Fatalf("losing success retained: %v", err)
	}
}

func TestOpenCancelStopsAttempts(t *testing.T) {
	ips := candidateIPs(6)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{}, 6)
	done := make(chan int, 1)
	go func() {
		_, _, n, err := dialCandidates(ctx, ips, time.Second, 10*time.Millisecond, func(ctx context.Context, _ netip.Addr) (net.Conn, error) {
			started <- struct{}{}
			<-ctx.Done()
			return nil, ctx.Err()
		})
		if !errors.Is(err, context.Canceled) {
			t.Errorf("error=%v", err)
		}
		done <- n
	}()
	for range 2 {
		select {
		case <-started:
		case <-time.After(300 * time.Millisecond):
			cancel()
			<-done
			t.Fatal("second attempt never started")
		}
	}
	cancel()
	if n := <-done; n != 2 {
		t.Fatalf("attempts=%d after cancellation, want 2", n)
	}
	select {
	case <-started:
		t.Fatal("new attempt after cancellation")
	default:
	}
}

func TestOpenAttemptCount(t *testing.T) {
	ips := candidateIPs(3)
	addrs := []netip.Addr{ips[0], ips[0], ips[1], ips[1], ips[2]}
	refused := errors.New("refused")
	var calls atomic.Int64
	_, _, n, err := dialCandidates(context.Background(), addrs, time.Second, time.Hour, func(context.Context, netip.Addr) (net.Conn, error) { calls.Add(1); return nil, refused })
	if !errors.Is(err, refused) || n != 3 || calls.Load() != 3 {
		t.Fatalf("attempts=%d calls=%d error=%v", n, calls.Load(), err)
	}
}
