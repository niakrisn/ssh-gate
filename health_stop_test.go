package main

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

func TestHealthStopCancelsProbe(t *testing.T) {
	// Hold the real net.Dialer's DNS phase. No public network is used.
	// The suite is sequential; restore the process resolver after the dial exits.
	old := net.DefaultResolver
	entered := make(chan struct{})
	var once sync.Once
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		once.Do(func() { close(entered) })
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	h, err := NewHealthServer("127.0.0.1:0", "probe-stop.invalid", 22, disconnectedDialer{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { h.runProbe(); close(done) }()
	t.Cleanup(func() {
		h.StopAccept()
		select {
		case <-done:
		case <-time.After(4 * time.Second):
			t.Error("probe did not finish")
		}
		net.DefaultResolver = old
	})
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("probe did not start DNS")
	}
	h.StopAccept()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("stop did not cancel active probe")
	}
}

func TestHealthStopFinishesProbeLoop(t *testing.T) {
	h, err := NewHealthServer("127.0.0.1:0", "127.0.0.1", 1, disconnectedDialer{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.Start()
	h.StopAccept()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := h.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-h.probeDone:
	default:
		t.Fatal("drain returned before probe loop finished")
	}
}
