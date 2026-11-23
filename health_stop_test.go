package main

import (
	"context"
	"testing"
	"time"
)

func TestHealthStopClearsReadiness(t *testing.T) {
	h, err := NewHealthServer("127.0.0.1:0", disconnectedDialer{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.Start()
	if !h.ready.Load() {
		t.Fatal("health listener did not become ready")
	}
	if err := h.StopAccept(); err != nil {
		t.Fatal(err)
	}
	if h.ready.Load() {
		t.Fatal("readiness remained true after stopping listeners")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := h.Drain(ctx); err != nil {
		t.Fatal(err)
	}
}
