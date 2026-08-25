package main

import (
	"context"
	"sync"
	"testing"
)

// TestRuleEngineStopConcurrent guards against double-close of the DNS cache
// purge channel: Start(ctx), Stop(), cancel() (the main path) and repeated
// Stop() may race. closeOnce makes all of these safe — the test asserts that
// they run without panic and without a data race (the race detector proves it).
func TestRuleEngineStopConcurrent(t *testing.T) {
	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatalf("NewRuleEngine: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	rules.Start(ctx)

	var wg sync.WaitGroup

	// Simulate the main path: cancel the context.
	wg.Add(1)
	go func() {
		defer wg.Done()
		cancel()
	}()

	// Simulate the shutdown path racing with it, plus repeated Stop() calls.
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rules.Stop()
		}()
	}

	wg.Wait()

	// Repeated Stop() after everything must remain a no-op, not a panic.
	for i := 0; i < 5; i++ {
		rules.Stop()
	}
}
