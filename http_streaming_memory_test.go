//go:build !race

package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPStreamingMemory(t *testing.T) {
	const clients, size = 8, 64 << 20
	var received atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 32<<10)
		for {
			n, err := r.Body.Read(buf)
			received.Add(int64(n))
			if n > 0 {
				time.Sleep(100 * time.Microsecond)
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
		}
		io.WriteString(w, "ok")
	}))
	defer origin.Close()
	s := startTestProxy(t, "")
	upload := func(size int64) error {
		c, err := net.Dial("tcp", proxyAddr(s))
		if err != nil {
			return err
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(30 * time.Second))
		fmt.Fprintf(c, "POST %s/ HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\n\r\n", origin.URL, strings.TrimPrefix(origin.URL, "http://"))
		if err := writeChunks(c, size, nil); err != nil {
			return err
		}
		r, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			return err
		}
		_, err = io.Copy(io.Discard, r.Body)
		r.Body.Close()
		if r.StatusCode != 200 {
			return fmt.Errorf("upload status %d", r.StatusCode)
		}
		return err
	}
	// Warm the server/runtime before taking the baseline. Neither generator
	// nor receiver stores the transferred payload.
	if err := upload(32 << 10); err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	var baseline runtime.MemStats
	runtime.ReadMemStats(&baseline)
	var peak atomic.Uint64
	peak.Store(baseline.HeapAlloc)
	stop, sampled := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(sampled)
		tick := time.NewTicker(5 * time.Millisecond)
		defer tick.Stop()
		for {
			var stats runtime.MemStats
			runtime.ReadMemStats(&stats)
			if stats.HeapAlloc > peak.Load() {
				peak.Store(stats.HeapAlloc)
			}
			select {
			case <-stop:
				return
			case <-tick.C:
			}
		}
	}()
	var wg sync.WaitGroup
	errs := make(chan error, clients)
	for range clients {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- upload(size) }()
	}
	wg.Wait()
	close(stop)
	<-sampled
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	if n := received.Load(); n != clients*size+(32<<10) {
		t.Errorf("received %d bytes", n)
	}
	extra := peak.Load() - baseline.HeapAlloc
	t.Logf("extra peak HeapAlloc: %d bytes for eight 64MiB uploads", extra)
	if extra >= 64<<20 {
		t.Fatalf("streaming retained %d extra bytes, limit 64MiB", extra)
	}
}
