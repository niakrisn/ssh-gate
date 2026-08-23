package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/9seconds/mtg/v2/essentials"
	"github.com/9seconds/mtg/v2/network"
)

// mockSSHDialer is a pass-through dialer that records dial calls.
type mockSSHDialer struct {
	dialCount atomic.Int32
}

func newMockSSHDialer() *mockSSHDialer {
	return &mockSSHDialer{}
}

func (m *mockSSHDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	m.dialCount.Add(1)
	return net.Dial(network, addr)
}

func (m *mockSSHDialer) NetworkDialer() network.Dialer {
	return &mockNetworkDialer{m: m}
}

func (m *mockSSHDialer) stop() {}

type mockNetworkDialer struct {
	m *mockSSHDialer
}

func (d *mockNetworkDialer) Dial(network_, addr string) (essentials.Conn, error) {
	conn, err := d.m.DialContext(context.Background(), network_, addr)
	if err != nil {
		return nil, err
	}
	return netConnToEssentials{conn}, nil
}

func (d *mockNetworkDialer) DialContext(ctx context.Context, network_, addr string) (essentials.Conn, error) {
	conn, err := d.m.DialContext(ctx, network_, addr)
	if err != nil {
		return nil, err
	}
	return netConnToEssentials{conn}, nil
}

// newTestHTTPServer creates an HTTP server that echoes the request path + headers.
func newTestHTTPServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK " + r.URL.Path))
	}))
}

// assertContains checks that actual contains expected substring.
func assertContains(t *testing.T, actual, expected string) {
	t.Helper()
	if len(actual) < len(expected) {
		t.Errorf("expected %q to contain %q", actual, expected)
		return
	}
	found := false
	for i := 0; i <= len(actual)-len(expected); i++ {
		if actual[i:i+len(expected)] == expected {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected %q to contain %q", actual, expected)
	}
}

func assertEqual(t *testing.T, got, want any) {
	t.Helper()
	if got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}

func assertError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Error("expected error, got nil")
	}
}

func assertNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// readAll reads all bytes from a reader with timeout.
func readAll(t *testing.T, r io.Reader, limit int) []byte {
	t.Helper()
	buf := make([]byte, limit)
	n, err := io.ReadFull(r, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		t.Fatal(err)
	}
	return buf[:n]
}
