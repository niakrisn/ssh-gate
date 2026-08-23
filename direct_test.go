package main

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestParseIPFamily(t *testing.T) {
	tests := []struct {
	raw  string
	want IPFamily
	err  bool
	}{
		{"", FamilyBoth, false},
		{"both", FamilyBoth, false},
		{"auto", FamilyBoth, false},
		{"ipv4", FamilyIPv4, false},
		{"v4", FamilyIPv4, false},
		{"IPv6", FamilyIPv6, false},
		{" v4 ", FamilyIPv4, false},
		{"ipv46", FamilyBoth, true},
		{"tcp", FamilyBoth, true},
	}

	for _, tc := range tests {
		got, err := parseIPFamily(tc.raw)
		if tc.err {
			if err == nil {
				t.Errorf("parseIPFamily(%q): expected error", tc.raw)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseIPFamily(%q): unexpected error: %v", tc.raw, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseIPFamily(%q) = %v, want %v", tc.raw, got, tc.want)
		}
	}
}

func TestDialDirect_FamilyFilter(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// IPv4 literal with FamilyBoth and FamilyIPv4 — dials the listener.
	for _, family := range []IPFamily{FamilyBoth, FamilyIPv4} {
		conn, dstIP, err := dialDirect(ctx, "127.0.0.1", port, family)
		if err != nil {
			t.Errorf("dialDirect(127.0.0.1, %d, %s): %v", port, family, err)
			continue
		}
		if dstIP != "127.0.0.1" {
			t.Errorf("dialDirect dst = %q, want %q", dstIP, "127.0.0.1")
		}
		conn.Close()
	}

	// IPv4 literal with FamilyIPv6 — no matching address.
	if _, _, err := dialDirect(ctx, "127.0.0.1", port, FamilyIPv6); err == nil {
		t.Error("dialDirect(127.0.0.1, FamilyIPv6): expected error, got nil")
	}

	// IPv6 loopback with FamilyIPv4 — no matching address.
	if _, _, err := dialDirect(ctx, "::1", 1, FamilyIPv4); err == nil {
		t.Error("dialDirect(::1, FamilyIPv4): expected error, got nil")
	}
}
