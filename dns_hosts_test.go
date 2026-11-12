package main

import (
	"context"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

func TestDNSTCPIgnoresHosts(t *testing.T) {
	if os.Getenv("SSH_GATE_TEST_HOSTS_FIXTURE") != "1" {
		t.Skip("requires the isolated Linux hosts fixture")
	}
	const host = "hosts-conflict.example"
	contents, err := os.ReadFile("/etc/hosts")
	if err != nil {
		t.Fatal(err)
	}
	fixture := false
	for _, line := range strings.Split(string(contents), "\n") {
		line, _, _ = strings.Cut(line, "#")
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "127.0.0.9" {
			continue
		}
		for _, name := range fields[1:] {
			if name == host {
				fixture = true
			}
		}
	}
	if !fixture {
		t.Fatal("required hosts fixture absent")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	local, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		t.Fatalf("hosts control lookup: %v", err)
	}
	found := false
	for _, ip := range local {
		if ip.IP.Equal(net.ParseIP("127.0.0.9")) {
			found = true
		}
	}
	if !found {
		t.Fatalf("required hosts fixture absent: %v", local)
	}
	want := netip.MustParseAddr("203.0.113.7")
	peer := startFakeDNSServer(t, func(string) (byte, netip.Addr) { return 0, want })
	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatal(err)
	}
	defer rules.Stop()
	rules.SetTunnelDNS([]string{peer.addr}, &channelDialer{})
	rules.dns.localLookup = func(context.Context, string) ([]net.IPAddr, error) {
		t.Error("unexpected local fallback")
		return nil, errNotFound
	}
	got, err := rules.ResolveAll(context.Background(), host)
	if err != nil || len(got) != 1 || got[0] != want {
		t.Fatalf("tunnel answer=%v error=%v observed queries=%v", got, err, peer.asked())
	}
	names := peer.asked()
	if len(names) != 2 {
		t.Fatalf("queries=%v, want A and AAAA", names)
	}
	for _, name := range names {
		if name != host+"." {
			t.Fatalf("unexpected query %q", name)
		}
	}
}
