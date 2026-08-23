package main

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestRuleEngine_RFC1918Bypass(t *testing.T) {
	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatal(err)
	}

	// RFC 1918 addresses are always DIRECT
	for _, host := range []string{
		"10.0.0.1",
		"10.255.255.255",
		"172.16.0.1",
		"172.31.255.255",
		"192.168.0.1",
		"192.168.255.255",
		"127.0.0.1",
		"127.255.255.255",
		"169.254.0.1",
	} {
		if got := rules.Route(context.Background(), host, 80); got != RouteDirect {
			t.Errorf("Route(%q, 80) = %v, want %v (RFC 1918 bypass)", host, got, RouteDirect)
		}
	}
}

func TestRuleEngine_LoopbackIPv6(t *testing.T) {
	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatal(err)
	}

	for _, host := range []string{"::1", "fe80::1"} {
		if got := rules.Route(context.Background(), host, 80); got != RouteDirect {
			t.Errorf("Route(%q, 80) = %v, want %v", host, got, RouteDirect)
		}
	}
}

func TestRuleEngine_FallbackTunnel(t *testing.T) {
	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatal(err)
	}

	if got := rules.Route(context.Background(), "google.com", 443); got != RouteTunnel {
		t.Errorf("Route(%q, 443) = %v, want %v (fallback)", "google.com", got, RouteTunnel)
	}
}

func TestRuleEngine_DirectRules_IP(t *testing.T) {
	rules, err := NewRuleEngine("ip:1.2.3.0/24")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		host     string
		want     Route
	}{
		{"1.2.3.1", RouteDirect},
		{"1.2.3.255", RouteDirect},
		{"1.2.4.1", RouteTunnel},
		{"8.8.8.8", RouteTunnel},
	}

	for _, tc := range tests {
		if got := rules.Route(context.Background(), tc.host, 80); got != tc.want {
			t.Errorf("Route(%q, 80) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

func TestRuleEngine_DirectRules_Domain(t *testing.T) {
	rules, err := NewRuleEngine("internal.local")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		host string
		want Route
	}{
		{"internal.local", RouteDirect},
		{"sub.internal.local", RouteDirect},
		{"notinternal.local", RouteTunnel},
		{"internal.com", RouteTunnel},
	}

	for _, tc := range tests {
		if got := rules.Route(context.Background(), tc.host, 80); got != tc.want {
			t.Errorf("Route(%q, 80) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

func TestRuleEngine_DirectRules_Regex(t *testing.T) {
	rules, err := NewRuleEngine("re:.*\\.internal\\.com$")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		host string
		want Route
	}{
		{"app.internal.com", RouteDirect},
		{"api.internal.com", RouteDirect},
		{"external.com", RouteTunnel},
	}

	for _, tc := range tests {
		if got := rules.Route(context.Background(), tc.host, 80); got != tc.want {
			t.Errorf("Route(%q, 80) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

func TestRuleEngine_MultipleRules(t *testing.T) {
	rules, err := NewRuleEngine("ip:10.0.0.0/8,re:.*\\.corp\\.com$,internal.net")
	if err != nil {
		t.Fatal(err)
	}

	for _, host := range []string{"10.1.2.3", "app.corp.com", "internal.net"} {
		if got := rules.Route(context.Background(), host, 80); got != RouteDirect {
			t.Errorf("Route(%q, 80) = %v, want %v", host, got, RouteDirect)
		}
	}

	if got := rules.Route(context.Background(), "external.com", 80); got != RouteTunnel {
		t.Errorf("Route(external.com, 80) = %v, want %v", got, RouteTunnel)
	}
}

func TestRuleEngine_Decide(t *testing.T) {
	tests := []struct {
		name       string
		direct     string
		host       string
		wantRoute  Route
		wantReason string
	}{
		{"private", "", "127.0.0.1", RouteDirect, "private"},
		{"regex_direct", "re:.*\\.corp\\.com$", "app.corp.com", RouteDirect, "direct:re:.*\\.corp\\.com$"},
		{"fallback", "", "google.com", RouteTunnel, "fallback"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rules, err := NewRuleEngine(tc.direct)
			if err != nil {
				t.Fatal(err)
			}
			gotRoute, gotReason := rules.Decide(context.Background(), tc.host, 80)
			if gotRoute != tc.wantRoute {
				t.Errorf("Decide(%q, 80) route = %v, want %v", tc.host, gotRoute, tc.wantRoute)
			}
			if gotReason != tc.wantReason {
				t.Errorf("Decide(%q, 80) reason = %q, want %q", tc.host, gotReason, tc.wantReason)
			}
		})
	}
}

func TestParseRuleEntry_IP(t *testing.T) {
	r, err := parseRuleEntry("ip:10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	if r.ipPrefix == nil || !r.ipPrefix.Contains(netip.MustParseAddr("10.0.0.1")) {
		t.Error("ip:10.0.0.0/8 should match 10.0.0.1")
	}
}

func TestParseRuleEntry_Regex(t *testing.T) {
	r, err := parseRuleEntry("re:.*\\.test$")
	if err != nil {
		t.Fatal(err)
	}
	if !r.re.MatchString("example.test") {
		t.Error("re:.*\\.test$ should match example.test")
	}
}

func TestParseRuleEntry_Domain(t *testing.T) {
	r, err := parseRuleEntry("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if r.domain != "example.com" {
		t.Errorf("domain = %q, want %q", r.domain, "example.com")
	}
}

func TestParseRuleEntry_InvalidCIDR(t *testing.T) {
	_, err := parseRuleEntry("ip:invalid")
	if err == nil {
		t.Error("expected error for invalid CIDR")
	}
}

func TestParseRuleEntry_InvalidRegex(t *testing.T) {
	_, err := parseRuleEntry("re:[invalid")
	if err == nil {
		t.Error("expected error for invalid regex")
	}
}

func TestDNSCache_Resolve(t *testing.T) {
	c := &dnsCache{
		cache: make(map[string]cacheEntry),
		ttl:   1 * time.Second,
	}

	// Test resolving a known public host
	ip, err := c.Resolve(context.Background(), "google.com")
	if err != nil {
		t.Skip("no DNS:", err)
	}
	if !ip.IsValid() {
		t.Fatal("expected valid IP")
	}

	// Second call should use cache
	ip2, err := c.Resolve(context.Background(), "google.com")
	if err != nil {
		t.Fatal(err)
	}
	if ip != ip2 {
		t.Errorf("cached resolve: got %v, want %v", ip2, ip)
	}

	// Test direct IP
	ip3, err := c.Resolve(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	if ip3.String() != "8.8.8.8" {
		t.Errorf("direct IP: got %v, want 8.8.8.8", ip3)
	}
}
