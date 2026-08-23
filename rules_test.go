package main

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestRuleEngine_RFC1918Bypass(t *testing.T) {
	rules, err := NewRuleEngine("", "ip:10.0.0.0/8", "")
	if err != nil {
		t.Fatal(err)
	}

	// RFC 1918 addresses are always DIRECT even if listed in TUNNEL_RULES
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
		if got := rules.Route(host, 80); got != RouteDirect {
			t.Errorf("Route(%q, 80) = %v, want %v (RFC 1918 bypass)", host, got, RouteDirect)
		}
	}
}

func TestRuleEngine_LoopbackIPv6(t *testing.T) {
	rules, err := NewRuleEngine("", "", "")
	if err != nil {
		t.Fatal(err)
	}

	for _, host := range []string{"::1", "fe80::1"} {
		if got := rules.Route(host, 80); got != RouteDirect {
			t.Errorf("Route(%q, 80) = %v, want %v", host, got, RouteDirect)
		}
	}
}

func TestRuleEngine_FallbackTunnel(t *testing.T) {
	rules, err := NewRuleEngine("", "", "")
	if err != nil {
		t.Fatal(err)
	}

	if got := rules.Route("google.com", 443); got != RouteTunnel {
		t.Errorf("Route(%q, 443) = %v, want %v (fallback)", "google.com", got, RouteTunnel)
	}
}

func TestRuleEngine_DirectRules_IP(t *testing.T) {
	rules, err := NewRuleEngine("ip:1.2.3.0/24", "", "")
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
		if got := rules.Route(tc.host, 80); got != tc.want {
			t.Errorf("Route(%q, 80) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

func TestRuleEngine_DirectRules_Domain(t *testing.T) {
	rules, err := NewRuleEngine("internal.local", "", "")
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
		if got := rules.Route(tc.host, 80); got != tc.want {
			t.Errorf("Route(%q, 80) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

func TestRuleEngine_DirectRules_Regex(t *testing.T) {
	rules, err := NewRuleEngine("re:.*\\.internal\\.com$", "", "")
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
		if got := rules.Route(tc.host, 80); got != tc.want {
			t.Errorf("Route(%q, 80) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

func TestRuleEngine_TunnelRules(t *testing.T) {
	rules, err := NewRuleEngine("", "ip:91.108.0.0/16", "")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		host string
		want Route
	}{
		{"91.108.0.1", RouteTunnel},
		{"91.108.40.64", RouteTunnel},
		{"91.109.0.1", RouteTunnel},
		{"91.107.0.1", RouteTunnel}, // not in range
	}

	for _, tc := range tests {
		if got := rules.Route(tc.host, 80); got != tc.want {
			t.Errorf("Route(%q, 80) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

func TestRuleEngine_NoProxy(t *testing.T) {
	rules, err := NewRuleEngine("", "", "localhost,.local")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		host string
		want Route
	}{
		{"localhost", RouteDirect},
		{"myhost.local", RouteDirect},
		{"api.myhost.local", RouteDirect},
		{"example.com", RouteTunnel},
	}

	for _, tc := range tests {
		if got := rules.Route(tc.host, 80); got != tc.want {
			t.Errorf("Route(%q, 80) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

func TestRuleEngine_Priority(t *testing.T) {
	// DIRECT_RULES > TUNNEL_RULES for same host
	rules, err := NewRuleEngine("example.com", "example.com", "")
	if err != nil {
		t.Fatal(err)
	}

	if got := rules.Route("example.com", 80); got != RouteDirect {
		t.Errorf("Route(example.com, 80) = %v, want %v (DIRECT > TUNNEL priority)", got, RouteDirect)
	}
}

func TestRuleEngine_Priority_RFC1918OverTunnel(t *testing.T) {
	// RFC 1918 bypass overrides TUNNEL_RULES
	rules, err := NewRuleEngine("", "ip:192.168.0.0/16", "")
	if err != nil {
		t.Fatal(err)
	}

	if got := rules.Route("192.168.1.1", 80); got != RouteDirect {
		t.Errorf("Route(192.168.1.1, 80) = %v, want %v (RFC 1918 > TUNNEL)", got, RouteDirect)
	}
}

func TestRuleEngine_MultipleRules(t *testing.T) {
	rules, err := NewRuleEngine("ip:10.0.0.0/8,re:.*\\.corp\\.com$,internal.net", "", "")
	if err != nil {
		t.Fatal(err)
	}

	for _, host := range []string{"10.1.2.3", "app.corp.com", "internal.net"} {
		if got := rules.Route(host, 80); got != RouteDirect {
			t.Errorf("Route(%q, 80) = %v, want %v", host, got, RouteDirect)
		}
	}

	if got := rules.Route("external.com", 80); got != RouteTunnel {
		t.Errorf("Route(external.com, 80) = %v, want %v", got, RouteTunnel)
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
