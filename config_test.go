package main

import (
	"os"
	"slices"
	"strings"
	"testing"
)

// TestParseKeepalivePeriod covers the semantics of SSH_KEEPALIVE_PERIOD:
// valid Go durations pass through; 0/0s disable keepalive (0); empty or
// unparseable input is a hard error so the container fails loud on bad
// input (loadConfig always supplies a non-empty default).
func TestParseKeepalivePeriod(t *testing.T) {
	valid := map[string]struct {
		want    float64 // seconds, 0 = disabled
		wantErr bool
	}{
		"90s": {want: 90},
		"2m":  {want: 120},
		"1h":  {want: 3600},
		"0s":  {want: 0},
		"0":   {want: 0},
		"":    {wantErr: true},
		"abc": {wantErr: true},
		"10x": {wantErr: true},
	}

	for raw, want := range valid {
		got, err := parseKeepalivePeriod(raw)
		if want.wantErr {
			if err == nil {
				t.Errorf("parseKeepalivePeriod(%q): expected error, got nil", raw)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseKeepalivePeriod(%q): unexpected error: %v", raw, err)
			continue
		}
		if got.Seconds() != want.want {
			t.Errorf("parseKeepalivePeriod(%q) = %v, want %v seconds", raw, got, want.want)
		}
	}
}

// TestParseKeepaliveInterval covers the semantics of SSH_KEEPALIVE_INTERVAL:
// durations become whole seconds for TCP_KEEPINTVL, sub-second values round
// up to 1 s; 0 keeps the kernel default (0); empty, negative or unparseable
// input are hard errors.
func TestParseKeepaliveInterval(t *testing.T) {
	valid := map[string]struct {
		want    int
		wantErr bool
	}{
		"1s":     {want: 1},
		"10s":    {want: 10},
		"90s":    {want: 90},
		"1m":     {want: 60},
		"1500ms": {want: 1},
		"0s":     {want: 0},
		"":       {wantErr: true},
		"-1s":    {wantErr: true},
		"abc":    {wantErr: true},
	}
	for raw, want := range valid {
		got, err := parseKeepaliveInterval(raw)
		if want.wantErr {
			if err == nil {
				t.Errorf("parseKeepaliveInterval(%q): expected error, got nil", raw)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseKeepaliveInterval(%q): unexpected error: %v", raw, err)
			continue
		}
		if got != want.want {
			t.Errorf("parseKeepaliveInterval(%q) = %d, want %d", raw, got, want.want)
		}
	}
}

// TestParseKeepaliveProbes covers the semantics of SSH_KEEPALIVE_PROBES:
// non-negative integers pass through; 0 keeps the kernel default (0); empty,
// negative or non-integer input are hard errors.
func TestParseKeepaliveProbes(t *testing.T) {
	valid := map[string]struct {
		want    int
		wantErr bool
	}{
		"5":   {want: 5},
		"9":   {want: 9},
		"0":   {want: 0},
		"":    {wantErr: true},
		"-1":  {wantErr: true},
		"abc": {wantErr: true},
	}
	for raw, want := range valid {
		got, err := parseKeepaliveProbes(raw)
		if want.wantErr {
			if err == nil {
				t.Errorf("parseKeepaliveProbes(%q): expected error, got nil", raw)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseKeepaliveProbes(%q): unexpected error: %v", raw, err)
			continue
		}
		if got != want.want {
			t.Errorf("parseKeepaliveProbes(%q) = %d, want %d", raw, got, want.want)
		}
	}
}

// TestParseDialTimeout covers the semantics of SSH_DIAL_TIMEOUT: valid Go
// durations pass through; zero/negative/unparseable values are hard errors
// because an unbounded destination dial can hang forever on a blackholed host.
func TestParseDialTimeout(t *testing.T) {
	valid := map[string]struct {
		want    float64 // seconds
		wantErr bool
	}{
		"30s": {want: 30},
		"2m":  {want: 120},
		"1ms": {want: 0.001},
		"0s":  {wantErr: true},
		"0":   {wantErr: true},
		"":    {wantErr: true},
		"-5s": {wantErr: true},
		"abc": {wantErr: true},
	}

	for raw, want := range valid {
		got, err := parseDialTimeout(raw)
		if want.wantErr {
			if err == nil {
				t.Errorf("parseDialTimeout(%q): expected error, got nil", raw)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseDialTimeout(%q): unexpected error: %v", raw, err)
			continue
		}
		if got.Seconds() != want.want {
			t.Errorf("parseDialTimeout(%q) = %v, want %v seconds", raw, got, want.want)
		}
	}
}

// TestLoadConfigDohHost covers DOH_HOST semantics: a plain hostname and an
// explicit :443 pass; URLs, other ports and IP-literal addresses are
// rejected (TLS is validated against the hostname, and DoH provider certs
// carry no IP SANs).
func TestLoadConfigDohHost(t *testing.T) {
	t.Setenv("PROXY_MODES", "socks5")
	for _, v := range []string{"", "cloudflare-dns.com", "dns.google:443"} {
		t.Setenv("SSH_HOST", "h")
		t.Setenv("SSH_USER", "u")
		t.Setenv("DOH_HOST", v)
		if _, err := loadConfig(); err != nil {
			t.Errorf("DOH_HOST=%q: unexpected error: %v", v, err)
		}
	}
	for _, v := range []string{
		"https://dns.google",
		"dns.google/dns-query",
		"dns.google:8443",
		"1.1.1.1",
		"1.1.1.1:443",
	} {
		t.Setenv("SSH_HOST", "h")
		t.Setenv("SSH_USER", "u")
		t.Setenv("DOH_HOST", v)
		if _, err := loadConfig(); err == nil {
			t.Errorf("DOH_HOST=%q: expected error, got nil", v)
		}
	}
}

// TestLoadConfigDialTimeoutCap: SSH_DIAL_TIMEOUT must stay below the
// connection-history window — dropStalled moves dialing records out of the
// active map once they outlive it, so a longer dial could lose its record.
func TestLoadConfigDialTimeoutCap(t *testing.T) {
	t.Setenv("PROXY_MODES", "socks5")
	t.Setenv("SSH_HOST", "h")
	t.Setenv("SSH_USER", "u")
	t.Setenv("SSH_DIAL_TIMEOUT", "11m")
	if _, err := loadConfig(); err == nil || !strings.Contains(err.Error(), "must be below") {
		t.Fatalf("err = %v, want the history-window cap error", err)
	}
	t.Setenv("SSH_DIAL_TIMEOUT", "9m")
	if _, err := loadConfig(); err != nil {
		t.Fatalf("9m should be valid: %v", err)
	}
}

// TestParseListenList covers comma-separated listen-address lists: items are
// trimmed, empty items skipped, each item must be host:port, at least one
// address is required.
func TestParseListenList(t *testing.T) {
	cases := []struct {
		raw     string
		want    []string
		wantErr bool
	}{
		{raw: ":1080", want: []string{":1080"}},
		{raw: "0.0.0.0:1080,127.0.0.1:1081", want: []string{"0.0.0.0:1080", "127.0.0.1:1081"}},
		{raw: " :1080 , :1081 ,", want: []string{":1080", ":1081"}},
		{raw: ",,:", want: nil, wantErr: true},
		{raw: ":1080,bad", want: nil, wantErr: true},
		{raw: "1080", want: nil, wantErr: true},
	}
	for _, c := range cases {
		got, err := parseListenList("TEST_LISTEN", c.raw)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseListenList(%q): expected error, got nil", c.raw)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseListenList(%q): unexpected error: %v", c.raw, err)
			continue
		}
		if len(got) != len(c.want) {
			t.Errorf("parseListenList(%q) = %v, want %v", c.raw, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("parseListenList(%q) = %v, want %v", c.raw, got, c.want)
			}
		}
	}
}

// TestLoadConfigListenLists: SOCKS5_LISTEN / HTTP_LISTEN accept a single
// address (backward compatible) and a comma-separated list.
func TestLoadConfigListenLists(t *testing.T) {
	t.Setenv("PROXY_MODES", "socks5,http")
	t.Setenv("SSH_HOST", "h")
	t.Setenv("SSH_USER", "u")

	t.Setenv("SOCKS5_LISTEN", ":1080")
	t.Setenv("HTTP_LISTEN", ":3128")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("single addresses: %v", err)
	}
	if len(cfg.socks5Addrs) != 1 || cfg.socks5Addrs[0] != ":1080" ||
		len(cfg.httpAddrs) != 1 || cfg.httpAddrs[0] != ":3128" {
		t.Fatalf("single addresses: got socks5=%v http=%v", cfg.socks5Addrs, cfg.httpAddrs)
	}

	t.Setenv("SOCKS5_LISTEN", ":1080,127.0.0.1:1081")
	t.Setenv("HTTP_LISTEN", "0.0.0.0:3128, [::]:3128 ")
	cfg, err = loadConfig()
	if err != nil {
		t.Fatalf("lists: %v", err)
	}
	wantSocks5 := []string{":1080", "127.0.0.1:1081"}
	wantHTTP := []string{"0.0.0.0:3128", "[::]:3128"}
	if len(cfg.socks5Addrs) != len(wantSocks5) || len(cfg.httpAddrs) != len(wantHTTP) {
		t.Fatalf("lists: got socks5=%v http=%v", cfg.socks5Addrs, cfg.httpAddrs)
	}
	for i := range wantSocks5 {
		if cfg.socks5Addrs[i] != wantSocks5[i] || cfg.httpAddrs[i] != wantHTTP[i] {
			t.Fatalf("lists: got socks5=%v http=%v", cfg.socks5Addrs, cfg.httpAddrs)
		}
	}
}

// TestLoadConfigTunnelDNSDefault: DoH is optional and off by default, unset
// or empty alike; the tunnel then resolves through the built-in servers.
func TestLoadConfigTunnelDNSDefault(t *testing.T) {
	t.Setenv("PROXY_MODES", "socks5")
	t.Setenv("SSH_HOST", "h")
	t.Setenv("SSH_USER", "u")
	t.Setenv("TUNNEL_DNS", "")

	t.Setenv("DOH_HOST", "")
	check := func(what string) {
		t.Helper()
		cfg, err := loadConfig()
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		want := []string{"1.1.1.1:53", "8.8.8.8:53"}
		if cfg.dohHost != "" || !slices.Equal(cfg.tunnelDNS, want) {
			t.Fatalf("%s: dohHost = %q, tunnelDNS = %v, want no DoH and %v", what, cfg.dohHost, cfg.tunnelDNS, want)
		}
	}
	check(`DOH_HOST=""`)
	os.Unsetenv("DOH_HOST")
	check("unset DOH_HOST")

	t.Setenv("DOH_HOST", "dns.google")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("DOH_HOST=dns.google: %v", err)
	}
	if cfg.dohHost != "dns.google" || cfg.tunnelDNS != nil {
		t.Fatalf("DOH_HOST=dns.google: dohHost = %q, tunnelDNS = %v", cfg.dohHost, cfg.tunnelDNS)
	}
}

// TestLoadConfigTunnelDNS covers the TUNNEL_DNS forms.
func TestLoadConfigTunnelDNS(t *testing.T) {
	t.Setenv("PROXY_MODES", "socks5")
	t.Setenv("SSH_HOST", "h")
	t.Setenv("SSH_USER", "u")
	t.Setenv("DOH_HOST", "")

	for raw, want := range map[string][]string{
		"1.1.1.1":                 {"1.1.1.1:53"},
		"1.1.1.1:5353":            {"1.1.1.1:5353"},
		"2606:4700::1111":         {"[2606:4700::1111]:53"},
		"[2606:4700::1111]:5353":  {"[2606:4700::1111]:5353"},
		"127.0.0.53":              {"127.0.0.53:53"},
		" 1.1.1.1 , 9.9.9.9:53 ,": {"1.1.1.1:53", "9.9.9.9:53"},
	} {
		t.Setenv("TUNNEL_DNS", raw)
		cfg, err := loadConfig()
		if err != nil {
			t.Errorf("TUNNEL_DNS=%q: %v", raw, err)
			continue
		}
		if !slices.Equal(cfg.tunnelDNS, want) {
			t.Errorf("TUNNEL_DNS=%q = %v, want %v", raw, cfg.tunnelDNS, want)
		}
	}
	for _, raw := range []string{"dns.google", "dns.google:53", "1.1.1.1:0", "1.1.1.1:70000", "1.1.1.1:dns", " , "} {
		t.Setenv("TUNNEL_DNS", raw)
		if _, err := loadConfig(); err == nil {
			t.Errorf("TUNNEL_DNS=%q: expected error, got nil", raw)
		}
	}

	t.Setenv("TUNNEL_DNS", "1.1.1.1")
	t.Setenv("DOH_HOST", "dns.google")
	if _, err := loadConfig(); err == nil {
		t.Error("DOH_HOST and TUNNEL_DNS together: expected error, got nil")
	}
}

// TestLoadConfigLocalDNSOnNXDomain: the setting is off by default and takes
// on/off like ACCESS_LOG.
func TestLoadConfigLocalDNSOnNXDomain(t *testing.T) {
	t.Setenv("PROXY_MODES", "socks5")
	t.Setenv("SSH_HOST", "h")
	t.Setenv("SSH_USER", "u")

	t.Setenv("LOCAL_DNS_ON_NXDOMAIN", "")
	if cfg, err := loadConfig(); err != nil || cfg.localOnNXDomain {
		t.Fatalf("default: localOnNXDomain = %v, err = %v", cfg.localOnNXDomain, err)
	}
	t.Setenv("LOCAL_DNS_ON_NXDOMAIN", "on")
	if cfg, err := loadConfig(); err != nil || !cfg.localOnNXDomain {
		t.Fatalf("on: localOnNXDomain = %v, err = %v", cfg.localOnNXDomain, err)
	}
	t.Setenv("LOCAL_DNS_ON_NXDOMAIN", "maybe")
	if _, err := loadConfig(); err == nil {
		t.Fatal("LOCAL_DNS_ON_NXDOMAIN=maybe: expected error, got nil")
	}
}

// TestConfigureDNS: the config picks one tunnel resolver mode and passes the
// NXDOMAIN setting on.
func TestConfigureDNS(t *testing.T) {
	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatalf("NewRuleEngine: %v", err)
	}
	cfg := config{tunnelDNS: []string{"1.1.1.1:53", "9.9.9.9:5353"}, localOnNXDomain: true}
	configureDNS(rules, cfg, testDialer{})
	if mode := rules.DNSStatus().Mode; mode != "servers" {
		t.Fatalf("mode = %s, want servers", mode)
	}
	if !rules.dns.localOnNXDomain {
		t.Fatal("localOnNXDomain not passed on")
	}
	if len(rules.dns.tunnel) != 2 || rules.dns.tunnel[0].name != "1.1.1.1" || rules.dns.tunnel[1].name != "9.9.9.9:5353" {
		t.Fatalf("tunnel = %+v", rules.dns.tunnel)
	}

	rules, err = NewRuleEngine("")
	if err != nil {
		t.Fatalf("NewRuleEngine: %v", err)
	}
	configureDNS(rules, config{dohHost: "dns.google"}, testDialer{})
	if mode := rules.DNSStatus().Mode; mode != "doh" {
		t.Fatalf("mode = %s, want doh", mode)
	}
	if len(rules.dns.tunnel) != 1 || rules.dns.tunnel[0].name != "dns.google" {
		t.Fatalf("tunnel = %+v", rules.dns.tunnel)
	}
}

func TestParseMaxConnections(t *testing.T) {
	cases := map[string]struct {
		want    int
		wantErr bool
	}{
		"4096": {want: 4096},
		"1":    {want: 1},
		"0":    {want: 0},
		"-1":   {wantErr: true},
		"":     {wantErr: true},
		"many": {wantErr: true},
	}
	for raw, want := range cases {
		got, err := parseMaxConnections(raw)
		if want.wantErr {
			if err == nil {
				t.Errorf("parseMaxConnections(%q): expected error, got nil", raw)
			}
			continue
		}
		if err != nil || got != want.want {
			t.Errorf("parseMaxConnections(%q) = %d, %v; want %d", raw, got, err, want.want)
		}
	}
}

func TestParseHostList(t *testing.T) {
	got, err := parseHostList("UI_ALLOWED_HOSTS", " gate.lan, 192.168.1.5 ,,fe80::1")
	if err != nil {
		t.Fatalf("parseHostList: %v", err)
	}
	if len(got) != 3 || got[0] != "gate.lan" || got[1] != "192.168.1.5" || got[2] != "fe80::1" {
		t.Fatalf("parseHostList = %v", got)
	}
	for _, bad := range []string{"gate.lan:9090", "[::1]", "http://gate.lan", "a b"} {
		if _, err := parseHostList("UI_ALLOWED_HOSTS", bad); err == nil {
			t.Errorf("parseHostList(%q): expected error", bad)
		}
	}
	if got, err := parseHostList("UI_ALLOWED_HOSTS", ""); err != nil || len(got) != 0 {
		t.Fatalf("parseHostList(\"\") = %v, %v; want empty", got, err)
	}
}

// TestLoadConfigSSHHostIPv6: the tunnel dials tcp4 only, so an IPv6 literal
// must fail at startup instead of looping in reconnect.
func TestLoadConfigSSHHostIPv6(t *testing.T) {
	t.Setenv("PROXY_MODES", "socks5")
	t.Setenv("SSH_USER", "u")
	for _, v := range []string{"2001:db8::1", "[2001:db8::1]", "::1"} {
		t.Setenv("SSH_HOST", v)
		if _, err := loadConfig(); err == nil || !strings.Contains(err.Error(), "IPv4 only") {
			t.Errorf("SSH_HOST=%q: err = %v, want the IPv4-only error", v, err)
		}
	}
	for _, v := range []string{"203.0.113.1", "vps.example.com", "::ffff:203.0.113.1"} {
		t.Setenv("SSH_HOST", v)
		if _, err := loadConfig(); err != nil {
			t.Errorf("SSH_HOST=%q: unexpected error: %v", v, err)
		}
	}
}
