package main

import (
	"os"
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

// TestLoadConfigDohHostEmptyDisables: DOH_HOST is read strictly — unset
// falls back to the default endpoint, set-but-empty disables DoH as the
// documentation promises. The old getEnv path collapsed empty to the
// default, making the documented "empty disables DoH" unreachable.
func TestLoadConfigDohHostEmptyDisables(t *testing.T) {
	t.Setenv("PROXY_MODES", "socks5")
	t.Setenv("SSH_HOST", "h")
	t.Setenv("SSH_USER", "u")

	t.Setenv("DOH_HOST", "")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf(`DOH_HOST="": %v`, err)
	}
	if cfg.dohHost != "" {
		t.Fatalf(`DOH_HOST="" → dohHost = %q, want "" (empty must disable DoH)`, cfg.dohHost)
	}

	os.Unsetenv("DOH_HOST")
	cfg, err = loadConfig()
	if err != nil {
		t.Fatalf("unset DOH_HOST: %v", err)
	}
	if cfg.dohHost != "cloudflare-dns.com" {
		t.Fatalf("unset DOH_HOST → dohHost = %q, want cloudflare-dns.com", cfg.dohHost)
	}
}
