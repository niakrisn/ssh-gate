package main

import (
	"strings"
	"testing"
)

// TestParseKeepalivePeriod covers the semantics of SSH_KEEPALIVE_PERIOD:
// valid Go durations pass through; empty/0/0s disable keepalive (0);
// an unparseable value is a hard error so the container fails loud on bad input.
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
		"":    {want: 0},
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
