package main

import (
	"context"
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

// TestBadConfigExitStatus: a config file the operator must fix cannot be
// restarted around. Logging is not up yet at that point, so the exit status is
// set by hand; the child re-runs main the way the SIGTERM test does.
func TestBadConfigExitStatus(t *testing.T) {
	if os.Getenv("SSH_GATE_TEST_BADCONFIG") == "1" {
		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
		os.Args = []string{os.Args[0], "--config", os.Getenv("SSH_GATE_TEST_CONFIG")}
		main()
		return
	}

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("typo_key: 1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestBadConfigExitStatus$")
	cmd.Env = append(os.Environ(), "SSH_GATE_TEST_BADCONFIG=1", "SSH_GATE_TEST_CONFIG="+path)
	out, err := cmd.CombinedOutput()

	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("err = %v, want a non-zero exit; output: %s", err, out)
	}
	if exit.ExitCode() != exitConfig {
		t.Fatalf("exit = %d, want %d; output: %s", exit.ExitCode(), exitConfig, out)
	}
	if !strings.Contains(string(out), "load config") {
		t.Fatalf("output = %q, want the config error", out)
	}
}

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

func TestConfigureDNS(t *testing.T) {
	rules, err := NewRuleEngine(nil)
	if err != nil {
		t.Fatalf("NewRuleEngine: %v", err)
	}
	cfg := config{tunnelDNS: []string{"1.1.1.1:53", "9.9.9.9:5353"}}
	configureDNS(rules, cfg, testDialer{})
	if mode := rules.DNSStatus().Mode; mode != "servers" {
		t.Fatalf("mode = %s, want servers", mode)
	}
	if len(rules.dns.tunnel) != 2 || rules.dns.tunnel[0].name != "1.1.1.1" || rules.dns.tunnel[1].name != "9.9.9.9:5353" {
		t.Fatalf("tunnel = %+v", rules.dns.tunnel)
	}

	rules, err = NewRuleEngine(nil)
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

// TestLoadConfigDoHEndpointShape: the DoH client builds
// https://<host>/dns-query itself, so a value that carries a scheme, a path or
// a space names a nonsense host. It would start fine and only break on the
// first tunnel lookup, so startup has to refuse it.
func TestLoadConfigDoHEndpointShape(t *testing.T) {
	config := func(host string) string {
		return "proxy:\n  socks5:\n    listen: [\":1080\"]\ndns:\n  tunnel:\n    doh_host: \"" + host + "\"\n"
	}
	for _, host := range []string{"dns.google", "dns.example:8443", "192.0.2.1", "[2001:db8::1]:443"} {
		if _, err := loadConfigFile(writeConfig(t, config(host))); err != nil {
			t.Errorf("doh_host %q rejected: %v", host, err)
		}
	}
	for _, host := range []string{"https://dns.google", "dns.google/dns-query", "dns google", "dns.google:notaport", "dns.google:0", ":443"} {
		if _, err := loadConfigFile(writeConfig(t, config(host))); err == nil {
			t.Errorf("doh_host %q accepted", host)
		}
	}
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := t.TempDir() + "/config.yaml"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadConfigRejectsServerIDsThatBreakKnownHostsFormat(t *testing.T) {
	for _, id := range []string{"edge a", "edge\na", "#edge"} {
		body := "ssh:\n  servers:\n    - id: \"" + id + "\"\n      host: ssh.example.test\n      user: tunnel\n"
		if _, err := loadConfigFile(writeConfig(t, body)); err == nil {
			t.Errorf("server id %q accepted", id)
		}
	}
}

func TestShippedYAMLConfigsLoad(t *testing.T) {
	for _, path := range []string{"config.example.yaml", "debian/ssh-gate.config.yaml"} {
		if _, err := loadConfigFile(path); err != nil {
			t.Errorf("load %s: %v", path, err)
		}
	}
}

// routing.direct.rules is a sequence in the documented form, but the e2e stand
// can only get it from Compose interpolation, which produces text. Both
// spellings must arrive as the same rules, including the comma-separated string
// DIRECT_RULES held before the config file existed. Commas belong to the string
// spelling alone: a sequence entry is one rule even when it contains one.
func TestLoadConfigRulesAcceptsSequenceAndString(t *testing.T) {
	minimal := "proxy:\n  socks5:\n    listen: [\"127.0.0.1:0\"]\nssh:\n  servers:\n    - id: edge-a\n      host: ssh.example.test\n      user: tunnel\n"
	for _, tc := range []struct {
		name, rules string
		want        []string
	}{
		{"sequence", "routing:\n  direct:\n    rules:\n      - re:\\.ru$\n      - ip:198.51.100.0/24\n", []string{`re:\.ru$`, "ip:198.51.100.0/24"}},
		{"string", "routing:\n  direct:\n    rules: re:\\.ru$, ip:198.51.100.0/24\n", []string{`re:\.ru$`, "ip:198.51.100.0/24"}},
		{"sequence with comma", "routing:\n  direct:\n    rules:\n      - \"re:host[0,3]$\"\n", []string{`re:host[0,3]$`}},
		{"empty", "routing:\n  direct:\n    rules:\n", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := loadConfigFile(writeConfig(t, minimal+tc.rules))
			if err != nil {
				t.Fatalf("config: %v", err)
			}
			if !slices.Equal(cfg.directRules, tc.want) {
				t.Errorf("directRules = %q, want %q", cfg.directRules, tc.want)
			}
			if _, err := NewRuleEngine(cfg.directRules); err != nil {
				t.Errorf("rules do not parse: %v", err)
			}
		})
	}
}

// The e2e stand keeps its gate config inline in docker-compose.e2e.yml, because
// only the Compose file can interpolate the server endpoint and the routing
// policy from .env. Compose expands those placeholders at run time, so
// standConfig expands them the same way: a typo in that block would otherwise
// surface only as a container that exits on startup.
func standConfig(t *testing.T, env map[string]string) config {
	t.Helper()
	raw, err := os.ReadFile("docker-compose.e2e.yml")
	if err != nil {
		t.Fatalf("read compose file: %v", err)
	}
	var compose struct {
		Configs map[string]struct {
			Content string `yaml:"content"`
		} `yaml:"configs"`
	}
	if err := yaml.Unmarshal(raw, &compose); err != nil {
		t.Fatalf("parse compose file: %v", err)
	}
	body := compose.Configs["gate_config"].Content
	if body == "" {
		t.Fatal("docker-compose.e2e.yml has no configs.gate_config.content")
	}
	expanded := os.Expand(body, func(expr string) string {
		// Compose writes ${NAME}, ${NAME:-default} and ${NAME:?message}. An
		// empty value takes the default too, which is how Compose treats both.
		name, arg, hasArg := strings.Cut(expr, ":")
		if v, ok := env[name]; ok {
			if v != "" || !hasArg {
				return v
			}
		}
		switch {
		case !hasArg:
			t.Errorf("config references ${%s}, which the stand does not resolve", expr)
		case strings.HasPrefix(arg, "?"):
			t.Errorf("config requires ${%s}, which the stand does not resolve", expr)
		default:
			return strings.TrimPrefix(arg, "-")
		}
		return ""
	})
	cfg, err := loadConfigFile(writeConfig(t, expanded))
	if err != nil {
		t.Fatalf("stand config: %v", err)
	}
	return cfg
}

// e2eEndpoint is the stand's own .env content as far as the test cares: the
// real values are credentials and stay out of the repository. Routing settings
// are present but empty, which is the shape of an .env that predates them.
var e2eEndpoint = map[string]string{
	"SSH_HOST":         "ssh.example.invalid",
	"SSH_PORT":         "2200",
	"SSH_USER":         "tunnel",
	"DIRECT_RULES":     "",
	"DIRECT_IP_FAMILY": "",
}

func TestE2EStandConfigLoads(t *testing.T) {
	cfg := standConfig(t, e2eEndpoint)
	if len(cfg.sshServers) != 1 {
		t.Fatalf("stand must declare exactly one SSH server, got %d", len(cfg.sshServers))
	}
	server := cfg.sshServers[0]
	if server.host != "ssh.example.invalid" || server.port != 2200 || server.user != "tunnel" {
		t.Errorf("endpoint placeholders did not reach the config: %+v", server)
	}
	if server.transports < 2 {
		t.Errorf("the stand needs two transports to show per-slot spread, got %d", server.transports)
	}
}

// The stand must route by the rules in .env, not by its own policy: a stand
// that silently drops them tests a configuration no deployment uses, and an
// empty rule list turns every destination into a tunneled one.
func TestE2EStandRoutesByEnvRules(t *testing.T) {
	rules := `re:\.ru$,re:example\.com$,ip:198.51.100.0/24`
	cfg := standConfig(t, map[string]string{
		"SSH_HOST":         "ssh.example.invalid",
		"SSH_PORT":         "2200",
		"SSH_USER":         "tunnel",
		"DIRECT_RULES":     rules,
		"DIRECT_IP_FAMILY": "ipv4",
	})
	// Compose hands the gate one comma-separated string, so the entries the
	// operator wrote have to arrive one per rule.
	if want := []string{`re:\.ru$`, `re:example\.com$`, "ip:198.51.100.0/24"}; !slices.Equal(cfg.directRules, want) {
		t.Errorf("directRules = %q, want %q from the .env value %q", cfg.directRules, want, rules)
	}
	if cfg.directIPFamily != FamilyIPv4 {
		t.Errorf("directIPFamily = %v, want ipv4 from .env", cfg.directIPFamily)
	}
	engine, err := NewRuleEngine(cfg.directRules)
	if err != nil {
		t.Fatalf("rules from .env do not parse: %v", err)
	}
	for _, tc := range []struct{ host, want string }{
		{"example.ru", `direct:re:\.ru$`},
		{"www.example.com", `direct:re:example\.com$`},
		{"198.51.100.7", `direct:ip:198.51.100.0/24`},
	} {
		if route, reason := engine.decideHost(tc.host); route != RouteDirect || reason != tc.want {
			t.Errorf("decideHost(%q) = (%s, %s), want (direct, %s)", tc.host, route, reason, tc.want)
		}
	}
	if route, reason := engine.decideHost("example.org"); route != RouteTunnel || reason != "fallback" {
		t.Errorf("decideHost(unlisted) = (%s, %s), want (tunnel, fallback)", route, reason)
	}
}

// An operator without DIRECT_RULES in .env still gets a usable stand: the
// placeholders must render no rules and the config default, not one empty rule
// or an empty ip_family.
func TestE2EStandWithoutEnvRulesStillLoads(t *testing.T) {
	cfg := standConfig(t, e2eEndpoint)
	if len(cfg.directRules) != 0 {
		t.Errorf("directRules = %q, want no rules when .env has none", cfg.directRules)
	}
	if cfg.directIPFamily != FamilyBoth {
		t.Errorf("directIPFamily = %v, want the config default both", cfg.directIPFamily)
	}
	if _, err := NewRuleEngine(cfg.directRules); err != nil {
		t.Errorf("empty rules must parse: %v", err)
	}
}

func TestLoadConfigYAMLDefaultsAndNestedProxy(t *testing.T) {
	cfg, err := loadConfigFile(writeConfig(t, `proxy:
  socks5:
    listen: ["0.0.0.0:1080"]
  http:
    listen: ["0.0.0.0:3128"]
ssh:
  servers:
    - id: edge-a
      host: ssh.example.test
      user: tunnel
`))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cfg.proxyModes, []string{"socks5", "http"}) || cfg.sshPort != 22 || cfg.dialTimeout != 30*time.Second {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	if !slices.Equal(cfg.socks5Addrs, []string{"0.0.0.0:1080"}) || !slices.Equal(cfg.httpAddrs, []string{"0.0.0.0:3128"}) {
		t.Fatalf("proxy listeners: %v %v", cfg.socks5Addrs, cfg.httpAddrs)
	}
}

func TestLoadConfigRejectsUnknownAndDuplicateServerID(t *testing.T) {
	for _, body := range []string{
		"proxy:\n  socks5:\n    listen: [\":1080\"]\nunknown: true\n",
		"proxy:\n  socks5:\n    listen: [\":1080\"]\nssh:\n  servers:\n    - {id: x, host: a, user: u}\n    - {id: x, host: b, user: u}\n",
	} {
		if _, err := loadConfigFile(writeConfig(t, body)); err == nil {
			t.Fatalf("accepted invalid YAML config: %s", body)
		}
	}
}

func TestLoadConfigAllowsNoSSHServers(t *testing.T) {
	cfg, err := loadConfigFile(writeConfig(t, "proxy:\n  http:\n    listen: [\":3128\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.sshHost != "" || !slices.Equal(cfg.proxyModes, []string{"http"}) {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}
