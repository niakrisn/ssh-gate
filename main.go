package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type config struct {
	sshHost              string
	sshPort              int
	sshUser              string
	dataDir              string
	proxyModes           []string
	socks5Addrs          []string
	httpAddrs            []string
	directRules          string
	directIPFamily       IPFamily
	dohHost              string
	healthAddr           string
	sshKeepalivePeriod   time.Duration
	sshKeepaliveInterval int
	sshKeepaliveProbes   int
	dialTimeout          time.Duration
	maxConnections       int
	uiAllowedHosts       []string
}

type server struct {
	Name     string
	Shutdown func(context.Context) error
}

// connHistoryMaxAge bounds the in-memory connection history window.
// SSH_DIAL_TIMEOUT must stay below it: dropStalled moves dialing records
// older than this window to history, so a dial in flight past it would lose
// its record.
const connHistoryMaxAge = 10 * time.Minute

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	setLogLevel(getEnv("LOG_LEVEL", "info"))
	log.Logger = log.With().Caller().Logger()

	cfg, err := loadConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("load config")
	}

	if err := os.MkdirAll(cfg.dataDir, 0700); err != nil {
		log.Fatal().Err(err).Str("dir", cfg.dataDir).Msg("create data dir")
	}

	pubKey, err := EnsureSSHKeyPair(cfg.dataDir)
	if err != nil {
		log.Fatal().Err(err).Msg("ensure SSH key")
	}

	if _, err := os.Stat(filepath.Join(cfg.dataDir, firstRunDoneFile)); os.IsNotExist(err) {
		printFirstRun(pubKey, cfg)
		if err := os.WriteFile(filepath.Join(cfg.dataDir, firstRunDoneFile), nil, 0644); err != nil {
			log.Warn().Err(err).Msg("save first-run marker; the hint prints again on next start")
		}
	}

	// Connection history is in-memory only: last 1000 connections / 10 minutes.
	tracker := NewConnTracker(1000, connHistoryMaxAge)

	dialer, err := newSSHDialer(sshDialerCfg{
		host:              cfg.sshHost,
		port:              cfg.sshPort,
		user:              cfg.sshUser,
		keyPath:           filepath.Join(cfg.dataDir, sshKeyFile),
		keepalivePeriod:   cfg.sshKeepalivePeriod,
		keepaliveInterval: cfg.sshKeepaliveInterval,
		keepaliveProbes:   cfg.sshKeepaliveProbes,
		tracker:           tracker,
		dialTimeout:       cfg.dialTimeout,
	})
	if err != nil {
		log.Fatal().Err(err).Msg("SSH dialer")
	}

	rules, err := NewRuleEngine(cfg.directRules)
	if err != nil {
		log.Fatal().Err(err).Msg("rule engine")
	}

	// Route tunnel-destination resolution through the configured DoH
	// endpoint, inside the SSH tunnel. Direct destinations keep local DNS.
	if cfg.dohHost != "" {
		rules.SetDOH(cfg.dohHost, dialer)
	}

	// One Opener per process: both proxy protocols share the route/resolve
	// policy (direct via local DNS, tunnel via DoH) and the SSH dialer.
	opener := &Opener{rules: rules, d: dialer, family: cfg.directIPFamily}

	var servers []server

	// One limit for all proxy listeners: descriptors and goroutines are
	// per process.
	limit := newConnLimiter(cfg.maxConnections)

	// One server instance per listen address; all instances share the
	// Opener (route policy, DNS, SSH dialer).
	if contains(cfg.proxyModes, "socks5") {
		for _, addr := range cfg.socks5Addrs {
			s5, err := NewSOCKS5Server(addr, opener)
			if err != nil {
				log.Fatal().Err(err).Str("listen", addr).Msg("SOCKS5 server")
			}
			s5.SetConnLimit(limit)
			s5.Start()
			servers = append(servers, server{Name: "SOCKS5 " + addr, Shutdown: s5.Shutdown})
		}
	}

	if contains(cfg.proxyModes, "http") {
		for _, addr := range cfg.httpAddrs {
			hp, err := NewHTTPProxyServer(addr, opener)
			if err != nil {
				log.Fatal().Err(err).Str("listen", addr).Msg("HTTP proxy")
			}
			hp.SetConnLimit(limit)
			hp.Start()
			servers = append(servers, server{Name: "HTTP " + addr, Shutdown: hp.Shutdown})
		}
	}

	// Health/ready endpoint + Web UI.
	hs, err := NewHealthServer(cfg.healthAddr, cfg.sshHost, cfg.sshPort, dialer, tracker)
	if err != nil {
		log.Fatal().Err(err).Msg("health server")
	}
	hs.AllowHosts(cfg.uiAllowedHosts)
	hs.Start()
	servers = append(servers, server{Name: "health", Shutdown: hs.Shutdown})

	// Graceful shutdown on SIGTERM/SIGINT
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		cancel()
	}()

	rules.Start(ctx)

	<-ctx.Done()
	log.Info().Msg("shutting down...")
	// The signal ctx is already canceled; passing it to the servers would
	// skip the relay drain entirely. Give the drain its own deadline,
	// comfortably below compose's stop_grace_period (10 s).
	const shutdownDrainTimeout = 5 * time.Second
	drainCtx, cancelDrain := context.WithTimeout(context.Background(), shutdownDrainTimeout)
	defer cancelDrain()
	shutdownServers(drainCtx, servers)
	rules.Stop()
	dialer.stop()
}

func shutdownServers(ctx context.Context, servers []server) {
	for _, s := range servers {
		if err := s.Shutdown(ctx); err != nil {
			log.Warn().Str("server", s.Name).Err(err).Msg("shutdown")
		} else {
			log.Info().Str("server", s.Name).Msg("stopped")
		}
	}
}

func loadConfig() (config, error) {
	// Validate SSH_PORT
	portStr := getEnv("SSH_PORT", "22")
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return config{}, fmt.Errorf("invalid SSH_PORT %q: %w", portStr, err)
	}
	if err := validatePort(port); err != nil {
		return config{}, fmt.Errorf("invalid SSH_PORT: %w", err)
	}

	// Validate PROXY_MODES
	modesRaw := getEnv("PROXY_MODES", "socks5")
	modes, err := parseModes(modesRaw)
	if err != nil {
		return config{}, fmt.Errorf("invalid PROXY_MODES: %w", err)
	}

	// Validate SSH_HOST (getEnvRequired already rejects an empty value)
	sshHost, err := getEnvRequired("SSH_HOST")
	if err != nil {
		return config{}, fmt.Errorf("configuration error: %w", err)
	}
	// The tunnel connects over IPv4 only (dialer.go dials tcp4), so an
	// IPv6 literal could never connect; fail at startup, not in the
	// reconnect loop.
	if ip := net.ParseIP(strings.Trim(sshHost, "[]")); ip != nil && ip.To4() == nil {
		return config{}, fmt.Errorf("invalid SSH_HOST %q: the tunnel connects over IPv4 only, use an IPv4 address or a name with an A record", sshHost)
	}

	// Validate SSH_USER
	sshUser, err := getEnvRequired("SSH_USER")
	if err != nil {
		return config{}, fmt.Errorf("configuration error: %w", err)
	}

	// Validate DIRECT_IP_FAMILY
	directIPFamily, err := parseIPFamily(getEnv("DIRECT_IP_FAMILY", "both"))
	if err != nil {
		return config{}, fmt.Errorf("invalid DIRECT_IP_FAMILY: %w", err)
	}

	// Validate SSH_KEEPALIVE_PERIOD
	sshKeepalivePeriod, err := parseKeepalivePeriod(getEnv("SSH_KEEPALIVE_PERIOD", "10s"))
	if err != nil {
		return config{}, fmt.Errorf("invalid SSH_KEEPALIVE_PERIOD: %w", err)
	}

	// Validate SSH_KEEPALIVE_INTERVAL
	sshKeepaliveInterval, err := parseKeepaliveInterval(getEnv("SSH_KEEPALIVE_INTERVAL", "1s"))
	if err != nil {
		return config{}, fmt.Errorf("invalid SSH_KEEPALIVE_INTERVAL: %w", err)
	}

	// Validate SSH_KEEPALIVE_PROBES
	sshKeepaliveProbes, err := parseKeepaliveProbes(getEnv("SSH_KEEPALIVE_PROBES", "5"))
	if err != nil {
		return config{}, fmt.Errorf("invalid SSH_KEEPALIVE_PROBES: %w", err)
	}

	// Validate SSH_DIAL_TIMEOUT
	dialTimeout, err := parseDialTimeout(getEnv("SSH_DIAL_TIMEOUT", "30s"))
	if err != nil {
		return config{}, fmt.Errorf("invalid SSH_DIAL_TIMEOUT: %w", err)
	}
	if dialTimeout >= connHistoryMaxAge {
		return config{}, fmt.Errorf("invalid SSH_DIAL_TIMEOUT %s: must be below %s (connection history window)", dialTimeout, connHistoryMaxAge)
	}

	// Validate MAX_CONNECTIONS
	maxConnections, err := parseMaxConnections(getEnv("MAX_CONNECTIONS", "4096"))
	if err != nil {
		return config{}, err
	}

	// Validate listen addresses (comma-separated lists; one server per
	// address).
	socks5Addrs, err := parseListenList("SOCKS5_LISTEN", getEnv("SOCKS5_LISTEN", ":1080"))
	if err != nil {
		return config{}, err
	}

	httpAddrs, err := parseListenList("HTTP_LISTEN", getEnv("HTTP_LISTEN", ":3128"))
	if err != nil {
		return config{}, err
	}

	healthAddr := getEnv("HEALTH_LISTEN", "127.0.0.1:9090")
	if err := validateHostPort(healthAddr); err != nil {
		return config{}, fmt.Errorf("invalid HEALTH_LISTEN: %w", err)
	}

	// Validate UI_ALLOWED_HOSTS
	uiAllowedHosts, err := parseHostList("UI_ALLOWED_HOSTS", getEnv("UI_ALLOWED_HOSTS", ""))
	if err != nil {
		return config{}, err
	}

	// Validate DATA_DIR
	dataDir := getEnv("DATA_DIR", "/data")
	if dataDir == "" {
		return config{}, fmt.Errorf("DATA_DIR cannot be empty")
	}

	// Validate DOH_HOST: a hostname (optionally with port 443) for the
	// DNS-over-HTTPS endpoint that tunnel destinations resolve through.
	// Read strictly: unset falls back to the default endpoint, set-but-empty
	// disables DoH (main wires SetDOH only for a non-empty host), as
	// .env.example documents. getEnv would collapse empty to the default and
	// make that promise unreachable. Note compose interpolates
	// ${DOH_HOST:-cloudflare-dns.com}, so an empty value there still becomes
	// the default — under compose disable DoH by not setting the variable
	// (deb/systemd: just omit it).
	dohHost, ok := os.LookupEnv("DOH_HOST")
	if !ok {
		dohHost = "cloudflare-dns.com"
	}
	if dohHost != "" {
		if strings.Contains(dohHost, "/") {
			return config{}, fmt.Errorf("invalid DOH_HOST %q: use a hostname, e.g. cloudflare-dns.com", dohHost)
		}
		hostOnly := dohHost
		if host, port, err := net.SplitHostPort(dohHost); err == nil {
			hostOnly = host
			if port != "443" {
				return config{}, fmt.Errorf("invalid DOH_HOST %q: only port 443 is supported", dohHost)
			}
		}
		// IP-literal endpoints are unusable: TLS certificates are validated
		// against the hostname, and DoH provider certs carry no IP SANs.
		if net.ParseIP(hostOnly) != nil {
			return config{}, fmt.Errorf("invalid DOH_HOST %q: use a hostname (e.g. cloudflare-dns.com), not an IP address", dohHost)
		}
	}

	return config{
		sshHost:              sshHost,
		sshPort:              port,
		sshUser:              sshUser,
		dataDir:              dataDir,
		proxyModes:           modes,
		socks5Addrs:          socks5Addrs,
		httpAddrs:            httpAddrs,
		directRules:          getEnv("DIRECT_RULES", ""),
		directIPFamily:       directIPFamily,
		dohHost:              dohHost,
		healthAddr:           healthAddr,
		sshKeepalivePeriod:   sshKeepalivePeriod,
		sshKeepaliveInterval: sshKeepaliveInterval,
		sshKeepaliveProbes:   sshKeepaliveProbes,
		dialTimeout:          dialTimeout,
		maxConnections:       maxConnections,
		uiAllowedHosts:       uiAllowedHosts,
	}, nil
}

func parseModes(raw string) ([]string, error) {
	valid := map[string]bool{"socks5": true, "http": true}
	var modes []string
	for _, m := range strings.Split(raw, ",") {
		m = strings.TrimSpace(strings.ToLower(m))
		if m == "" {
			continue
		}
		if !valid[m] {
			return nil, fmt.Errorf("unknown proxy mode %q (valid: socks5, http)", m)
		}
		modes = append(modes, m)
	}
	if len(modes) == 0 {
		return []string{"socks5"}, nil
	}
	return modes, nil
}

// parseListenList parses a comma-separated list of host:port listen
// addresses (one proxy server per address). Whitespace around items is
// ignored, empty items are skipped, at least one address is required.
func parseListenList(name, raw string) ([]string, error) {
	var addrs []string
	for _, addr := range strings.Split(raw, ",") {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		if err := validateHostPort(addr); err != nil {
			return nil, fmt.Errorf("invalid %s address %q: %w", name, addr, err)
		}
		addrs = append(addrs, addr)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("invalid %s %q: no listen addresses", name, raw)
	}
	return addrs, nil
}

// parseHostList parses a comma-separated list of host names or IP
// addresses without ports. Whitespace is trimmed, empty items skipped.
func parseHostList(name, raw string) ([]string, error) {
	var hosts []string
	for _, h := range strings.Split(raw, ",") {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(h); err == nil || strings.ContainsAny(h, "/[] ") {
			return nil, fmt.Errorf("invalid %s entry %q: want a host name or IP address without port", name, h)
		}
		hosts = append(hosts, h)
	}
	return hosts, nil
}

func setLogLevel(level string) {
	switch strings.ToLower(level) {
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// parseKeepalivePeriod parses SSH_KEEPALIVE_PERIOD as a Go duration.
// Non-positive values disable OS keepalive (returned as 0). Empty input is
// a hard error: loadConfig always supplies a non-empty default, so an empty
// raw value here would mean a caller bug, not a configuration choice.
func parseKeepalivePeriod(raw string) (time.Duration, error) {
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid SSH_KEEPALIVE_PERIOD %q (Go duration, e.g. 90s): %w", raw, err)
	}
	if d <= 0 {
		return 0, nil
	}
	return d, nil
}

// parseKeepaliveInterval parses SSH_KEEPALIVE_INTERVAL as a Go duration and
// returns whole seconds for TCP_KEEPINTVL. Zero keeps the kernel default
// (returned as 0); sub-second values round up to 1 s. Empty input is a hard
// error: loadConfig always supplies a non-empty default.
func parseKeepaliveInterval(raw string) (int, error) {
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid SSH_KEEPALIVE_INTERVAL %q (Go duration, e.g. 1s): %w", raw, err)
	}
	if d < 0 {
		return 0, fmt.Errorf("SSH_KEEPALIVE_INTERVAL must be non-negative, got %s", raw)
	}
	if d == 0 {
		return 0, nil
	}
	s := int(d / time.Second)
	if s < 1 {
		s = 1
	}
	return s, nil
}

// parseKeepaliveProbes parses SSH_KEEPALIVE_PROBES as an integer for
// TCP_KEEPCNT. Zero keeps the kernel default (returned as 0). Empty input is
// a hard error: loadConfig always supplies a non-empty default.
func parseKeepaliveProbes(raw string) (int, error) {
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid SSH_KEEPALIVE_PROBES %q (integer, e.g. 5): %w", raw, err)
	}
	if n < 0 {
		return 0, fmt.Errorf("SSH_KEEPALIVE_PROBES must be non-negative, got %d", n)
	}
	return n, nil
}

// parseDialTimeout parses SSH_DIAL_TIMEOUT as a Go duration.
// A non-positive value is rejected: an unbounded destination dial can
// hang forever on a blackholed host.
func parseDialTimeout(raw string) (time.Duration, error) {
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid SSH_DIAL_TIMEOUT %q (Go duration, e.g. 30s): %w", raw, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("SSH_DIAL_TIMEOUT must be positive, got %s", raw)
	}
	return d, nil
}

// parseMaxConnections parses MAX_CONNECTIONS, the limit of concurrent
// client connections over all proxy listeners. 0 disables the limit.
func parseMaxConnections(raw string) (int, error) {
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid MAX_CONNECTIONS %q (integer, e.g. 4096): %w", raw, err)
	}
	if n < 0 {
		return 0, fmt.Errorf("MAX_CONNECTIONS must be non-negative (0 = no limit), got %d", n)
	}
	return n, nil
}

func getEnvRequired(key string) (string, error) {
	v := os.Getenv(key)
	if v == "" {
		return "", fmt.Errorf("required env var %s is empty", key)
	}
	return v, nil
}

// firstRunPorts returns the unique ports of the listen addresses in order,
// so the first-run hint lists each reachable port once. An address without
// a parseable port falls back to the protocol default.
func firstRunPorts(addrs []string, defaultPort string) []string {
	seen := map[string]bool{}
	var ports []string
	for _, addr := range addrs {
		_, port, _ := net.SplitHostPort(addr)
		if port == "" {
			port = defaultPort
		}
		if !seen[port] {
			seen[port] = true
			ports = append(ports, port)
		}
	}
	return ports
}

func printFirstRun(pubKey string, cfg config) {
	fmt.Println()
	fmt.Println("=== ssh-gate first run ===")
	fmt.Println()
	fmt.Println("Add to VPS ~/.ssh/authorized_keys:")
	fmt.Println()
	fmt.Printf("   command=\"echo 'tunnel only'\",no-pty,no-agent-forwarding,no-X11-forwarding,no-user-rc %s\n", pubKey)
	fmt.Println()

	if contains(cfg.proxyModes, "socks5") {
		for _, port := range firstRunPorts(cfg.socks5Addrs, "1080") {
			fmt.Printf("SOCKS5 proxy: localhost:%s\n", port)
		}
	}

	if contains(cfg.proxyModes, "http") {
		for _, port := range firstRunPorts(cfg.httpAddrs, "3128") {
			fmt.Printf("HTTP proxy:  localhost:%s\n", port)
		}
	}
	fmt.Println()
}
