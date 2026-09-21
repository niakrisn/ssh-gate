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
	socks5Addr           string
	httpAddr             string
	directRules          string
	directIPFamily       IPFamily
	dohHost              string
	healthAddr           string
	sshKeepalivePeriod   time.Duration
	sshKeepaliveInterval int
	sshKeepaliveProbes   int
	dialTimeout          time.Duration
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
		os.WriteFile(filepath.Join(cfg.dataDir, firstRunDoneFile), nil, 0644)
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

	if contains(cfg.proxyModes, "socks5") {
		s5, err := NewSOCKS5Server(cfg.socks5Addr, opener)
		if err != nil {
			log.Fatal().Err(err).Msg("SOCKS5 server")
		}
		s5.Start()
		servers = append(servers, server{Name: "SOCKS5", Shutdown: s5.Shutdown})
	}

	if contains(cfg.proxyModes, "http") {
		hp, err := NewHTTPProxyServer(cfg.httpAddr, opener)
		if err != nil {
			log.Fatal().Err(err).Msg("HTTP proxy")
		}
		hp.Start()
		servers = append(servers, server{Name: "HTTP", Shutdown: hp.Shutdown})
	}

	// Health/ready endpoint + Web UI.
	hs, err := NewHealthServer(cfg.healthAddr, cfg.sshHost, cfg.sshPort, dialer, tracker)
	if err != nil {
		log.Fatal().Err(err).Msg("health server")
	}
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
	shutdownServers(ctx, servers)
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

	// Validate SSH_HOST
	sshHost, err := getEnvRequired("SSH_HOST")
	if err != nil {
		return config{}, fmt.Errorf("configuration error: %w", err)
	}
	if sshHost == "" {
		return config{}, fmt.Errorf("SSH_HOST cannot be empty")
	}

	// Validate SSH_USER
	sshUser, err := getEnvRequired("SSH_USER")
	if err != nil {
		return config{}, fmt.Errorf("configuration error: %w", err)
	}
	if sshUser == "" {
		return config{}, fmt.Errorf("SSH_USER cannot be empty")
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

	// Validate listen addresses
	socks5Addr := getEnv("SOCKS5_LISTEN", ":1080")
	if err := validateHostPort(socks5Addr); err != nil {
		return config{}, fmt.Errorf("invalid SOCKS5_LISTEN: %w", err)
	}

	httpAddr := getEnv("HTTP_LISTEN", ":3128")
	if err := validateHostPort(httpAddr); err != nil {
		return config{}, fmt.Errorf("invalid HTTP_LISTEN: %w", err)
	}

	healthAddr := getEnv("HEALTH_LISTEN", "127.0.0.1:9090")
	if err := validateHostPort(healthAddr); err != nil {
		return config{}, fmt.Errorf("invalid HEALTH_LISTEN: %w", err)
	}

	// Validate DATA_DIR
	dataDir := getEnv("DATA_DIR", "/data")
	if dataDir == "" {
		return config{}, fmt.Errorf("DATA_DIR cannot be empty")
	}

	// Validate DOH_HOST: a hostname (optionally with port 443) for the
	// DNS-over-HTTPS endpoint that tunnel destinations resolve through.
	dohHost := getEnv("DOH_HOST", "cloudflare-dns.com")
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
		socks5Addr:           socks5Addr,
		httpAddr:             httpAddr,
		directRules:          getEnv("DIRECT_RULES", ""),
		directIPFamily:       directIPFamily,
		dohHost:              dohHost,
		healthAddr:           healthAddr,
		sshKeepalivePeriod:   sshKeepalivePeriod,
		sshKeepaliveInterval: sshKeepaliveInterval,
		sshKeepaliveProbes:   sshKeepaliveProbes,
		dialTimeout:          dialTimeout,
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
// Empty or non-positive values disable OS keepalive (returned as 0).
func parseKeepalivePeriod(raw string) (time.Duration, error) {
	if raw == "" {
		return 0, nil
	}
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
// returns whole seconds for TCP_KEEPINTVL. Empty or zero keeps the kernel
// default (returned as 0); sub-second values round up to 1 s.
func parseKeepaliveInterval(raw string) (int, error) {
	if raw == "" {
		return 0, nil
	}
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
// TCP_KEEPCNT. Empty or zero keeps the kernel default (returned as 0).
func parseKeepaliveProbes(raw string) (int, error) {
	if raw == "" {
		return 0, nil
	}
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

func getEnvRequired(key string) (string, error) {
	v := os.Getenv(key)
	if v == "" {
		return "", fmt.Errorf("required env var %s is empty", key)
	}
	return v, nil
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
		_, port, _ := net.SplitHostPort(cfg.socks5Addr)
		if port == "" {
			port = "1080"
		}
		fmt.Printf("SOCKS5 proxy: localhost:%s\n", port)
	}

	if contains(cfg.proxyModes, "http") {
		_, port, _ := net.SplitHostPort(cfg.httpAddr)
		if port == "" {
			port = "3128"
		}
		fmt.Printf("HTTP proxy:  localhost:%s\n", port)
	}
	fmt.Println()
}
