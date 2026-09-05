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
	sshHost            string
	sshPort            int
	sshUser            string
	dataDir            string
	proxyModes         []string
	socks5Addr         string
	mtprotoAddr        string
	directRules        string
	directIPFamily     IPFamily
	dohIP              string
	healthAddr         string
	sshKeepalivePeriod time.Duration
}

type server struct {
	Name     string
	Shutdown func(context.Context) error
}

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

	secret := ""
	if contains(cfg.proxyModes, "mtproto") {
		secret, err = EnsureMTProtoSecret(cfg.dataDir)
		if err != nil {
			log.Fatal().Err(err).Msg("ensure MTProto secret")
		}
	}

	if _, err := os.Stat(filepath.Join(cfg.dataDir, firstRunDoneFile)); os.IsNotExist(err) {
		printFirstRun(secret, pubKey, cfg)
		os.WriteFile(filepath.Join(cfg.dataDir, firstRunDoneFile), nil, 0644)
	}

	dialer, err := newSSHDialer(sshDialerCfg{
		host:            cfg.sshHost,
		port:            cfg.sshPort,
		user:            cfg.sshUser,
		keyPath:         filepath.Join(cfg.dataDir, sshKeyFile),
		keepalivePeriod: cfg.sshKeepalivePeriod,
	})
	if err != nil {
		log.Fatal().Err(err).Msg("SSH dialer")
	}

	rules, err := NewRuleEngine(cfg.directRules)
	if err != nil {
		log.Fatal().Err(err).Msg("rule engine")
	}

	var servers []server

	if contains(cfg.proxyModes, "socks5") {
		s5, err := NewSOCKS5Server(cfg.socks5Addr, rules, dialer, cfg.directIPFamily)
		if err != nil {
			log.Fatal().Err(err).Msg("SOCKS5 server")
		}
		s5.Start()
		servers = append(servers, server{Name: "SOCKS5", Shutdown: s5.Shutdown})
	}

	if contains(cfg.proxyModes, "mtproto") {
		mt, err := newMTProtoServer(cfg.mtprotoAddr, secret, dialer.NetworkDialer(), cfg.dohIP)
		if err != nil {
			log.Fatal().Err(err).Msg("MTProto server")
		}
		mt.Start()
		servers = append(servers, server{Name: "MTProto", Shutdown: mt.Shutdown})
	}

	// Health/ready endpoint
	hs, err := NewHealthServer(cfg.healthAddr, dialer)
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
	sshKeepalivePeriod, err := parseKeepalivePeriod(getEnv("SSH_KEEPALIVE_PERIOD", "90s"))
	if err != nil {
		return config{}, fmt.Errorf("invalid SSH_KEEPALIVE_PERIOD: %w", err)
	}

	// Validate listen addresses
	socks5Addr := getEnv("SOCKS5_LISTEN", ":1080")
	if err := validateHostPort(socks5Addr); err != nil {
		return config{}, fmt.Errorf("invalid SOCKS5_LISTEN: %w", err)
	}

	mtprotoAddr := getEnv("MTPROTO_LISTEN", ":20443")
	if err := validateHostPort(mtprotoAddr); err != nil {
		return config{}, fmt.Errorf("invalid MTPROTO_LISTEN: %w", err)
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

	// Validate DOH_IP
	dohIP := getEnv("DOH_IP", "9.9.9.9")
	if dohIP != "" {
		if ip := net.ParseIP(dohIP); ip == nil {
			return config{}, fmt.Errorf("invalid DOH_IP %q: not a valid IP address", dohIP)
		}
	}

	return config{
		sshHost:            sshHost,
		sshPort:            port,
		sshUser:            sshUser,
		dataDir:            dataDir,
		proxyModes:         modes,
		socks5Addr:         socks5Addr,
		mtprotoAddr:        mtprotoAddr,
		directRules:        getEnv("DIRECT_RULES", ""),
		directIPFamily:     directIPFamily,
		dohIP:              dohIP,
		healthAddr:         healthAddr,
		sshKeepalivePeriod: sshKeepalivePeriod,
	}, nil
}

func parseModes(raw string) ([]string, error) {
	valid := map[string]bool{"socks5": true, "mtproto": true}
	var modes []string
	for _, m := range strings.Split(raw, ",") {
		m = strings.TrimSpace(strings.ToLower(m))
		if m == "" {
			continue
		}
		if !valid[m] {
			return nil, fmt.Errorf("unknown proxy mode %q (valid: socks5, mtproto)", m)
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

func getEnvRequired(key string) (string, error) {
	v := os.Getenv(key)
	if v == "" {
		return "", fmt.Errorf("required env var %s is empty", key)
	}
	return v, nil
}

func printFirstRun(secret, pubKey string, cfg config) {
	fmt.Println()
	fmt.Println("=== mtproto-ssh first run ===")
	fmt.Println()
	fmt.Println("1. Add to VPS ~/.ssh/authorized_keys:")
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

	if secret != "" {
		_, port, _ := net.SplitHostPort(cfg.mtprotoAddr)
		if port == "" {
			port = "20443"
		}
		fmt.Println()
		fmt.Println("2. Telegram proxy link:")
		fmt.Printf("   tg://proxy?server=localhost&port=%s&secret=%s\n", port, secret)
		fmt.Println()
		fmt.Println("3. Or connect in Settings → Data and Storage → Proxy → Secret Chat (FakeTLS)")
	}
	fmt.Println()
}
