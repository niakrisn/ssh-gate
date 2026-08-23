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

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type config struct {
	sshHost        string
	sshPort        int
	sshUser        string
	dataDir        string
	proxyModes     []string
	socks5Addr     string
	mtprotoAddr    string
	directRules    string
	directIPFamily IPFamily
	dohIP          string
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
		host:    cfg.sshHost,
		port:    cfg.sshPort,
		user:    cfg.sshUser,
		keyPath: filepath.Join(cfg.dataDir, sshKeyFile),
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

	// Graceful shutdown on SIGTERM/SIGINT
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		cancel()
	}()

	<-ctx.Done()
	log.Info().Msg("shutting down...")
	shutdownServers(ctx, servers)
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
	portStr := getEnv("SSH_PORT", "22")
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return config{}, fmt.Errorf("invalid SSH_PORT %q: %w", portStr, err)
	}

	modesRaw := getEnv("PROXY_MODES", "socks5")
	modes := parseModes(modesRaw)

	sshHost, err := getEnvRequired("SSH_HOST")
	if err != nil {
		return config{}, err
	}
	sshUser, err := getEnvRequired("SSH_USER")
	if err != nil {
		return config{}, err
	}

	directIPFamily, err := parseIPFamily(getEnv("DIRECT_IP_FAMILY", "both"))
	if err != nil {
		return config{}, err
	}

	return config{
		sshHost:        sshHost,
		sshPort:        port,
		sshUser:        sshUser,
		dataDir:        getEnv("DATA_DIR", "/data"),
		proxyModes:     modes,
		socks5Addr:     getEnv("SOCKS5_LISTEN", ":1080"),
		mtprotoAddr:    getEnv("MTPROTO_LISTEN", ":20443"),
		directRules:    getEnv("DIRECT_RULES", ""),
		directIPFamily: directIPFamily,
		dohIP:          getEnv("DOH_IP", "9.9.9.9"),
	}, nil
}

func parseModes(raw string) []string {
	var modes []string
	for _, m := range strings.Split(raw, ",") {
		m = strings.TrimSpace(strings.ToLower(m))
		if m == "" {
			continue
		}
		modes = append(modes, m)
	}
	if len(modes) == 0 {
		modes = []string{"socks5"}
	}
	return modes
}

func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
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
