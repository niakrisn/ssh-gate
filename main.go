package main

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

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

	secret, err := EnsureMTProtoSecret(cfg.dataDir)
	if err != nil {
		log.Fatal().Err(err).Msg("ensure MTProto secret")
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
	}, cfg.ipAllowlist)
	if err != nil {
		log.Fatal().Err(err).Msg("SSH dialer")
	}

	if err := runProxy(secret, cfg.listenAddr(), dialer, cfg.dohIP); err != nil {
		log.Fatal().Err(err).Msg("proxy")
	}
}

type config struct {
	sshHost     string
	sshPort     int
	sshUser     string
	dataDir     string
	listen      string
	dohIP       string
	ipAllowlist []netip.Prefix
}

func (c config) listenAddr() string {
	host, port, err := net.SplitHostPort(c.listen)
	if err != nil {
		return c.listen
	}
	if port == "" {
		port = "20443"
	}
	if host == "" {
		return ":" + port
	}
	return net.JoinHostPort(host, port)
}

func loadConfig() (config, error) {
	portStr := getEnv("SSH_PORT", "22")
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return config{}, fmt.Errorf("invalid SSH_PORT %q: %w", portStr, err)
	}

	allowlist, err := parseIPAllowlist(getEnv("IP_ALLOWLIST", ""))
	if err != nil {
		return config{}, fmt.Errorf("parse IP_ALLOWLIST: %w", err)
	}

	return config{
		sshHost:     getEnvRequired("SSH_HOST"),
		sshPort:     port,
		sshUser:     getEnvRequired("SSH_USER"),
		dataDir:     getEnv("DATA_DIR", "/data"),
		listen:      getEnv("MTPROTO_LISTEN", ":20443"),
		dohIP:       getEnv("DOH_IP", "9.9.9.9"),
		ipAllowlist: allowlist,
	}, nil
}

func parseIPAllowlist(raw string) ([]netip.Prefix, error) {
	if raw == "" {
		return nil, nil
	}

	var prefixes []netip.Prefix
	for _, cidr := range strings.Split(raw, ",") {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
		}
		prefixes = append(prefixes, p)
	}
	return prefixes, nil
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

func getEnvRequired(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Warn().Str("key", key).Msg("required env var is empty")
	}
	return v
}

func printFirstRun(secret, pubKey string, cfg config) {
	_, port, _ := net.SplitHostPort(cfg.listen)
	if port == "" {
		port = "20443"
	}

	fmt.Println()
	fmt.Println("=== mtproto-ssh first run ===")
	fmt.Println()
	fmt.Println("1. Add to VPS ~/.ssh/authorized_keys:")
	fmt.Println()
	fmt.Printf("   command=\"echo 'tunnel only'\",no-pty,no-agent-forwarding,no-X11-forwarding,no-user-rc %s\n", pubKey)
	fmt.Println()
	fmt.Println("2. Telegram proxy link:")
	fmt.Printf("   tg://proxy?server=localhost&port=%s&secret=%s\n", port, secret)
	fmt.Println()
	fmt.Println("3. Or connect in Settings → Data and Storage → Proxy → Secret Chat (FakeTLS)")
	fmt.Println()
}
