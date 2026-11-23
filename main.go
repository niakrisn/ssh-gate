package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go.yaml.in/yaml/v3"
)

type config struct {
	sshServers             []sshServerConfig
	sshHost                string
	sshPort                int
	sshUser                string
	dataDir                string
	proxyModes             []string
	socks5Addrs            []string
	httpAddrs              []string
	directRules            []string
	directIPFamily         IPFamily
	dohHost                string
	tunnelDNS              []string
	healthAddr             string
	sshKeepalivePeriod     time.Duration
	sshKeepaliveInterval   int
	sshKeepaliveProbes     int
	dialTimeout            time.Duration
	uiAllowedHosts         []string
	logLevel               string
	accessLog              bool
	balancingHashKey       string
	retryMaxAttempts       int
	passiveMaxFails        int
	passiveFailTimeout     time.Duration
	passiveUnhealthyPeriod time.Duration
	healthURL              string
	healthInterval         time.Duration
	healthTimeout          time.Duration
	healthMaxFails         int
	healthSuccesses        int
}

type sshServerConfig struct {
	id                     string
	host                   string
	port                   int
	user                   string
	transports             int
	maxClientTunnels       int
	maxPendingOpens        int
	maxPendingServiceOpens int
}

// ruleList is routing.direct.rules. It takes the documented YAML sequence and a
// single comma-separated string, which is the form DIRECT_RULES held before the
// config file existed. The string form exists because Compose can only
// interpolate .env as text: rules routinely contain "[" and "]", and those are
// flow-sequence indicators in YAML, so a list spelled `[${DIRECT_RULES}]`
// fails to parse. Only the string form splits on commas - it is defined by them
// - so a rule containing a comma has to be its own sequence entry.
type ruleList []string

func (l *ruleList) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode || node.Tag == "!!null" {
		var entries []string
		if err := node.Decode(&entries); err != nil {
			return err
		}
		*l = entries
		return nil
	}
	var raw string
	if err := node.Decode(&raw); err != nil {
		return err
	}
	var entries []string
	for _, entry := range strings.Split(raw, ",") {
		if entry = strings.TrimSpace(entry); entry != "" {
			entries = append(entries, entry)
		}
	}
	*l = entries
	return nil
}

type fileConfig struct {
	Proxy struct {
		SOCKS5 *struct {
			Listen []string `yaml:"listen"`
		} `yaml:"socks5"`
		HTTP *struct {
			Listen []string `yaml:"listen"`
		} `yaml:"http"`
	} `yaml:"proxy"`
	Routing struct {
		Direct struct {
			Rules    ruleList `yaml:"rules"`
			IPFamily string   `yaml:"ip_family"`
		} `yaml:"direct"`
	} `yaml:"routing"`
	SSH struct {
		Keepalive struct {
			Period   string `yaml:"period"`
			Interval string `yaml:"interval"`
			Probes   int    `yaml:"probes"`
		} `yaml:"keepalive"`
		Servers []struct {
			ID         string `yaml:"id"`
			Host       string `yaml:"host"`
			Port       int    `yaml:"port"`
			User       string `yaml:"user"`
			Transports int    `yaml:"transports"`
			Limits     struct {
				MaxClientTunnels       int `yaml:"max_client_tunnels"`
				MaxPendingOpens        int `yaml:"max_pending_opens"`
				MaxPendingServiceOpens int `yaml:"max_pending_service_opens"`
			} `yaml:"limits"`
		} `yaml:"servers"`
	} `yaml:"ssh"`
	DNS struct {
		Tunnel struct {
			Servers []string `yaml:"servers"`
			DOHHost string   `yaml:"doh_host"`
		} `yaml:"tunnel"`
	} `yaml:"dns"`
	Balancing struct {
		HashKey string `yaml:"hash_key"`
		Retry   struct {
			MaxAttempts int    `yaml:"max_attempts"`
			Timeout     string `yaml:"timeout"`
		} `yaml:"retry"`
		Passive struct {
			MaxFails        int    `yaml:"max_fails"`
			FailTimeout     string `yaml:"fail_timeout"`
			UnhealthyPeriod string `yaml:"unhealthy_period"`
		} `yaml:"passive"`
	} `yaml:"balancing"`
	Health struct {
		Listen    string `yaml:"listen"`
		URL       string `yaml:"url"`
		Interval  string `yaml:"interval"`
		Timeout   string `yaml:"timeout"`
		MaxFails  int    `yaml:"max_fails"`
		Successes int    `yaml:"successes"`
	} `yaml:"health"`
	UI struct {
		AllowedHosts []string `yaml:"allowed_hosts"`
	} `yaml:"ui"`
	Logging struct {
		Level  string `yaml:"level"`
		Access bool   `yaml:"access"`
	} `yaml:"logging"`
	Storage struct {
		Directory string `yaml:"directory"`
	} `yaml:"storage"`
}

type server struct {
	Name       string
	StopAccept func() error
	Drain      func(context.Context) error
	ForceClose func()
}

// connHistoryMaxAge bounds the in-memory connection history window.
// balancing.retry.timeout must stay below it: dropStalled moves dialing records
// older than this window to history, so a dial in flight past it would lose
// its record.
const connHistoryMaxAge = 10 * time.Minute

// exitConfig is the exit status of every startup error (EX_CONFIG from
// sysexits.h): a bad value, an unreadable key, a busy port. A restart does
// not fix any of them, so the unit lists it in RestartPreventExitStatus and
// the service stays failed with the error in the journal instead of
// restarting in a loop.
const exitConfig = 78

// missing lists absent SSH configuration. Proxy listeners still run so
// direct routes remain available when the server list is empty.
func (c config) missing() []string {
	if c.sshHost == "" || c.sshUser == "" {
		return []string{"ssh.servers"}
	}
	return nil
}

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	configPath := flag.String("config", "/etc/ssh-gate/config.yaml", "YAML configuration file")
	flag.Parse()
	cfg, err := loadConfigFile(*configPath)
	if err != nil {
		// Logging cannot be set up yet: its level comes from this file. The
		// status still has to be the one the unit lists in
		// RestartPreventExitStatus, and zerolog's Fatal would exit 1 here,
		// making systemd restart a broken config forever.
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		os.Exit(exitConfig)
	}
	// log.Fatal is used only for startup errors.
	logs := setupLogging(parseLogLevel(cfg.logLevel), cfg.accessLog)
	defer logs.stop()
	zerolog.FatalExitFunc = logs.exitFatal

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

	status := newSDStatus()

	// Connection history is in-memory only: last 1000 connections / 10 minutes.
	tracker := NewConnTracker(1000, connHistoryMaxAge)

	d, rules, servers := startProxies(cfg, tracker, status)
	if len(cfg.sshServers) == 0 {
		log.Warn().Msg("no SSH servers configured; proxy listeners only serve direct routes")
		status.set(notConfiguredText([]string{"ssh.servers"}))
	}

	// Health/ready endpoint + Web UI.
	hs, err := NewHealthServer(cfg.healthAddr, d, tracker)
	if err != nil {
		log.Fatal().Err(err).Msg("health server")
	}
	hs.AllowHosts(cfg.uiAllowedHosts)
	if rules != nil {
		hs.SetDNSStatus(rules.DNSStatus)
	}
	hs.Start()
	hs.SetReady(len(servers) > 0)
	servers = append(servers, server{Name: "health", StopAccept: hs.StopAccept, Drain: hs.Drain, ForceClose: hs.ForceClose})

	// Graceful shutdown on SIGTERM/SIGINT
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		cancel()
	}()

	if rules != nil {
		rules.Start(ctx)
		if set, ok := d.(*sshDialerSet); ok {
			set.startHealthChecks(ctx, rules, cfg.healthURL, cfg.healthInterval, cfg.healthTimeout)
		}
	}
	status.ready()

	<-ctx.Done()
	log.Info().Msg("shutting down...")
	status.stop("Stopping, draining connections")
	hs.SetReady(false)
	// The signal ctx is already canceled; passing it to the servers would
	// skip the relay drain entirely. Give the drain its own deadline,
	// comfortably below compose's stop_grace_period (10 s).
	const shutdownDrainTimeout = 5 * time.Second
	drainCtx, cancelDrain := context.WithTimeout(context.Background(), shutdownDrainTimeout)
	defer cancelDrain()
	if err := shutdownServers(drainCtx, servers, rules, d); err != nil {
		log.Warn().Err(err).Msg("shutdown")
	}
}

// configureDNS routes tunnel-destination resolution through the configured
// resolvers, inside the SSH tunnel. Direct destinations keep local DNS.
func configureDNS(rules *RuleEngine, cfg config, d dialer) {
	if cfg.dohHost != "" {
		rules.SetDOH(cfg.dohHost, d)
		return
	}
	rules.SetTunnelDNS(cfg.tunnelDNS, d)
}

// startProxies starts the SSH dialer and the proxy listeners. The dialer
// reports every tunnel state change to the systemd status line.
func startProxies(cfg config, tracker *ConnTracker, status *sdStatus) (dialer, *RuleEngine, []server) {
	set := &sshDialerSet{}
	hostKeys := &hostKeyStore{path: filepath.Join(cfg.dataDir, sshKnownHostsFile)}
	var monitors []*sshDialer
	for _, serverCfg := range cfg.sshServers {
		quota := newServerQuota(serverCfg.maxClientTunnels, serverCfg.maxPendingOpens, serverCfg.maxPendingServiceOpens)
		pool := &sshTransportPool{id: serverCfg.id, host: serverCfg.host, port: serverCfg.port, user: serverCfg.user, healthURL: cfg.healthURL, quota: quota, health: newServerHealth(cfg.passiveMaxFails, cfg.passiveFailTimeout, cfg.passiveUnhealthyPeriod, cfg.healthMaxFails, cfg.healthSuccesses)}
		for slot := 0; slot < serverCfg.transports; slot++ {
			dcfg := sshDialerCfg{
				host: serverCfg.host, port: serverCfg.port, user: serverCfg.user,
				keyPath: filepath.Join(cfg.dataDir, sshKeyFile), serverID: serverCfg.id, transportSlot: slot, hostKeys: hostKeys,
				openQuota:       quota,
				keepalivePeriod: cfg.sshKeepalivePeriod, keepaliveInterval: cfg.sshKeepaliveInterval,
				keepaliveProbes: cfg.sshKeepaliveProbes, tracker: tracker, dialTimeout: cfg.dialTimeout,
			}
			slotID := slot
			dcfg.onStatus = func(st tunnelStatus) {
				status.set(fmt.Sprintf("%s slot %d: %s", dcfg.serverID, dcfg.transportSlot, statusText(dcfg, st)))
				event := log.Info().Str("server_id", dcfg.serverID).Int("slot", dcfg.transportSlot).Str("state", st.State)
				if st.Err != nil {
					event = event.Err(st.Err)
				}
				event.Msg("SSH transport state changed")
				if st.State == stateReconnecting {
					pool.transportFailed(slotID)
				}
			}
			d, err := newSSHDialer(dcfg)
			if err != nil {
				for _, slot := range pool.slots {
					slot.dialer.stop()
				}
				set.stop()
				log.Fatal().Err(err).Str("server_id", serverCfg.id).Msg("SSH transport")
			}
			pool.slots = append(pool.slots, &transportSlot{dialer: d, index: slot})
			monitors = append(monitors, d)
		}
		set.pools = append(set.pools, pool)
	}
	rules, err := NewRuleEngine(cfg.directRules)
	if err != nil {
		set.stop()
		log.Fatal().Err(err).Msg("rule engine")
	}
	configureDNS(rules, cfg, set)
	for _, d := range monitors {
		d.start()
	}
	log.Info().Str("mode", rules.DNSStatus().Mode).Strs("tunnel_dns", cfg.tunnelDNS).Msg("DNS resolvers configured")
	opener := &Opener{rules: rules, d: set, family: cfg.directIPFamily, dialTimeout: cfg.dialTimeout, hashKey: cfg.balancingHashKey, maxAttempts: cfg.retryMaxAttempts}
	var servers []server
	if contains(cfg.proxyModes, "socks5") {
		for _, addr := range cfg.socks5Addrs {
			s5, err := NewSOCKS5Server(addr, opener)
			if err != nil {
				log.Fatal().Err(err).Str("listen", addr).Msg("SOCKS5 server")
			}
			s5.Start()
			servers = append(servers, server{Name: "SOCKS5 " + addr, StopAccept: s5.StopAccept, Drain: s5.Drain, ForceClose: s5.ForceClose})
		}
	}
	if contains(cfg.proxyModes, "http") {
		for _, addr := range cfg.httpAddrs {
			hp, err := NewHTTPProxyServer(addr, opener)
			if err != nil {
				log.Fatal().Err(err).Str("listen", addr).Msg("HTTP proxy")
			}
			hp.Start()
			servers = append(servers, server{Name: "HTTP " + addr, StopAccept: hp.StopAccept, Drain: hp.Drain, ForceClose: hp.ForceClose})
		}
	}
	return set, rules, servers
}

func shutdownServers(ctx context.Context, servers []server, rules *RuleEngine, d dialer) error {
	var errs []error
	for _, s := range servers {
		if err := s.StopAccept(); err != nil {
			errs = append(errs, fmt.Errorf("%s stop: %w", s.Name, err))
		}
	}
	if err := drainServers(ctx, servers); err != nil {
		errs = append(errs, err)
		for _, s := range servers {
			s.ForceClose()
		}
	}
	// Accepted work keeps DNS and SSH alive until drain completes or the
	// common deadline forces every client closed.
	if rules != nil {
		rules.Stop()
	}
	d.stop()
	cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := drainServers(cleanup, servers); err != nil {
		errs = append(errs, err)
	}
	if rules != nil {
		if err := rules.dns.waitStopped(cleanup); err != nil {
			errs = append(errs, fmt.Errorf("DNS cleanup: %w", err))
		}
	}
	if owner, ok := d.(interface{ waitStopped(context.Context) error }); ok {
		if err := owner.waitStopped(cleanup); err != nil {
			errs = append(errs, fmt.Errorf("SSH cleanup: %w", err))
		}
	}
	return errors.Join(errs...)
}

func drainServers(ctx context.Context, servers []server) error {
	results := make(chan error, len(servers))
	for _, s := range servers {
		go func() {
			err := s.Drain(ctx)
			if err != nil {
				err = fmt.Errorf("%s drain: %w", s.Name, err)
			}
			results <- err
		}()
	}
	var errs []error
	for range servers {
		if err := <-results; err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func loadConfig() (config, error) {
	return loadConfigFile("/etc/ssh-gate/config.yaml")
}

func loadConfigFile(path string) (config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return config{}, fmt.Errorf("read %s: %w", path, err)
	}
	var raw fileConfig
	raw.SSH.Keepalive.Period = "10s"
	raw.SSH.Keepalive.Interval = "1s"
	raw.SSH.Keepalive.Probes = 5
	raw.Routing.Direct.IPFamily = "both"
	raw.Balancing.Retry.Timeout = "30s"
	raw.Balancing.HashKey = "client_ip_destination"
	raw.Balancing.Retry.MaxAttempts = 3
	raw.Balancing.Passive.MaxFails = 3
	raw.Balancing.Passive.FailTimeout = "30s"
	raw.Balancing.Passive.UnhealthyPeriod = "30s"
	raw.Health.Listen = "127.0.0.1:9090"
	raw.Health.URL = "https://www.youtube.com"
	raw.Health.Interval = "10s"
	raw.Health.Timeout = "5s"
	raw.Health.MaxFails = 3
	raw.Health.Successes = 2
	raw.Logging.Level = "info"
	raw.Logging.Access = true
	raw.Storage.Directory = "/data"
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil {
		return config{}, fmt.Errorf("parse %s: %w", path, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return config{}, fmt.Errorf("parse %s: multiple YAML documents are not supported", path)
		}
		return config{}, fmt.Errorf("parse %s: %w", path, err)
	}

	if raw.Proxy.SOCKS5 == nil && raw.Proxy.HTTP == nil {
		return config{}, errors.New("at least one of proxy.socks5 or proxy.http must be configured")
	}
	var modes, socks, httpAddrs []string
	if raw.Proxy.SOCKS5 != nil {
		modes = append(modes, "socks5")
		socks = raw.Proxy.SOCKS5.Listen
	}
	if raw.Proxy.HTTP != nil {
		modes = append(modes, "http")
		httpAddrs = raw.Proxy.HTTP.Listen
	}
	validateAddrs := func(name string, addrs []string) error {
		if len(addrs) == 0 {
			return fmt.Errorf("%s.listen must contain at least one address", name)
		}
		for _, a := range addrs {
			if err := validateHostPort(a); err != nil {
				return fmt.Errorf("invalid %s.listen address %q: %w", name, a, err)
			}
		}
		return nil
	}
	if raw.Proxy.SOCKS5 != nil {
		if err := validateAddrs("proxy.socks5", socks); err != nil {
			return config{}, err
		}
	}
	if raw.Proxy.HTTP != nil {
		if err := validateAddrs("proxy.http", httpAddrs); err != nil {
			return config{}, err
		}
	}
	family, err := parseIPFamily(raw.Routing.Direct.IPFamily)
	if err != nil {
		return config{}, fmt.Errorf("routing.direct.ip_family: %w", err)
	}
	period, err := parseKeepalivePeriod(raw.SSH.Keepalive.Period)
	if err != nil {
		return config{}, fmt.Errorf("ssh.keepalive.period: %w", err)
	}
	interval, err := parseKeepaliveInterval(raw.SSH.Keepalive.Interval)
	if err != nil {
		return config{}, fmt.Errorf("ssh.keepalive.interval: %w", err)
	}
	if raw.SSH.Keepalive.Probes < 0 {
		return config{}, errors.New("ssh.keepalive.probes must be non-negative")
	}
	dialTimeout, err := parseDialTimeout(raw.Balancing.Retry.Timeout)
	if err != nil {
		return config{}, fmt.Errorf("balancing.retry.timeout: %w", err)
	}
	if dialTimeout >= connHistoryMaxAge {
		return config{}, fmt.Errorf("balancing.retry.timeout %s: must be below %s (connection history window)", dialTimeout, connHistoryMaxAge)
	}
	if raw.Balancing.Retry.MaxAttempts < 1 || raw.Balancing.Retry.MaxAttempts > 3 {
		return config{}, errors.New("balancing.retry.max_attempts must be between 1 and 3")
	}
	if raw.Balancing.HashKey != "client_ip_destination" && raw.Balancing.HashKey != "client_ip" {
		return config{}, errors.New("balancing.hash_key must be client_ip_destination or client_ip")
	}
	for name, value := range map[string]string{"balancing.passive.fail_timeout": raw.Balancing.Passive.FailTimeout, "balancing.passive.unhealthy_period": raw.Balancing.Passive.UnhealthyPeriod, "health.interval": raw.Health.Interval, "health.timeout": raw.Health.Timeout} {
		d, e := time.ParseDuration(value)
		if e != nil || d <= 0 {
			return config{}, fmt.Errorf("%s must be a positive duration", name)
		}
	}
	passiveFailTimeout, _ := time.ParseDuration(raw.Balancing.Passive.FailTimeout)
	passiveUnhealthyPeriod, _ := time.ParseDuration(raw.Balancing.Passive.UnhealthyPeriod)
	healthInterval, _ := time.ParseDuration(raw.Health.Interval)
	healthTimeout, _ := time.ParseDuration(raw.Health.Timeout)
	if raw.Balancing.Passive.MaxFails < 1 || raw.Health.MaxFails < 1 || raw.Health.Successes < 1 {
		return config{}, errors.New("balancing.passive.max_fails, health.max_fails, and health.successes must be positive")
	}
	if raw.Storage.Directory == "" {
		return config{}, errors.New("storage.directory cannot be empty")
	}
	if err := validateHostPort(raw.Health.Listen); err != nil {
		return config{}, fmt.Errorf("health.listen: %w", err)
	}
	if raw.Health.URL == "" {
		return config{}, errors.New("health.url cannot be empty")
	}
	probeURL, err := url.ParseRequestURI(raw.Health.URL)
	if err != nil {
		return config{}, fmt.Errorf("health.url: %w", err)
	}
	if probeURL.Scheme != "https" || probeURL.Host == "" {
		return config{}, errors.New("health.url must be an absolute HTTPS URL")
	}
	if raw.Logging.Level != "debug" && raw.Logging.Level != "info" && raw.Logging.Level != "warn" && raw.Logging.Level != "error" {
		return config{}, fmt.Errorf("logging.level %q is invalid", raw.Logging.Level)
	}
	seen := map[string]bool{}
	for i, srv := range raw.SSH.Servers {
		if srv.ID == "" || srv.Host == "" || srv.User == "" {
			return config{}, fmt.Errorf("ssh.servers[%d] requires id, host, and user", i)
		}
		if strings.TrimSpace(srv.ID) != srv.ID || strings.ContainsAny(srv.ID, " \t\r\n#") {
			return config{}, fmt.Errorf("ssh.servers[%d].id cannot contain whitespace or #", i)
		}
		if seen[srv.ID] {
			return config{}, fmt.Errorf("duplicate ssh server id %q", srv.ID)
		}
		seen[srv.ID] = true
		if srv.Port == 0 {
			raw.SSH.Servers[i].Port = 22
		} else if err := validatePort(srv.Port); err != nil {
			return config{}, fmt.Errorf("ssh.servers[%d].port: %w", i, err)
		}
		if ip := net.ParseIP(strings.Trim(srv.Host, "[]")); ip != nil && ip.To4() == nil {
			return config{}, fmt.Errorf("ssh.servers[%d].host: IPv4 only; use IPv4 or a name with an A record", i)
		}
		if srv.Transports == 0 {
			raw.SSH.Servers[i].Transports = 4
		} else if srv.Transports < 1 {
			return config{}, fmt.Errorf("ssh.servers[%d].transports must be positive", i)
		}
		limits := &raw.SSH.Servers[i].Limits
		if limits.MaxClientTunnels == 0 {
			limits.MaxClientTunnels = 4096
		}
		if limits.MaxPendingOpens == 0 {
			limits.MaxPendingOpens = 256
		}
		if limits.MaxPendingServiceOpens == 0 {
			limits.MaxPendingServiceOpens = 32
		}
		if limits.MaxClientTunnels < 1 || limits.MaxPendingOpens < 1 || limits.MaxPendingServiceOpens < 1 {
			return config{}, fmt.Errorf("ssh.servers[%d].limits must be positive", i)
		}
	}
	var host, user string
	port := 22
	serverConfigs := make([]sshServerConfig, 0, len(raw.SSH.Servers))
	if len(raw.SSH.Servers) > 0 {
		host = raw.SSH.Servers[0].Host
		user = raw.SSH.Servers[0].User
		port = raw.SSH.Servers[0].Port
	}
	for _, srv := range raw.SSH.Servers {
		serverConfigs = append(serverConfigs, sshServerConfig{
			id: srv.ID, host: srv.Host, port: srv.Port, user: srv.User,
			transports: srv.Transports, maxClientTunnels: srv.Limits.MaxClientTunnels,
			maxPendingOpens: srv.Limits.MaxPendingOpens, maxPendingServiceOpens: srv.Limits.MaxPendingServiceOpens,
		})
	}
	var tunnelDNS []string
	dohHost := raw.DNS.Tunnel.DOHHost
	if err := validateDOHHost(dohHost); err != nil {
		return config{}, fmt.Errorf("dns.tunnel.doh_host: %w", err)
	}
	if dohHost != "" && len(raw.DNS.Tunnel.Servers) > 0 {
		return config{}, errors.New("dns.tunnel.doh_host and dns.tunnel.servers are mutually exclusive")
	}
	if dohHost == "" {
		rawServers := raw.DNS.Tunnel.Servers
		if len(rawServers) == 0 {
			rawServers = []string{"1.1.1.1", "8.8.8.8"}
		}
		tunnelDNS, err = parseTunnelDNS(strings.Join(rawServers, ","))
		if err != nil {
			return config{}, fmt.Errorf("dns.tunnel.servers: %w", err)
		}
	}
	return config{sshServers: serverConfigs, sshHost: host, sshPort: port, sshUser: user, dataDir: raw.Storage.Directory, proxyModes: modes, socks5Addrs: socks, httpAddrs: httpAddrs, directRules: raw.Routing.Direct.Rules, directIPFamily: family, dohHost: dohHost, tunnelDNS: tunnelDNS, healthAddr: raw.Health.Listen, sshKeepalivePeriod: period, sshKeepaliveInterval: interval, sshKeepaliveProbes: raw.SSH.Keepalive.Probes, dialTimeout: dialTimeout, uiAllowedHosts: raw.UI.AllowedHosts, logLevel: raw.Logging.Level, accessLog: raw.Logging.Access, balancingHashKey: raw.Balancing.HashKey, retryMaxAttempts: raw.Balancing.Retry.MaxAttempts, passiveMaxFails: raw.Balancing.Passive.MaxFails, passiveFailTimeout: passiveFailTimeout, passiveUnhealthyPeriod: passiveUnhealthyPeriod, healthURL: raw.Health.URL, healthInterval: healthInterval, healthTimeout: healthTimeout, healthMaxFails: raw.Health.MaxFails, healthSuccesses: raw.Health.Successes}, nil
}

// parseTunnelDNS parses a comma-separated list of DNS server IPs with an
// optional port into host:port addresses. Names are refused: resolving the
// resolver would need a resolver.
func parseTunnelDNS(raw string) ([]string, error) {
	var servers []string
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		host, port := entry, "53"
		if _, err := netip.ParseAddr(entry); err != nil {
			if host, port, err = net.SplitHostPort(entry); err != nil {
				return nil, fmt.Errorf("invalid DNS server %q: use an IP address with an optional port", entry)
			}
		}
		if _, err := netip.ParseAddr(host); err != nil {
			return nil, fmt.Errorf("invalid DNS server %q: use an IP address, not a name", entry)
		}
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid DNS server %q: bad port", entry)
		}
		servers = append(servers, net.JoinHostPort(host, port))
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("DNS tunnel resolver list is empty")
	}
	return servers, nil
}

// validateDOHHost checks the DoH endpoint is a bare host name or address with
// an optional port. The client builds "https://<host>/dns-query" itself, so a
// scheme, a path or a stray space becomes a request to a nonsense host: the
// proxy would start fine and only break on the first tunnel lookup. An empty
// value means "no DoH" and is the caller's business.
func validateDOHHost(raw string) error {
	const want = `want a host name or address with an optional port, for example dns.google or dns.example:8443`
	if raw == "" {
		return nil
	}
	if strings.Contains(raw, "://") {
		return fmt.Errorf("invalid %q: no scheme allowed, %s", raw, want)
	}
	host, port, err := net.SplitHostPort(raw)
	switch {
	case err == nil:
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("invalid %q: bad port, %s", raw, want)
		}
	case strings.HasSuffix(err.Error(), "missing port in address"):
		host = raw
	default:
		return fmt.Errorf("invalid %q: %s", raw, want)
	}
	if host == "" || strings.ContainsAny(host, " \t/\\?#@%") {
		return fmt.Errorf("invalid %q: %s", raw, want)
	}
	return nil
}

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

// accessLog gets one line per proxied connection. It is separate from the
// service log so that LOG_LEVEL does not hide it and, under systemd, it has
// its own SYSLOG_IDENTIFIER.
var accessLog = zerolog.New(os.Stderr).With().Timestamp().Logger()

const (
	journalIdent       = "ssh-gate"
	journalAccessIdent = "ssh-gate-access"
)

// setupLogging builds the service and access loggers. Levels are set per
// logger, not globally, so the access log stays on at logging.level=warn. Under
// systemd the lines go to journald natively (priority and identifier per
// line); elsewhere (Docker, a terminal) both loggers write JSON to stderr.
func setupLogging(level zerolog.Level, access bool) *logging {
	var conn *net.UnixConn
	if stderrIsJournal() {
		conn, _ = dialJournal()
	}
	owner := newLogging(conn, os.Stderr)
	appOut := &journalWriter{owner: owner, ident: journalIdent}
	accessOut := &journalWriter{owner: owner, ident: journalAccessIdent}

	log.Logger = zerolog.New(appOut).Level(level).With().Timestamp().Caller().Logger()
	if access {
		accessLog = zerolog.New(accessOut).With().Timestamp().Logger()
	} else {
		accessLog = zerolog.Nop()
	}
	return owner
}

func parseLogLevel(level string) zerolog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return zerolog.DebugLevel
	case "warn":
		return zerolog.WarnLevel
	case "error":
		return zerolog.ErrorLevel
	default:
		return zerolog.InfoLevel
	}
}

func parseKeepalivePeriod(raw string) (time.Duration, error) {
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid keepalive period %q (Go duration, e.g. 90s): %w", raw, err)
	}
	if d <= 0 {
		return 0, nil
	}
	return d, nil
}

// parseKeepaliveInterval parses keepalive interval as a Go duration and
// returns whole seconds for TCP_KEEPINTVL. Zero keeps the kernel default
// (returned as 0); sub-second values round up to 1 s. Empty input is a hard
// error: loadConfig always supplies a non-empty default.
func parseKeepaliveInterval(raw string) (int, error) {
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid keepalive interval %q (Go duration, e.g. 1s): %w", raw, err)
	}
	if d < 0 {
		return 0, fmt.Errorf("keepalive interval must be non-negative, got %s", raw)
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

// parseKeepaliveProbes parses keepalive probes as an integer for
// TCP_KEEPCNT. Zero keeps the kernel default (returned as 0). Empty input is
// a hard error: loadConfig always supplies a non-empty default.
func parseKeepaliveProbes(raw string) (int, error) {
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid keepalive probes %q (integer, e.g. 5): %w", raw, err)
	}
	if n < 0 {
		return 0, fmt.Errorf("keepalive probes must be non-negative, got %d", n)
	}
	return n, nil
}

// parseDialTimeout parses tunnel attempt timeout as a Go duration.
// A non-positive value is rejected: an unbounded destination dial can
// hang forever on a blackholed host.
func parseDialTimeout(raw string) (time.Duration, error) {
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid tunnel attempt timeout %q (Go duration, e.g. 30s): %w", raw, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("tunnel attempt timeout must be positive, got %s", raw)
	}
	return d, nil
}

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
