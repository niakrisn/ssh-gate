package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/9seconds/mtg/v2/antireplay"
	"github.com/9seconds/mtg/v2/mtglib"
	"github.com/9seconds/mtg/v2/network"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// MTProtoServer wraps mtglib.Proxy with lifecycle control.
type MTProtoServer struct {
	proxy     *mtglib.Proxy
	ln        net.Listener
	done      chan struct{}
	closeOnce sync.Once
}

// defaultDohIP is the fallback DoH endpoint: Cloudflare, whose cert carries
// the IP SANs that mtg's IP-based DoH requires.
const defaultDohIP = "1.1.1.1"

// dohBootstrap names the DoH endpoint that resolves DOH_HOST itself: the
// query egresses through the tunnel, so a poisoned local resolver cannot
// affect the answer.
type dohBootstrap struct {
	addr string      // host:port of the bootstrap DoH endpoint
	tls  *tls.Config // nil: system roots
}

// defaultDohBootstrap points at Cloudflare (defaultDohIP).
var defaultDohBootstrap = dohBootstrap{addr: defaultDohIP + ":443"}

// resolveDohIP maps the DOH_HOST hostname onto the IP literal mtg's
// network.NewNetwork requires. The lookup egresses through the tunnel
// (bootstrap DoH at b.addr), so a poisoned local resolver cannot affect it.
// The chosen IP is then probed for IP-based DoH (see probeDohIP). Any
// failure falls back to defaultDohIP, from which the AutoUpdate fetch
// degrades gracefully.
func resolveDohIP(host string, d dialer, b dohBootstrap) string {
	if host == "" {
		return defaultDohIP
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	client := tunnelHTTPClient(d, 10*time.Second, b.tls)
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	v4, err := dohJSONQuery(ctx, client, b.addr, host, dohQueryA)
	if err != nil {
		log.Warn().Str("host", host).Err(err).Str("fallback", defaultDohIP).Msg("bootstrap DoH lookup failed")
		return defaultDohIP
	}
	var v6 []netip.Addr
	if addrs, err := dohJSONQuery(ctx, client, b.addr, host, dohQueryAAAA); err == nil {
		v6 = addrs
	} else if !errors.Is(err, errDohNotFound) {
		log.Warn().Str("host", host).Err(err).Msg("bootstrap DoH AAAA lookup failed")
	}

	// The probe phase is bounded as a whole: candidates are tried serially,
	// and each one can burn the client timeout on a degraded tunnel.
	probeCtx, cancelProbe := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelProbe()

	if ip := pickDohIP(v4, v6, func(ip netip.Addr) bool { return probeDohIP(probeCtx, ip, client) }); ip.IsValid() {
		return ip.String()
	}
	tried := make([]string, 0, len(v4)+len(v6))
	for _, ip := range v4 {
		tried = append(tried, ip.String())
	}
	for _, ip := range v6 {
		tried = append(tried, ip.String())
	}
	log.Warn().Str("host", host).Strs("tried", tried).Str("fallback", defaultDohIP).Msg("resolve DoH host: no usable address")
	return defaultDohIP
}

// probeDohIP reports whether ip serves DoH with a certificate valid for the
// IP itself: mtg validates DoH TLS against the IP literal it was given, and
// most provider endpoints only carry hostname SANs. A definitive NXDOMAIN
// counts as a pass — the probe checks transport and TLS, not the answer.
func probeDohIP(ctx context.Context, ip netip.Addr, client *http.Client) bool {
	_, err := dohJSONQuery(ctx, client, net.JoinHostPort(ip.String(), "443"), "example.com", dohQueryA)
	return err == nil || errors.Is(err, errDohNotFound)
}

// pickDohIP picks the first probe-passing address from the resolved
// answers, preferring IPv4; the zero Addr when none passes.
func pickDohIP(v4, v6 []netip.Addr, probe func(netip.Addr) bool) netip.Addr {
	for _, ip := range v4 {
		if probe(ip) {
			return ip
		}
	}
	for _, ip := range v6 {
		if probe(ip) {
			return ip
		}
	}
	return netip.Addr{}
}

func newMTProtoServer(listen, secret, dohIP string, dialer network.Dialer) (*MTProtoServer, error) {
	secretVal, err := mtglib.ParseSecret(secret)
	if err != nil {
		return nil, fmt.Errorf("parse MTProto secret: %w", err)
	}

	netw, err := network.NewNetwork(dialer, "", dohIP, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("create network: %w", err)
	}

	opts := mtglib.ProxyOpts{
		Secret:          secretVal,
		Network:         netw,
		AutoUpdate:      true,
		AntiReplayCache: antireplay.NewNoop(),
		IPBlocklist:     allowAllBlocklist{},
		IPAllowlist:     allowAllAllowlist{},
		EventStream:     logEventStream{},
		Logger:          newLogLogger(),
	}

	proxy, err := mtglib.NewProxy(opts)
	if err != nil {
		return nil, fmt.Errorf("create proxy: %w", err)
	}

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", listen, err)
	}

	return &MTProtoServer{proxy: proxy, ln: ln, done: make(chan struct{})}, nil
}

func (m *MTProtoServer) Start() {
	log.Info().Str("listen", m.ln.Addr().String()).Msg("MTProto proxy starting")

	go func() {
		defer m.closeOnce.Do(func() { close(m.done) })
		if err := m.proxy.Serve(m.ln); err != nil {
			log.Error().Err(err).Msg("MTProto proxy failed")
		}
	}()
}

func (m *MTProtoServer) Shutdown(ctx context.Context) error {
	m.ln.Close()
	m.closeOnce.Do(func() { close(m.done) })
	select {
	case <-m.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// allowAllBlocklist implements mtglib.IPBlocklist — allows everything.
type allowAllBlocklist struct{}

func (allowAllBlocklist) Contains(net.IP) bool { return false }
func (allowAllBlocklist) Run(time.Duration)    {}
func (allowAllBlocklist) Shutdown()            {}

// allowAllAllowlist implements mtglib.IPAllowlist — allows everything.
type allowAllAllowlist struct{}

func (allowAllAllowlist) Contains(net.IP) bool { return true }
func (allowAllAllowlist) Run(time.Duration)    {}
func (allowAllAllowlist) Shutdown()            {}

// logEventStream implements mtglib.EventStream — forwards events to zerolog.
type logEventStream struct{}

func (logEventStream) Send(_ context.Context, ev mtglib.Event) {
	switch e := ev.(type) {
	case mtglib.EventStart:
		log.Debug().Str("stream", e.StreamID()).Str("client", e.RemoteIP.String()).Msg("MTProto: client connected")
	case mtglib.EventConnectedToDC:
		log.Debug().Str("stream", e.StreamID()).Str("dc_ip", e.RemoteIP.String()).Int("dc", e.DC).Msg("MTProto: connected to DC")
	case mtglib.EventFinish:
		log.Debug().Str("stream", e.StreamID()).Msg("MTProto: stream finished")
	case mtglib.EventConcurrencyLimited:
		log.Warn().Msg("MTProto: connection declined (concurrency limit)")
	case mtglib.EventIPBlocklisted:
		log.Warn().Str("ip", e.RemoteIP.String()).Bool("blocklist", e.IsBlockList).Msg("MTProto: connection declined (IP blocklist)")
	case mtglib.EventReplayAttack:
		log.Warn().Str("stream", e.StreamID()).Msg("MTProto: replay attack detected")
	case mtglib.EventDomainFronting:
		log.Debug().Str("stream", e.StreamID()).Msg("MTProto: domain fronting active")
	case mtglib.EventTraffic:
		// too verbose for production logging; skip
	case mtglib.EventIPListSize:
		// informational, skip
	}
}

// logLogger implements mtglib.Logger — forwards to zerolog.
// Bound fields are accumulated and emitted with each log call.
type logLogger struct {
	name   string
	ints   map[string]int
	strs   map[string]string
	jsons  map[string]string
	parent *logLogger
}

func newLogLogger() logLogger {
	return logLogger{
		ints:  make(map[string]int),
		strs:  make(map[string]string),
		jsons: make(map[string]string),
	}
}

// collectFields walks the parent chain and gathers all bound fields.
func (l *logLogger) collectFields(name *string, ints *map[string]int, strs *map[string]string, jsons *map[string]string) {
	if l.parent != nil {
		l.parent.collectFields(name, ints, strs, jsons)
	}
	if l.name != "" {
		*name = l.name
	}
	for k, v := range l.ints {
		(*ints)[k] = v
	}
	for k, v := range l.strs {
		(*strs)[k] = v
	}
	for k, v := range l.jsons {
		(*jsons)[k] = v
	}
}

func (l logLogger) boundLogger() zerolog.Logger {
	var name string
	ints := make(map[string]int)
	strs := make(map[string]string)
	jsons := make(map[string]string)
	l.collectFields(&name, &ints, &strs, &jsons)

	le := log.With()
	if name != "" {
		le = le.Str("component", name)
	}
	for k, v := range ints {
		le = le.Int(k, v)
	}
	for k, v := range strs {
		le = le.Str(k, v)
	}
	for k, v := range jsons {
		le = le.RawJSON(k, []byte(v))
	}
	return le.Logger()
}

func (l logLogger) Named(name string) mtglib.Logger {
	return logLogger{name: name, parent: &l, ints: make(map[string]int), strs: make(map[string]string), jsons: make(map[string]string)}
}

func (l logLogger) BindInt(name string, value int) mtglib.Logger {
	nl := logLogger{parent: &l, ints: make(map[string]int), strs: make(map[string]string), jsons: make(map[string]string)}
	nl.ints[name] = value
	return nl
}

func (l logLogger) BindStr(name, value string) mtglib.Logger {
	nl := logLogger{parent: &l, ints: make(map[string]int), strs: make(map[string]string), jsons: make(map[string]string)}
	nl.strs[name] = value
	return nl
}

func (l logLogger) BindJSON(name, value string) mtglib.Logger {
	nl := logLogger{parent: &l, ints: make(map[string]int), strs: make(map[string]string), jsons: make(map[string]string)}
	nl.jsons[name] = value
	return nl
}

func (l logLogger) Printf(format string, args ...any) {
	zl := l.boundLogger()
	zl.Info().Msg(fmt.Sprintf(format, args...))
}
func (l logLogger) Info(msg string) { zl := l.boundLogger(); zl.Info().Msg(msg) }
func (l logLogger) InfoError(msg string, err error) {
	zl := l.boundLogger()
	zl.Info().Err(err).Msg(msg)
}
func (l logLogger) Warning(msg string) { zl := l.boundLogger(); zl.Warn().Msg(msg) }
func (l logLogger) WarningError(msg string, err error) {
	zl := l.boundLogger()
	zl.Warn().Err(err).Msg(msg)
}
func (l logLogger) Debug(msg string) { zl := l.boundLogger(); zl.Debug().Msg(msg) }
func (l logLogger) DebugError(msg string, err error) {
	zl := l.boundLogger()
	zl.Debug().Err(err).Msg(msg)
}
