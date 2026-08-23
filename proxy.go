package main

import (
	"context"
	"fmt"
	"net"
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
	proxy *mtglib.Proxy
	ln    net.Listener
	done  chan struct{}
	closeOnce sync.Once
}

func newMTProtoServer(listen, secret string, dialer network.Dialer, doh string) (*MTProtoServer, error) {
	secretVal, err := mtglib.ParseSecret(secret)
	if err != nil {
		return nil, fmt.Errorf("parse MTProto secret: %w", err)
	}

	netw, err := network.NewNetwork(dialer, "", doh, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("create network: %w", err)
	}

	opts := mtglib.ProxyOpts{
		Secret:          secretVal,
		Network:         netw,
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

func (allowAllBlocklist) Contains(net.IP) bool               { return false }
func (allowAllBlocklist) Run(time.Duration)                  {}
func (allowAllBlocklist) Shutdown()                          {}

// allowAllAllowlist implements mtglib.IPAllowlist — allows everything.
type allowAllAllowlist struct{}

func (allowAllAllowlist) Contains(net.IP) bool              { return true }
func (allowAllAllowlist) Run(time.Duration)                 {}
func (allowAllAllowlist) Shutdown()                         {}

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

func (l logLogger) Printf(format string, args ...any)   { zl := l.boundLogger(); zl.Info().Msg(fmt.Sprintf(format, args...)) }
func (l logLogger) Info(msg string)                     { zl := l.boundLogger(); zl.Info().Msg(msg) }
func (l logLogger) InfoError(msg string, err error)     { zl := l.boundLogger(); zl.Info().Err(err).Msg(msg) }
func (l logLogger) Warning(msg string)                  { zl := l.boundLogger(); zl.Warn().Msg(msg) }
func (l logLogger) WarningError(msg string, err error)  { zl := l.boundLogger(); zl.Warn().Err(err).Msg(msg) }
func (l logLogger) Debug(msg string)                    { zl := l.boundLogger(); zl.Debug().Msg(msg) }
func (l logLogger) DebugError(msg string, err error)    { zl := l.boundLogger(); zl.Debug().Err(err).Msg(msg) }
