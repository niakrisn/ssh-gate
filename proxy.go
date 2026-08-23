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
		EventStream:     nopEventStream{},
		Logger:          nopLogger{},
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

// nopEventStream implements mtglib.EventStream — drops all events.
type nopEventStream struct{}

func (nopEventStream) Send(context.Context, mtglib.Event) {}

// nopLogger implements mtglib.Logger — silent.
type nopLogger struct{}

func (nopLogger) Named(string) mtglib.Logger                   { return nopLogger{} }
func (nopLogger) BindInt(string, int) mtglib.Logger            { return nopLogger{} }
func (nopLogger) BindStr(string, string) mtglib.Logger         { return nopLogger{} }
func (nopLogger) BindJSON(string, string) mtglib.Logger        { return nopLogger{} }
func (nopLogger) Printf(format string, args ...any)            {}
func (nopLogger) Info(string)                                  {}
func (nopLogger) InfoError(string, error)                      {}
func (nopLogger) Warning(string)                               {}
func (nopLogger) WarningError(string, error)                   {}
func (nopLogger) Debug(string)                                 {}
func (nopLogger) DebugError(string, error)                     {}
