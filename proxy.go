package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/9seconds/mtg/v2/antireplay"
	"github.com/9seconds/mtg/v2/essentials"
	"github.com/9seconds/mtg/v2/mtglib"
	"github.com/9seconds/mtg/v2/network"
	"github.com/rs/zerolog/log"
)

// allowAllBlocklist implements mtglib.IPBlocklist — allows everything.
type dialer interface {
	Dial(network_, address string) (essentials.Conn, error)
	DialContext(ctx context.Context, network_, address string) (essentials.Conn, error)
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

func runProxy(
	secret string,
	listen string,
	dialer_ dialer,
	doh string,
) error {
	secretVal, err := mtglib.ParseSecret(secret)
	if err != nil {
		return fmt.Errorf("parse MTProto secret: %w", err)
	}

	netw, err := network.NewNetwork(dialer_, "", doh, 5*time.Second)
	if err != nil {
		return fmt.Errorf("create network: %w", err)
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
		return fmt.Errorf("create proxy: %w", err)
	}

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", listen, err)
	}

	log.Info().Str("listen", listen).Msg("MTProto proxy starting")

	// Graceful shutdown on SIGTERM/SIGINT
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		cancel()
	}()

	go func() {
		if err := proxy.Serve(ln); err != nil && ctx.Err() == nil {
			log.Error().Err(err).Msg("proxy failed")
		}
	}()

	<-ctx.Done()
	log.Info().Msg("shutting down...")
	proxy.Shutdown()
	return nil
}
