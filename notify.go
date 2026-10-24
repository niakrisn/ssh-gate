package main

import (
	"net"
	"os"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
)

// sdNotify sends one message to the systemd notify socket ($NOTIFY_SOCKET,
// set for Type=notify units). Outside systemd (Docker, a terminal) the
// variable is unset and the call does nothing. A name starting with "@" is
// an abstract socket.
func sdNotify(msg string) error {
	name := os.Getenv("NOTIFY_SOCKET")
	if name == "" {
		return nil
	}
	if strings.HasPrefix(name, "@") {
		name = "\x00" + name[1:]
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: name, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte(msg))
	return err
}

// sdStatus sets the status line that `systemctl status` shows. Once stop
// is called, later updates are dropped: the tunnel can drop while the
// proxies drain, and its "reconnecting" must not hide "Stopping".
type sdStatus struct {
	mu       sync.Mutex
	stopping bool
	notify   func(string) error
}

func newSDStatus() *sdStatus {
	return &sdStatus{notify: sdNotify}
}

// set replaces the status line.
func (s *sdStatus) set(text string) {
	s.send("STATUS=" + text)
}

// ready tells systemd that startup is done: the listeners are open. It does
// not wait for the tunnel, so `systemctl start` never blocks on the VPS.
func (s *sdStatus) ready() {
	s.send("READY=1")
}

// stop reports the shutdown and blocks all later updates.
func (s *sdStatus) stop(text string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopping = true
	s.write("STOPPING=1\nSTATUS=" + text)
}

func (s *sdStatus) send(msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopping {
		return
	}
	s.write(msg)
}

// write sends msg; the caller holds mu. A failed send only loses the
// status line, so it is logged at debug level.
func (s *sdStatus) write(msg string) {
	if err := s.notify(msg); err != nil {
		log.Debug().Err(err).Msg("sd_notify")
	}
}
