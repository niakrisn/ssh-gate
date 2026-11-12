package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

type blockedLogWriter struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	buf     syncBuffer
}

func (w *blockedLogWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	return w.buf.Write(p)
}

func TestLoggingBackpressure(t *testing.T) {
	sink := &blockedLogWriter{entered: make(chan struct{}), release: make(chan struct{})}
	defer close(sink.release)
	owner := newLogging(nil, sink)
	t.Cleanup(func() { shutdownTestLogging(t, owner) })
	w := &journalWriter{owner: owner, ident: journalIdent}
	go w.WriteLevel(zerolog.InfoLevel, []byte("{}\n"))
	<-sink.entered
	done := make(chan struct{})
	go func() {
		for range 10000 {
			_, _ = w.WriteLevel(zerolog.InfoLevel, []byte("{}\n"))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("log producers blocked on sink")
	}
	if got := owner.dropped[0].Load(); got != 9040 {
		t.Fatalf("dropped=%d, want 9040", got)
	}
	if len(owner.normal) != 960 || len(owner.priority) != 0 {
		t.Fatal("queue limit not enforced")
	}
}

func TestJournalFullSocket(t *testing.T) {
	addr := &net.UnixAddr{Name: filepath.Join(t.TempDir(), "journal"), Net: "unixgram"}
	srv, err := net.ListenUnixgram("unixgram", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	_ = srv.SetReadBuffer(4096)
	conn, err := net.DialUnix("unixgram", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetWriteBuffer(4096)
	sink := &blockedLogWriter{entered: make(chan struct{}), release: make(chan struct{})}
	l := newLogging(conn, sink)
	t.Cleanup(func() { shutdownTestLogging(t, l) })
	defer close(sink.release)
	w := &journalWriter{owner: l, ident: journalIdent}
	for range 128 {
		w.Write(bytes.Repeat([]byte("x"), 2048))
	}
	select {
	case <-sink.entered:
	case <-time.After(time.Second):
		conn.Close()
		t.Fatal("full journal socket never reached bounded fallback")
	}
	w.Write([]byte("journal recovered\n"))
	_ = srv.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	for {
		n, err := srv.Read(buf)
		if err != nil {
			t.Fatalf("blocked stderr prevented journal recovery: %v", err)
		}
		if bytes.Contains(buf[:n], []byte("journal recovered")) {
			break
		}
	}
}

func TestLoggingShutdownBounded(t *testing.T) {
	sink := &blockedLogWriter{entered: make(chan struct{}), release: make(chan struct{})}
	l := newLogging(nil, sink)
	w := &journalWriter{owner: l, ident: journalIdent}
	w.Write([]byte("{}\n"))
	<-sink.entered
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	for range 3 {
		if err := l.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("shutdown: %v", err)
		}
	}
	close(sink.release)
	shutdownTestLogging(t, l)
}

func TestLoggingFallbackBounded(t *testing.T) {
	addr := &net.UnixAddr{Name: filepath.Join(t.TempDir(), "journal"), Net: "unixgram"}
	srv, err := net.ListenUnixgram("unixgram", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	conn, err := net.DialUnix("unixgram", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	sink := &blockedLogWriter{entered: make(chan struct{}), release: make(chan struct{})}
	l := newLogging(conn, sink)
	t.Cleanup(func() { close(sink.release); shutdownTestLogging(t, l) })
	w := &journalWriter{owner: l, ident: journalIdent}
	w.Write([]byte("{}\n"))
	<-sink.entered
	for range 10000 {
		w.Write([]byte("{}\n"))
	}
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		l.mu.Lock()
		pending, queued := l.pending, len(l.fallback)
		l.mu.Unlock()
		if pending == 65 && queued == 64 && l.dropped[0].Load() == 9936 {
			break
		}
		select {
		case <-deadline.C:
			t.Fatalf("pending=%d fallback=%d dropped=%d", pending, queued, l.dropped[0].Load())
		case <-tick.C:
		}
	}
}

func TestDNSStatusDoesNotWaitForLog(t *testing.T) {
	sink := &blockedLogWriter{entered: make(chan struct{}), release: make(chan struct{})}
	prev := testAppLog.set(sink)
	finished := make(chan struct{})
	defer func() { close(sink.release); <-finished; testAppLog.set(prev) }()
	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatal(err)
	}
	defer rules.Stop()
	u := &upstream{name: "test"}
	rules.dns.tunnel = []*upstream{u}
	rules.dns.tunnelUp = func() bool { return true }
	go func() { defer close(finished); rules.dns.upstreamFailed(u, errUnreachable) }()
	<-sink.entered
	status := make(chan dnsStatus, 1)
	go func() { status <- rules.DNSStatus() }()
	select {
	case s := <-status:
		if s.Servers[0].Fail != 1 {
			t.Fatalf("status: %+v", s)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("DNSStatus waits for log sink while holding resolver mutex")
	}
}

func TestLoggingFatalExit(t *testing.T) {
	if mode := os.Getenv("SSH_GATE_TEST_FATAL"); mode != "" {
		var owner *logging
		if mode == "blocked" {
			sink := &blockedLogWriter{entered: make(chan struct{}), release: make(chan struct{})}
			owner = newLogging(nil, sink)
		} else {
			owner = newLogging(nil, os.Stderr)
		}
		// Use the same fatal owner/exit contract as main.
		zerolog.FatalExitFunc = owner.exitFatal
		logger := zerolog.New(&journalWriter{owner: owner, ident: journalIdent})
		logger.Fatal().Msg("fatal delivery")
		return
	}
	for _, mode := range []string{"ready", "blocked"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLoggingFatalExit$")
			cmd.Env = append(os.Environ(), "SSH_GATE_TEST_FATAL="+mode)
			b, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != exitConfig {
				t.Fatalf("exit: %v output=%s", err, b)
			}
			if mode == "ready" && !bytes.Contains(b, []byte("fatal delivery")) {
				t.Fatalf("missing fatal: %s", b)
			}
		})
	}
}

func shutdownTestLogging(t *testing.T, l *logging) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := l.Shutdown(ctx); err != nil {
		t.Error(err)
	}
}

func TestLoggingCopiesBuffer(t *testing.T) {
	sink := &blockedLogWriter{entered: make(chan struct{}), release: make(chan struct{})}
	l := newLogging(nil, sink)
	t.Cleanup(func() { shutdownTestLogging(t, l) })
	w := &journalWriter{owner: l, ident: journalAccessIdent}
	w.Write([]byte("{}\n"))
	<-sink.entered
	p := []byte("{\"message\":\"original\"}\n")
	w.Write(p)
	copy(p, bytes.Repeat([]byte("x"), len(p)))
	close(sink.release)
	shutdownTestLogging(t, l)
	if !bytes.Contains(sink.buf.Bytes(), []byte(`"original"`)) {
		t.Fatalf("buffer reused: %s", sink.buf.String())
	}
}

func TestLoggingRecordLimit(t *testing.T) {
	var sink syncBuffer
	l := newLogging(nil, &sink)
	w := &journalWriter{owner: l, ident: journalAccessIdent}
	w.WriteLevel(zerolog.ErrorLevel, bytes.Repeat([]byte("x"), 20000))
	shutdownTestLogging(t, l)
	var r struct {
		Level, Ident string
		Length       int `json:"original_length"`
	}
	if err := json.Unmarshal(sink.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if r.Level != "error" || r.Ident != journalAccessIdent || r.Length != 20000 || len(sink.Bytes()) > 16384 {
		t.Fatalf("replacement: %s", sink.String())
	}
}

func TestLoggingPrioritiesAndRecovery(t *testing.T) {
	sink := &blockedLogWriter{entered: make(chan struct{}), release: make(chan struct{})}
	l := newLogging(nil, sink)
	app := &journalWriter{owner: l, ident: journalIdent}
	access := &journalWriter{owner: l, ident: journalAccessIdent}
	app.Write([]byte("{}\n"))
	<-sink.entered
	for range 961 {
		access.Write([]byte("{\"message\":\"access\"}\n"))
	}
	for range 65 {
		app.WriteLevel(zerolog.WarnLevel, []byte("{\"message\":\"warning\"}\n"))
	}
	app.WriteLevel(zerolog.FatalLevel, []byte("{\"message\":\"fatal\"}\n"))
	if l.dropped[0].Load() != 2 || l.dropped[1].Load() != 1 {
		t.Fatal("lost records not counted by ident")
	}
	close(sink.release)
	shutdownTestLogging(t, l)
	b := sink.buf.Bytes()
	if !bytes.Contains(b, []byte(`"fatal"`)) || !bytes.Contains(b, []byte(`"ident":"ssh-gate-access"`)) || !bytes.Contains(b, []byte(`"dropped":2`)) {
		t.Fatalf("missing priority/recovery records: %.500s", b)
	}
	if bytes.Index(b, []byte(`"fatal"`)) > bytes.Index(b, []byte(`"access"`)) {
		t.Fatal("priority was left behind normal records")
	}
}

func TestJournalEntry(t *testing.T) {
	line := []byte(`{"level":"warn","message":"a=b\nc"}` + "\n")
	got := journalEntry("ssh-gate-access", zerolog.WarnLevel, line)

	msg := line[:len(line)-1]
	var want []byte
	want = append(want, "PRIORITY=4\nSYSLOG_IDENTIFIER=ssh-gate-access\nMESSAGE\n"...)
	want = binary.LittleEndian.AppendUint64(want, uint64(len(msg)))
	want = append(want, msg...)
	want = append(want, '\n')
	if !bytes.Equal(got, want) {
		t.Fatalf("entry:\n got %q\nwant %q", got, want)
	}
}

func TestJournalPriority(t *testing.T) {
	cases := map[zerolog.Level]int{
		zerolog.TraceLevel: 7,
		zerolog.DebugLevel: 7,
		zerolog.InfoLevel:  6,
		zerolog.WarnLevel:  4,
		zerolog.ErrorLevel: 3,
		zerolog.FatalLevel: 2,
		zerolog.PanicLevel: 2,
		zerolog.NoLevel:    6,
	}
	for level, want := range cases {
		if got := journalPriority(level); got != want {
			t.Errorf("%v: got %d, want %d", level, got, want)
		}
	}
}

func TestJournalWriterSendsAndFallsBack(t *testing.T) {
	addr := &net.UnixAddr{Name: filepath.Join(t.TempDir(), "journal"), Net: "unixgram"}
	srv, err := net.ListenUnixgram("unixgram", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	conn, err := net.DialUnix("unixgram", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	var fallback syncBuffer
	owner := newLogging(conn, &fallback)
	t.Cleanup(func() { shutdownTestLogging(t, owner) })
	w := &journalWriter{owner: owner, ident: "ssh-gate"}
	logger := zerolog.New(w)

	logger.Error().Msg("boom")
	buf := make([]byte, 4096)
	n, err := srv.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(buf[:n], []byte("PRIORITY=3\nSYSLOG_IDENTIFIER=ssh-gate\nMESSAGE\n")) {
		t.Fatalf("datagram: %q", buf[:n])
	}
	if len(fallback.Bytes()) != 0 {
		t.Fatalf("fallback used on a good socket: %q", fallback.String())
	}

	// journald gone: the line must still land somewhere.
	conn.Close()
	logger.Error().Msg("after close")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := owner.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(fallback.Bytes(), []byte(`"message":"after close"`)) {
		t.Fatalf("fallback: %q", fallback.String())
	}
}
