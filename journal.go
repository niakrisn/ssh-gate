package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
)

const journalSocket = "/run/systemd/journal/socket"

// journalWriter tags a record; the shared owner performs all sink I/O.
type journalWriter struct {
	owner *logging
	ident string
}

type logRecord struct {
	ident string
	level zerolog.Level
	data  []byte
}

const maxLogRecord = 16 << 10

// logging owns bounded queues for both loggers. Sink backpressure must not
// propagate to proxy handlers. A blocked stderr write can retain this one
// worker, but cannot create a worker or unbounded memory per record.
type logging struct {
	mu         sync.Mutex
	normal     chan logRecord
	priority   chan logRecord
	wake       chan struct{}
	idle       chan struct{}
	done       chan struct{}
	pending    int
	stopped    bool
	conn       *net.UnixConn
	stderr     io.Writer
	fallback   chan logRecord
	stderrDone chan struct{}
	dropped    [2]atomic.Uint64
	reported   [2]uint64
	lastReport time.Time
}

func newLogging(conn *net.UnixConn, stderr io.Writer) *logging {
	l := &logging{normal: make(chan logRecord, 960), priority: make(chan logRecord, 64),
		wake: make(chan struct{}, 1), idle: make(chan struct{}), done: make(chan struct{}), conn: conn, stderr: stderr}
	close(l.idle)
	l.stderrDone = make(chan struct{})
	if conn != nil {
		l.fallback = make(chan logRecord, 64)
		go l.runStderr()
	} else {
		close(l.stderrDone)
	}
	go l.run()
	return l
}

func logIdentIndex(ident string) int {
	if ident == journalAccessIdent {
		return 1
	}
	return 0
}

func (l *logging) enqueue(ident string, level zerolog.Level, p []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	drop := &l.dropped[logIdentIndex(ident)]
	if l.stopped {
		drop.Add(1)
		return
	}
	q := l.normal
	if level >= zerolog.WarnLevel && level <= zerolog.PanicLevel {
		q = l.priority
	}
	if len(q) == cap(q) {
		if level != zerolog.FatalLevel {
			drop.Add(1)
			return
		}
		old := <-q
		l.dropped[logIdentIndex(old.ident)].Add(1)
		l.pending--
	}
	var data []byte
	if len(p) > maxLogRecord {
		data, _ = json.Marshal(struct {
			Level   string `json:"level"`
			Ident   string `json:"ident"`
			Message string `json:"message"`
			Length  int    `json:"original_length"`
		}{level.String(), ident, "log record too large", len(p)})
		data = append(data, '\n')
	} else {
		data = bytes.Clone(p)
	}
	if l.pending == 0 {
		l.idle = make(chan struct{})
	}
	l.pending++
	q <- logRecord{ident, level, data}
	select {
	case l.wake <- struct{}{}:
	default:
	}
}

func (l *logging) run() {
	defer close(l.done)
	if l.fallback != nil {
		defer close(l.fallback)
	}
	for {
		l.mu.Lock()
		var r logRecord
		found := true
		select {
		case r = <-l.priority:
		default:
			select {
			case r = <-l.normal:
			default:
				found = false
			}
		}
		stop := l.stopped
		l.mu.Unlock()
		if !found {
			if stop {
				return
			}
			<-l.wake
			continue
		}
		if l.send(r) == nil {
			l.reportDrops()
		}
		l.finishRecord()
	}
}

func (l *logging) finishRecord() {
	l.mu.Lock()
	l.pending--
	if l.pending == 0 {
		close(l.idle)
	}
	l.mu.Unlock()
}

func (l *logging) runStderr() {
	defer close(l.stderrDone)
	for r := range l.fallback {
		_, _ = l.stderr.Write(r.data)
		l.finishRecord()
	}
}

func (l *logging) send(r logRecord) error {
	if l.conn != nil {
		_ = l.conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
		_, err := l.conn.Write(journalEntry(r.ident, r.level, r.data))
		if err == nil {
			return nil
		}
		// The fallback has one worker of its own; a blocked stderr must
		// never stop attempts to use a recovered journal socket.
		l.mu.Lock()
		select {
		case l.fallback <- r:
			l.pending++
		default:
			l.dropped[logIdentIndex(r.ident)].Add(1)
		}
		l.mu.Unlock()
		return err
	}
	_, err := l.stderr.Write(r.data)
	return err
}

func (l *logging) reportDrops() {
	if time.Since(l.lastReport) < time.Minute {
		return
	}
	reported := false
	for i, ident := range []string{journalIdent, journalAccessIdent} {
		n := l.dropped[i].Load()
		if n == l.reported[i] {
			continue
		}
		p, _ := json.Marshal(struct {
			Level   string `json:"level"`
			Ident   string `json:"ident"`
			Message string `json:"message"`
			Dropped uint64 `json:"dropped"`
		}{"warn", ident, "log records dropped", n - l.reported[i]})
		if l.send(logRecord{ident, zerolog.WarnLevel, append(p, '\n')}) == nil {
			l.reported[i] = n
			reported = true
		}
	}
	if reported {
		l.lastReport = time.Now()
	}
}

func (l *logging) Flush(ctx context.Context) error {
	l.mu.Lock()
	idle := l.idle
	l.mu.Unlock()
	select {
	case <-idle:
		return nil
	default:
	}
	select {
	case <-idle:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l *logging) Shutdown(ctx context.Context) error {
	l.mu.Lock()
	l.stopped = true
	select {
	case l.wake <- struct{}{}:
	default:
	}
	l.mu.Unlock()
	if l.conn != nil {
		defer l.conn.Close()
	}
	if err := l.Flush(ctx); err != nil {
		return err
	}
	select {
	case <-l.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-l.stderrDone:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l *logging) stop() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = l.Shutdown(ctx)
}

func (l *logging) exitFatal() {
	l.stop()
	os.Exit(exitConfig)
}

// dialJournal opens the journald datagram socket. One socket is shared by
// all writers: a datagram write is atomic and safe for concurrent use.
func dialJournal() (*net.UnixConn, error) {
	return net.DialUnix("unixgram", nil, &net.UnixAddr{Name: journalSocket, Net: "unixgram"})
}

func (w *journalWriter) Write(p []byte) (int, error) {
	return w.WriteLevel(zerolog.NoLevel, p)
}

func (w *journalWriter) WriteLevel(level zerolog.Level, p []byte) (int, error) {
	w.owner.enqueue(w.ident, level, p)
	return len(p), nil
}

// journalEntry builds one native protocol datagram. MESSAGE uses the binary
// field form (name, newline, little-endian 64-bit length, data), which needs
// no escaping whatever the line holds.
func journalEntry(ident string, level zerolog.Level, p []byte) []byte {
	msg := bytes.TrimSuffix(p, []byte("\n"))
	b := make([]byte, 0, len(msg)+64+len(ident))
	b = append(b, "PRIORITY="...)
	b = strconv.AppendInt(b, int64(journalPriority(level)), 10)
	b = append(b, "\nSYSLOG_IDENTIFIER="...)
	b = append(b, ident...)
	b = append(b, "\nMESSAGE\n"...)
	b = binary.LittleEndian.AppendUint64(b, uint64(len(msg)))
	b = append(b, msg...)
	b = append(b, '\n')
	return b
}

// journalPriority maps zerolog levels to syslog priorities. Fatal and panic
// stop at crit: emerg would be broadcast to every terminal.
func journalPriority(level zerolog.Level) int {
	switch level {
	case zerolog.TraceLevel, zerolog.DebugLevel:
		return 7
	case zerolog.InfoLevel:
		return 6
	case zerolog.WarnLevel:
		return 4
	case zerolog.ErrorLevel:
		return 3
	case zerolog.FatalLevel, zerolog.PanicLevel:
		return 2
	default:
		return 6
	}
}
