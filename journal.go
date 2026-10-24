package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strconv"

	"github.com/rs/zerolog"
)

const journalSocket = "/run/systemd/journal/socket"

// journalWriter sends log lines to systemd-journald over its native
// protocol, so each line keeps its priority (journalctl -p works) and its
// own SYSLOG_IDENTIFIER (journalctl -t splits the access log from the rest).
// MESSAGE is the JSON line as is. A failed send goes to fallback, so a
// stopped journald never loses a Fatal line.
type journalWriter struct {
	conn     *net.UnixConn
	ident    string
	fallback io.Writer
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
	if _, err := w.conn.Write(journalEntry(w.ident, level, p)); err != nil {
		return w.fallback.Write(p)
	}
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
