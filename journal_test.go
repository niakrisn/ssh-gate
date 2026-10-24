package main

import (
	"bytes"
	"encoding/binary"
	"net"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
)

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
	var fallback bytes.Buffer
	w := &journalWriter{conn: conn, ident: "ssh-gate", fallback: &fallback}
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
	if fallback.Len() != 0 {
		t.Fatalf("fallback used on a good socket: %q", fallback.String())
	}

	// journald gone: the line must still land somewhere.
	conn.Close()
	logger.Error().Msg("after close")
	if !bytes.Contains(fallback.Bytes(), []byte(`"message":"after close"`)) {
		t.Fatalf("fallback: %q", fallback.String())
	}
}
