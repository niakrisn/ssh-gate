//go:build linux

package main

import (
	"fmt"
	"os"
	"syscall"
)

// stderrIsJournal reports whether stderr is the journal stream systemd set
// up for the service: JOURNAL_STREAM holds its device and inode. A shell
// redirect or a pipe from a child of the service does not match.
func stderrIsJournal() bool {
	v := os.Getenv("JOURNAL_STREAM")
	if v == "" {
		return false
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(int(os.Stderr.Fd()), &st); err != nil {
		return false
	}
	return v == fmt.Sprintf("%d:%d", st.Dev, st.Ino)
}
