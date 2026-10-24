//go:build !linux

package main

// stderrIsJournal: journald is Linux only.
func stderrIsJournal() bool {
	return false
}
