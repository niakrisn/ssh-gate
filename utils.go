package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
)

// contains checks if a string is present in a slice.
func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

// validatePort validates that a port number is within valid range.
func validatePort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid port %d: must be between 1 and 65535", port)
	}
	return nil
}

// validateHostPort validates a host:port string. An empty port is rejected:
// net.Listen would treat it as an ephemeral port, which is never intended.
func validateHostPort(hostPort string) error {
	if hostPort == "" {
		return fmt.Errorf("empty host:port")
	}
	_, port, err := net.SplitHostPort(hostPort)
	if err != nil || port == "" {
		return fmt.Errorf("invalid host:port format: %s (expected host:port)", hostPort)
	}
	return nil
}

// writeFileAtomic writes data to path through a temp file in the same
// directory and a rename, so a crash never leaves a truncated file behind.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
