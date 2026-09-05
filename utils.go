package main

import (
	"fmt"
	"strings"
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

// containsAny checks if any of the strings in the needles slice
// is present in the haystack slice.
func containsAny(haystack []string, needles []string) bool {
	for _, h := range haystack {
		for _, n := range needles {
			if h == n {
				return true
			}
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

// validateHostPort validates a host:port string.
func validateHostPort(hostPort string) error {
	if hostPort == "" {
		return fmt.Errorf("empty host:port")
	}
	// Basic validation - more comprehensive validation happens at runtime
	if !strings.Contains(hostPort, ":") && hostPort != "" {
		return fmt.Errorf("invalid host:port format: %s (expected host:port)", hostPort)
	}
	return nil
}

// firstNonEmpty returns the first non-empty string from the arguments.
func firstNonEmpty(strings ...string) string {
	for _, s := range strings {
		if s != "" {
			return s
		}
	}
	return ""
}