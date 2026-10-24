package main

import (
	"errors"
	"testing"
)

func TestNetworkError(t *testing.T) {
	baseErr := errors.New("connection refused")
	err := NewNetworkError("dial", "example.com:80", baseErr)

	if got := err.Error(); got != "dial to example.com:80 failed: connection refused" {
		t.Errorf("NetworkError.Error() = %q, want %q", got, "dial to example.com:80 failed: connection refused")
	}

	if !errors.Is(err, baseErr) {
		t.Error("NetworkError should wrap base error")
	}
}

func TestDNSError(t *testing.T) {
	baseErr := errors.New("no such host")
	err := NewDNSError("example.com", baseErr)

	if got := err.Error(); got != "DNS resolution failed for example.com: no such host" {
		t.Errorf("DNSError.Error() = %q, want %q", got, "DNS resolution failed for example.com: no such host")
	}

	if !errors.Is(err, baseErr) {
		t.Error("DNSError should wrap base error")
	}
}
