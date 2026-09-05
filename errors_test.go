package main

import (
	"errors"
	"testing"
)

func TestConfigurationError(t *testing.T) {
	tests := []struct {
		name     string
		field    string
		value    string
		message  string
		want     string
	}{
		{
			name:    "with message",
			field:   "port",
			value:   "abc",
			message: "not a number",
			want:    "port: not a number",
		},
		{
			name:    "without message",
			field:   "port",
			value:   "abc",
			message: "",
			want:    "invalid port: abc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewConfigurationError(tt.field, tt.value, tt.message)
			if got := err.Error(); got != tt.want {
				t.Errorf("ConfigurationError.Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

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

func TestSSHError(t *testing.T) {
	baseErr := errors.New("authentication failed")
	err := NewSSHError("connection", "example.com", 22, baseErr)

	if got := err.Error(); got != "SSH connection to example.com:22 failed: authentication failed" {
		t.Errorf("SSHError.Error() = %q, want %q", got, "SSH connection to example.com:22 failed: authentication failed")
	}

	if !errors.Is(err, baseErr) {
		t.Error("SSHError should wrap base error")
	}
}