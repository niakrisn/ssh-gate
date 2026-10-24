package main

import (
	"testing"
)

func TestContains(t *testing.T) {
	tests := []struct {
		name  string
		slice []string
		s     string
		want  bool
	}{
		{
			name:  "empty slice",
			slice: []string{},
			s:     "test",
			want:  false,
		},
		{
			name:  "found",
			slice: []string{"a", "b", "c"},
			s:     "b",
			want:  true,
		},
		{
			name:  "not found",
			slice: []string{"a", "b", "c"},
			s:     "d",
			want:  false,
		},
		{
			name:  "case sensitive",
			slice: []string{"A", "B", "C"},
			s:     "a",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := contains(tt.slice, tt.s); got != tt.want {
				t.Errorf("contains(%v, %q) = %v, want %v", tt.slice, tt.s, got, tt.want)
			}
		})
	}
}

func TestValidatePort(t *testing.T) {
	tests := []struct {
		name    string
		port    int
		wantErr bool
	}{
		{
			name:    "valid port",
			port:    80,
			wantErr: false,
		},
		{
			name:    "port 1",
			port:    1,
			wantErr: false,
		},
		{
			name:    "port 65535",
			port:    65535,
			wantErr: false,
		},
		{
			name:    "port 0",
			port:    0,
			wantErr: true,
		},
		{
			name:    "port negative",
			port:    -1,
			wantErr: true,
		},
		{
			name:    "port too large",
			port:    65536,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePort(tt.port)
			if (err != nil) != tt.wantErr {
				t.Errorf("validatePort(%d) error = %v, wantErr %v", tt.port, err, tt.wantErr)
			}
		})
	}
}

func TestValidateHostPort(t *testing.T) {
	tests := []struct {
		name     string
		hostPort string
		wantErr  bool
	}{
		{
			name:     "valid host:port",
			hostPort: "localhost:8080",
			wantErr:  false,
		},
		{
			name:     "valid :port",
			hostPort: ":8080",
			wantErr:  false,
		},
		{
			name:     "empty",
			hostPort: "",
			wantErr:  true,
		},
		{
			name:     "no colon",
			hostPort: "localhost",
			wantErr:  true,
		},
		{
			name:     "empty port",
			hostPort: ":",
			wantErr:  true,
		},
		{
			name:     "empty host port",
			hostPort: "localhost:",
			wantErr:  true,
		},
		{
			name:     "valid ipv6 literal",
			hostPort: "[::1]:8080",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateHostPort(tt.hostPort)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateHostPort(%q) error = %v, wantErr %v", tt.hostPort, err, tt.wantErr)
			}
		})
	}
}
