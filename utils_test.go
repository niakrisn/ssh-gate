package main

import (
	"testing"
)

func TestContains(t *testing.T) {
	tests := []struct {
		name     string
		slice    []string
		s        string
		want     bool
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

func TestContainsAny(t *testing.T) {
	tests := []struct {
		name      string
		haystack []string
		needles  []string
		want      bool
	}{
		{
			name:      "empty haystack",
			haystack: []string{},
			needles:  []string{"a"},
			want:      false,
		},
		{
			name:      "empty needles",
			haystack: []string{"a", "b"},
			needles:  []string{},
			want:      false,
		},
		{
			name:      "found",
			haystack: []string{"a", "b", "c"},
			needles:  []string{"b", "d"},
			want:      true,
		},
		{
			name:      "not found",
			haystack: []string{"a", "b", "c"},
			needles:  []string{"d", "e"},
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := containsAny(tt.haystack, tt.needles); got != tt.want {
				t.Errorf("containsAny(%v, %v) = %v, want %v", tt.haystack, tt.needles, got, tt.want)
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
		name    string
		hostPort string
		wantErr bool
	}{
		{
			name:    "valid host:port",
			hostPort: "localhost:8080",
			wantErr: false,
		},
		{
			name:    "valid :port",
			hostPort: ":8080",
			wantErr: false,
		},
		{
			name:    "empty",
			hostPort: "",
			wantErr: true,
		},
		{
			name:    "no colon",
			hostPort: "localhost",
			wantErr: true,
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

func TestFirstNonEmpty(t *testing.T) {
	tests := []struct {
		name     string
		strings  []string
		want     string
	}{
		{
			name:     "first non-empty",
			strings:  []string{"", "", "test", "other"},
			want:     "test",
		},
		{
			name:     "all empty",
			strings:  []string{"", "", ""},
			want:     "",
		},
		{
			name:     "first is non-empty",
			strings:  []string{"first", "second"},
			want:     "first",
		},
		{
			name:     "empty list",
			strings:  []string{},
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := firstNonEmpty(tt.strings...); got != tt.want {
				t.Errorf("firstNonEmpty(%v) = %q, want %q", tt.strings, got, tt.want)
			}
		})
	}
}