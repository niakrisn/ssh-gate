package main

import "testing"

// TestParseKeepalivePeriod covers the semantics of SSH_KEEPALIVE_PERIOD:
// valid Go durations pass through; empty/0/0s disable keepalive (0);
// an unparseable value is a hard error so the container fails loud on bad input.
func TestParseKeepalivePeriod(t *testing.T) {
	valid := map[string]struct {
		want    float64 // seconds, 0 = disabled
		wantErr bool
	}{
		"90s": {want: 90},
		"2m":  {want: 120},
		"1h":  {want: 3600},
		"0s":  {want: 0},
		"0":   {want: 0},
		"":    {want: 0},
		"abc": {wantErr: true},
		"10x": {wantErr: true},
	}

	for raw, want := range valid {
		got, err := parseKeepalivePeriod(raw)
		if want.wantErr {
			if err == nil {
				t.Errorf("parseKeepalivePeriod(%q): expected error, got nil", raw)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseKeepalivePeriod(%q): unexpected error: %v", raw, err)
			continue
		}
		if got.Seconds() != want.want {
			t.Errorf("parseKeepalivePeriod(%q) = %v, want %v seconds", raw, got, want.want)
		}
	}
}
