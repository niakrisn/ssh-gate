package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

type fakeDohRecord struct {
	Type int    `json:"Type"`
	Data string `json:"Data"`
}

// dohAnswer is one fake server response: a dns-json RCODE plus the record
// lists returned on NOERROR.
type dohAnswer struct {
	status int // 0 NOERROR, 2 SERVFAIL, 3 NXDOMAIN
	a      []string
	aaaa   []string
}

// startFakeDoHServer starts an in-process dns-json DoH server; reply picks
// the answer per question (name and type A/AAAA). Its TLS cert is valid
// for 127.0.0.1 and ::1 only, which the probeDohIP cases rely on
// (127.0.0.2 simulates "no IP SAN").
func startFakeDoHServer(t *testing.T, reply func(name, qtype string) dohAnswer) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
		name, qtype := r.URL.Query().Get("name"), r.URL.Query().Get("type")
		ans := reply(name, qtype)
		var recs []fakeDohRecord
		if ans.status == 0 {
			if qtype == "AAAA" {
				for _, s := range ans.aaaa {
					recs = append(recs, fakeDohRecord{Type: 28, Data: s})
				}
			} else {
				for _, s := range ans.a {
					recs = append(recs, fakeDohRecord{Type: 1, Data: s})
				}
			}
		}
		body, err := json.Marshal(struct {
			Status int             `json:"Status"`
			Answer []fakeDohRecord `json:"Answer"`
		}{Status: ans.status, Answer: recs})
		if err != nil {
			t.Errorf("marshal fake answer: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-json")
		w.Write(body)
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// staticAnswer answers every question with the given record lists.
func staticAnswer(a, aaaa []string) func(name, qtype string) dohAnswer {
	return func(_, _ string) dohAnswer { return dohAnswer{a: a, aaaa: aaaa} }
}

// setBootstrap returns the dialer and bootstrap that point at the fake
// server: the testDialer redirects every tunnel dial (bootstrap and probe)
// to it, and the bootstrap trusts its test CA.
func setBootstrap(t *testing.T, srv *httptest.Server) (testDialer, dohBootstrap) {
	t.Helper()
	addr := srv.Listener.Addr().String()
	return testDialer{Target: addr}, dohBootstrap{
		addr: addr,
		tls:  srv.Client().Transport.(*http.Transport).TLSClientConfig,
	}
}

func mustAddrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

// TestPickDohIP: IPv4 is preferred, a probe-failing IP is skipped, v6 is
// the fallback, and an empty or fully rejected answer yields the zero Addr.
func TestPickDohIP(t *testing.T) {
	cases := []struct {
		name    string
		v4, v6  []netip.Addr
		passing map[string]bool
		want    netip.Addr
	}{
		{"prefer v4", mustAddrs("1.1.1.1"), mustAddrs("::1"), map[string]bool{"1.1.1.1": true, "::1": true}, netip.MustParseAddr("1.1.1.1")},
		{"v6 fallback", nil, mustAddrs("::1"), map[string]bool{"::1": true}, netip.MustParseAddr("::1")},
		{"skip probe-failing v4", mustAddrs("2.2.2.2", "1.1.1.1"), nil, map[string]bool{"1.1.1.1": true}, netip.MustParseAddr("1.1.1.1")},
		{"skip probe-failing v4, use v6", mustAddrs("2.2.2.2"), mustAddrs("::1"), map[string]bool{"::1": true}, netip.MustParseAddr("::1")},
		{"nothing passes", mustAddrs("2.2.2.2"), nil, nil, netip.Addr{}},
		{"empty", nil, nil, nil, netip.Addr{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := pickDohIP(tc.v4, tc.v6, func(ip netip.Addr) bool { return tc.passing[ip.String()] })
			if got != tc.want {
				t.Errorf("pickDohIP() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestResolveDohIP: the lookup goes through the tunnel (bootstrap DoH) and
// the chosen IP must pass the IP-TLS probe; every failure path falls back
// to defaultDohIP.
func TestResolveDohIP(t *testing.T) {
	t.Run("empty host, no dial", func(t *testing.T) {
		d := testDialer{Err: errors.New("dialer must not be used")}
		if got := resolveDohIP("", d, defaultDohBootstrap); got != defaultDohIP {
			t.Errorf("resolveDohIP() = %q, want %q", got, defaultDohIP)
		}
	})

	t.Run("bootstrap failure", func(t *testing.T) {
		d := testDialer{Err: errors.New("tunnel down")}
		if got := resolveDohIP("dohhost.example:443", d, defaultDohBootstrap); got != defaultDohIP {
			t.Errorf("resolveDohIP() = %q, want %q", got, defaultDohIP)
		}
	})

	t.Run("prefer v4 over v6", func(t *testing.T) {
		srv := startFakeDoHServer(t, staticAnswer([]string{"127.0.0.1"}, []string{"::1"}))
		d, b := setBootstrap(t, srv)
		if got := resolveDohIP("dohhost.example", d, b); got != "127.0.0.1" {
			t.Errorf("resolveDohIP() = %q, want 127.0.0.1", got)
		}
	})

	// 127.0.0.2 is not in the test cert's IP SANs, so its probe must fail
	// and the next candidate must win.
	t.Run("skip candidate without IP SAN", func(t *testing.T) {
		srv := startFakeDoHServer(t, staticAnswer([]string{"127.0.0.2", "127.0.0.1"}, nil))
		d, b := setBootstrap(t, srv)
		if got := resolveDohIP("dohhost.example", d, b); got != "127.0.0.1" {
			t.Errorf("resolveDohIP() = %q, want 127.0.0.1", got)
		}
	})

	t.Run("no usable address", func(t *testing.T) {
		srv := startFakeDoHServer(t, staticAnswer([]string{"127.0.0.2"}, nil))
		d, b := setBootstrap(t, srv)
		if got := resolveDohIP("dohhost.example", d, b); got != defaultDohIP {
			t.Errorf("resolveDohIP() = %q, want %q", got, defaultDohIP)
		}
	})

	t.Run("v6 fallback when no A records", func(t *testing.T) {
		srv := startFakeDoHServer(t, staticAnswer(nil, []string{"::1"}))
		d, b := setBootstrap(t, srv)
		if got := resolveDohIP("dohhost.example", d, b); got != "::1" {
			t.Errorf("resolveDohIP() = %q, want ::1", got)
		}
	})

	// A provider that answers the probe name (example.com) with a
	// definitive NXDOMAIN still passes: the probe checks transport and
	// TLS, not the answer.
	t.Run("probe NXDOMAIN counts as pass", func(t *testing.T) {
		srv := startFakeDoHServer(t, func(name, _ string) dohAnswer {
			if name == "example.com" {
				return dohAnswer{status: 3}
			}
			return dohAnswer{a: []string{"127.0.0.1"}}
		})
		d, b := setBootstrap(t, srv)
		if got := resolveDohIP("dohhost.example", d, b); got != "127.0.0.1" {
			t.Errorf("resolveDohIP() = %q, want 127.0.0.1", got)
		}
	})

	// A non-definitive probe failure (SERVFAIL) rejects the candidate,
	// unlike a definitive NXDOMAIN.
	t.Run("probe SERVFAIL rejects candidate", func(t *testing.T) {
		srv := startFakeDoHServer(t, func(name, _ string) dohAnswer {
			if name == "example.com" {
				return dohAnswer{status: 2}
			}
			return dohAnswer{a: []string{"127.0.0.1"}}
		})
		d, b := setBootstrap(t, srv)
		if got := resolveDohIP("dohhost.example", d, b); got != defaultDohIP {
			t.Errorf("resolveDohIP() = %q, want %q", got, defaultDohIP)
		}
	})

	// A failing AAAA bootstrap lookup (non-NXDOMAIN) is not fatal: the v4
	// answer is still usable.
	t.Run("AAAA failure falls back to v4", func(t *testing.T) {
		srv := startFakeDoHServer(t, func(_, qtype string) dohAnswer {
			if qtype == "AAAA" {
				return dohAnswer{status: 2}
			}
			return dohAnswer{a: []string{"127.0.0.1"}}
		})
		d, b := setBootstrap(t, srv)
		if got := resolveDohIP("dohhost.example", d, b); got != "127.0.0.1" {
			t.Errorf("resolveDohIP() = %q, want 127.0.0.1", got)
		}
	})
}
