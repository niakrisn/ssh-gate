package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// This endpoint exercises both public encodings with the same DNS outcomes.
func familyDoH(t *testing.T, format string, reply func(*http.Request, dnsmessage.Type) string) *RuleEngine {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg dnsmessage.Message
		if r.URL.Query().Has("dns") {
			var err error
			msg, err = readDoHWireQuery(r)
			if err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			if format == "json" {
				w.WriteHeader(400)
				return
			}
		} else {
			qtype := dnsmessage.TypeA
			if r.URL.Query().Get("type") == "AAAA" {
				qtype = dnsmessage.TypeAAAA
			}
			msg.Questions = []dnsmessage.Question{{Name: dnsmessage.MustNewName(r.URL.Query().Get("name") + "."), Type: qtype, Class: dnsmessage.ClassINET}}
		}
		q := msg.Questions[0]
		kind := reply(r, q.Type)
		msg.Response = true
		msg.Authorities = []dnsmessage.Resource{doHSOA("example.", 10, 10)}
		switch kind {
		case "address":
			var body dnsmessage.ResourceBody = &dnsmessage.AResource{A: [4]byte{203, 0, 113, 1}}
			if q.Type == dnsmessage.TypeAAAA {
				body = &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2001:db8::1").As16()}
			}
			msg.Answers = []dnsmessage.Resource{doHRecord(q.Name.String(), 60, body)}
		case "nodata":
		case "nxdomain":
			msg.RCode = dnsmessage.RCodeNameError
		case "servfail":
			msg.RCode = dnsmessage.RCodeServerFailure
		case "refused":
			msg.RCode = dnsmessage.RCodeRefused
		case "HTTP400":
			w.WriteHeader(400)
			return
		case "HTTP429":
			w.WriteHeader(429)
			return
		case "HTTP503":
			w.WriteHeader(503)
			return
		case "silent":
			<-r.Context().Done()
			return
		case "broken":
			if format == "wire" {
				w.Header().Set("Content-Type", dohWireMediaType)
			} else {
				w.Header().Set("Content-Type", "application/dns-json")
			}
			io.WriteString(w, "broken")
			return
		default:
			t.Errorf("unknown reply %q", kind)
			w.WriteHeader(500)
			return
		}
		if format == "wire" {
			writeDoHWireResponse(t, w, msg)
			return
		}
		w.Header().Set("Content-Type", "application/dns-json")
		if len(msg.Answers) == 0 {
			fmt.Fprintf(w, `{"Status":%d}`, msg.RCode)
			return
		}
		ip := "203.0.113.1"
		if q.Type == dnsmessage.TypeAAAA {
			ip = "2001:db8::1"
		}
		fmt.Fprintf(w, `{"Status":0,"Answer":[{"Type":%d,"Data":%q}]}`, q.Type, ip)
	}))
	t.Cleanup(srv.Close)
	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatal(err)
	}
	rules.dns.dohHost = strings.TrimPrefix(srv.URL, "https://")
	rules.dns.dohClient = srv.Client()
	rules.dns.dohClient.CheckRedirect = checkDoHRedirect
	rules.dns.tunnelUp = func() bool { return true }
	rules.dns.tunnel = []*upstream{{name: "test DoH", lookup: rules.dns.dohLookup}}
	t.Cleanup(rules.Stop)
	return rules
}

func TestDNSPartialFamilyDoH(t *testing.T) {
	for _, format := range []string{"wire", "json"} {
		for _, tc := range []struct {
			a, b     string
			count    int
			negative bool
		}{
			{"address", "address", 2, false}, {"address", "nodata", 1, false}, {"nodata", "address", 1, false},
			{"address", "servfail", 1, false}, {"servfail", "address", 1, false},
			{"address", "refused", 1, false}, {"refused", "address", 1, false},
			{"address", "HTTP503", 1, false}, {"HTTP503", "address", 1, false},
			{"address", "HTTP429", 1, false}, {"HTTP429", "address", 1, false},
			{"address", "nxdomain", 1, false}, {"nodata", "servfail", 0, false},
			{"nodata", "nodata", 0, true}, {"address", "broken", 0, false}, {"address", "HTTP400", 0, false},
		} {
			t.Run(format+"/"+tc.a+"/"+tc.b, func(t *testing.T) {
				rules := familyDoH(t, format, func(_ *http.Request, q dnsmessage.Type) string {
					if q == dnsmessage.TypeA {
						return tc.a
					}
					return tc.b
				})
				var local atomic.Int64
				rules.dns.localLookup = func(context.Context, string) ([]net.IPAddr, error) {
					local.Add(1)
					return nil, errors.New("local unavailable")
				}
				got, err := rules.ResolveAll(context.Background(), "partial.example")
				if tc.count > 0 {
					if err != nil || len(got) != tc.count || local.Load() != 0 {
						t.Fatalf("answer=%v err=%v local=%d", got, err, local.Load())
					}
					if st := rules.DNSStatus().Servers[0]; st.OK != 1 || st.Fail != 0 {
						t.Fatalf("partial marked failed: %+v", st)
					}
				} else if tc.negative {
					if !errors.Is(err, errNotFound) || local.Load() != 0 {
						t.Fatalf("negative=%v local=%d", err, local.Load())
					}
				} else if err == nil || local.Load() != 1 {
					t.Fatalf("failure=%v local=%d", err, local.Load())
				}
			})
		}
	}
}

func TestDoHPartialFamilyDeadline(t *testing.T) {
	for _, format := range []string{"wire", "json"} {
		t.Run(format, func(t *testing.T) {
			rules := familyDoH(t, format, func(_ *http.Request, q dnsmessage.Type) string {
				if q == dnsmessage.TypeA {
					return "address"
				}
				return "silent"
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				got, _, err := rules.dns.dohLookup(ctx, "deadline.example")
				if err == nil && len(got) != 1 {
					err = fmt.Errorf("addresses=%v", got)
				}
				done <- err
			}()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(800 * time.Millisecond):
				cancel()
				<-done
				t.Fatal("positive A waited for full resolver timeout")
			}
		})
	}
}

func TestDoHAWaitLeavesTimeForAAAA(t *testing.T) {
	for _, format := range []string{"wire", "json"} {
		t.Run(format, func(t *testing.T) {
			rules := familyDoH(t, format, func(_ *http.Request, q dnsmessage.Type) string {
				if q == dnsmessage.TypeA {
					return "silent"
				}
				return "address"
			})
			ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
			defer cancel()
			got, expiry, err := rules.dns.dohLookup(ctx, "aaaa.example")
			if err != nil || len(got) != 1 || !got[0].Is6() || expiry.After(time.Now()) {
				t.Fatalf("AAAA after A timeout=%v expiry=%v err=%v", got, expiry, err)
			}
		})
	}
}

func TestDNSPartialNotCachedDoH(t *testing.T) {
	for _, format := range []string{"wire", "json"} {
		t.Run(format, func(t *testing.T) {
			var recovered atomic.Bool
			var calls atomic.Int64
			rules := familyDoH(t, format, func(_ *http.Request, q dnsmessage.Type) string {
				calls.Add(1)
				if q == dnsmessage.TypeAAAA && !recovered.Load() {
					return "servfail"
				}
				return "address"
			})
			var local atomic.Int64
			rules.dns.localLookup = func(context.Context, string) ([]net.IPAddr, error) {
				local.Add(1)
				return nil, errors.New("unexpected local lookup")
			}
			got, err := rules.ResolveAll(context.Background(), "recover.example")
			if err != nil || len(got) != 1 {
				t.Fatalf("partial=%v %v", got, err)
			}
			recovered.Store(true)
			got, err = rules.ResolveAll(context.Background(), "recover.example")
			if err != nil || len(got) != 2 || calls.Load() != 4 || local.Load() != 0 {
				t.Fatalf("recovery=%v err=%v queries=%d local=%d", got, err, calls.Load(), local.Load())
			}
		})
	}
}

func TestDoHCallerCancelRejectsPartial(t *testing.T) {
	for _, format := range []string{"wire", "json"} {
		t.Run(format, func(t *testing.T) {
			started := make(chan struct{})
			var once sync.Once
			rules := familyDoH(t, format, func(_ *http.Request, q dnsmessage.Type) string {
				if q == dnsmessage.TypeA {
					return "address"
				}
				once.Do(func() { close(started) })
				return "silent"
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { _, _, err := rules.dns.dohLookup(ctx, "cancel.example"); done <- err }()
			<-started
			cancel()
			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled lookup returned partial: %v", err)
			}
		})
	}
}

func TestDNSNoFalseNegativeCacheDoH(t *testing.T) {
	for _, format := range []string{"wire", "json"} {
		for _, negative := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/NXDOMAIN=%t", format, negative), func(t *testing.T) {
				var recovered atomic.Bool
				var calls atomic.Int64
				rules := familyDoH(t, format, func(_ *http.Request, q dnsmessage.Type) string {
					calls.Add(1)
					if recovered.Load() {
						return "address"
					}
					if negative {
						if q == dnsmessage.TypeA {
							return "address"
						}
						return "nxdomain"
					}
					if q == dnsmessage.TypeA {
						return "nodata"
					}
					return "servfail"
				})
				rules.dns.localLookup = func(context.Context, string) ([]net.IPAddr, error) { return nil, errors.New("local unavailable") }
				got, err := rules.ResolveAll(context.Background(), "negative.example")
				if negative {
					if err != nil || len(got) != 1 {
						t.Fatalf("positive lost: %v %v", got, err)
					}
				} else if err == nil || errors.Is(err, errNotFound) {
					t.Fatalf("temporary failure became negative: %v", err)
				}
				recovered.Store(true)
				got, err = rules.ResolveAll(context.Background(), "negative.example")
				if err != nil || len(got) != 2 || calls.Load() != 4 {
					t.Fatalf("negative cache hid recovery: %v %v queries=%d", got, err, calls.Load())
				}
			})
		}
	}
}

func TestDoHNoFormatDowngradeOnSecondQuery(t *testing.T) {
	rules := familyDoH(t, "wire", func(*http.Request, dnsmessage.Type) string { return "address" })
	transport := rules.dns.dohClient.Transport.(*http.Transport)
	t.Cleanup(transport.CloseIdleConnections)
	var calls atomic.Int64
	rules.dns.dohClient.Transport = doHRoundTripper(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		msg, err := readDoHWireQuery(r)
		if err != nil {
			t.Errorf("unexpected format switch: %v", err)
			return nil, err
		}
		if msg.Questions[0].Type == dnsmessage.TypeAAAA {
			return nil, x509.UnknownAuthorityError{}
		}
		return transport.RoundTrip(r)
	})
	got, _, err := rules.dns.dohLookup(context.Background(), "trust.example")
	var cert x509.UnknownAuthorityError
	if !errors.As(err, &cert) || len(got) != 0 || calls.Load() != 2 {
		t.Fatalf("TLS failure masked: %v %v calls=%d", got, err, calls.Load())
	}
}

func TestDoHPartialWarningBounded(t *testing.T) {
	app, _, flush := captureLogs(t)
	rules := familyDoH(t, "wire", func(_ *http.Request, q dnsmessage.Type) string {
		if q == dnsmessage.TypeA {
			return "address"
		}
		return "servfail"
	})
	for i := range 10 {
		got, _, err := rules.dns.dohLookup(context.Background(), fmt.Sprintf("warn-%d.example", i))
		if err != nil || len(got) != 1 {
			t.Fatalf("partial=%v %v", got, err)
		}
	}
	flush()
	if n := strings.Count(app.String(), "DNS partial answer; not cached"); n != 1 {
		t.Fatalf("warnings=%d, want 1", n)
	}
}

func TestDoHCallerDeadlineRejectsPartial(t *testing.T) {
	for _, format := range []string{"wire", "json"} {
		t.Run(format, func(t *testing.T) {
			rules := familyDoH(t, format, func(_ *http.Request, q dnsmessage.Type) string {
				if q == dnsmessage.TypeA {
					return "address"
				}
				return "silent"
			})
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			got, _, err := rules.dns.dohLookup(ctx, "parent-deadline.example")
			if !errors.Is(err, context.DeadlineExceeded) || len(got) != 0 {
				t.Fatalf("expired caller received partial: %v %v", got, err)
			}
		})
	}
}
