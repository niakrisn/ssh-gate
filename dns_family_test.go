package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestDNSFamilyCombination(t *testing.T) {
	now := time.Now()
	positive := dnsFamilyResult{answer: dnsAnswer{addrs: []netip.Addr{netip.MustParseAddr("203.0.113.1")}, validUntil: now.Add(30 * time.Second)}}
	other := dnsFamilyResult{answer: dnsAnswer{addrs: []netip.Addr{netip.MustParseAddr("2001:db8::1")}, validUntil: now.Add(20 * time.Second)}}
	nodata := dnsFamilyResult{answer: dnsAnswer{validUntil: now.Add(10 * time.Second)}}
	nx := dnsFamilyResult{answer: nodata.answer, err: dnsRCodeError(dnsmessage.RCodeNameError)}
	servfail := dnsFamilyResult{err: dnsRCodeError(dnsmessage.RCodeServerFailure)}
	protocol := errors.New("invalid DNS question")
	for _, tc := range []struct {
		name  string
		a, b  dnsFamilyResult
		count int
		ttl   time.Duration
		err   error
	}{
		{"both", positive, other, 2, 20 * time.Second, nil},
		{"NODATA", positive, nodata, 1, 10 * time.Second, nil},
		{"NODATA without SOA", positive, dnsFamilyResult{answer: dnsAnswer{validUntil: now}}, 1, 0, nil},
		{"SERVFAIL", positive, servfail, 1, 0, nil},
		{"REFUSED", positive, dnsFamilyResult{err: dnsRCodeError(dnsmessage.RCodeRefused)}, 1, 0, nil},
		{"HTTP 429", positive, dnsFamilyResult{err: dohHTTPStatus(429)}, 1, 0, nil},
		{"HTTP 503", positive, dnsFamilyResult{err: dohHTTPStatus(503)}, 1, 0, nil},
		{"EOF", positive, dnsFamilyResult{err: io.EOF}, 1, 0, nil},
		{"reset", positive, dnsFamilyResult{err: fmt.Errorf("read: %w", syscall.ECONNRESET)}, 1, 0, nil},
		{"timeout", positive, dnsFamilyResult{err: context.DeadlineExceeded}, 1, 0, nil},
		{"contradictory NXDOMAIN", positive, nx, 1, 0, nil},
		{"both NODATA", nodata, nodata, 0, 10 * time.Second, errNotFound},
		{"NXDOMAIN", nx, nodata, 0, 10 * time.Second, errNotFound},
		{"no false negative", nodata, servfail, 0, 0, servfail.err},
		{"NXDOMAIN and failure", nx, servfail, 0, 0, servfail.err},
		{"protocol", positive, dnsFamilyResult{err: protocol}, 0, 0, protocol},
		{"HTTP 400", positive, dnsFamilyResult{err: dohHTTPStatus(400)}, 0, 0, dohHTTPStatus(400)},
		{"HTTP 403", positive, dnsFamilyResult{err: dohHTTPStatus(403)}, 0, 0, dohHTTPStatus(403)},
		{"TLS", positive, dnsFamilyResult{err: x509.UnknownAuthorityError{}}, 0, 0, x509.UnknownAuthorityError{}},
	} {
		for _, reverse := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/reverse=%t", tc.name, reverse), func(t *testing.T) {
				a, b := tc.a, tc.b
				if reverse {
					a, b = b, a
				}
				got, err := combineDNSFamilies(a, b, now)
				if !errors.Is(err, tc.err) || len(got.addrs) != tc.count {
					t.Fatalf("answer=%v err=%v want count=%d err=%v", got.addrs, err, tc.count, tc.err)
				}
				if tc.err == nil || errors.Is(tc.err, errNotFound) {
					if !got.validUntil.Equal(now.Add(tc.ttl)) {
						t.Fatalf("expiry=%v want %v", got.validUntil, now.Add(tc.ttl))
					}
				}
			})
		}
	}
}

func TestDoHJSONAddressFamily(t *testing.T) {
	for _, tc := range []struct {
		query dohQuery
		data  string
	}{
		{dohQueryA, "2001:db8::1"}, {dohQueryAAAA, "203.0.113.1"}, {dohQueryA, "invalid"},
	} {
		t.Run(tc.query.name+"/"+tc.data, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/dns-json")
				fmt.Fprintf(w, `{"Status":0,"Answer":[{"Type":%d,"Data":%q}]}`, tc.query.want, tc.data)
			}))
			defer srv.Close()
			got, err := dohJSONQuery(context.Background(), srv.Client(), strings.TrimPrefix(srv.URL, "https://"), "family.example", tc.query)
			if err == nil || len(got) != 0 {
				t.Fatalf("accepted wrong-family or invalid address: %v %v", got, err)
			}
		})
	}
}

func TestDoHFamilyRCodeType(t *testing.T) {
	for _, format := range []string{"wire", "json"} {
		for _, code := range []dnsmessage.RCode{dnsmessage.RCodeServerFailure, dnsmessage.RCodeNameError, dnsmessage.RCodeRefused} {
			t.Run(format+"/"+code.String(), func(t *testing.T) {
				srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if format == "json" {
						w.Header().Set("Content-Type", "application/dns-json")
						fmt.Fprintf(w, `{"Status":%d}`, code)
						return
					}
					msg, err := readDoHWireQuery(r)
					if err != nil {
						t.Error(err)
						return
					}
					msg.Response = true
					msg.RCode = code
					writeDoHWireResponse(t, w, msg)
				}))
				defer srv.Close()
				endpoint := strings.TrimPrefix(srv.URL, "https://")
				var err error
				if format == "wire" {
					q, _ := newDoHWireQuestion("rcode.example", dnsmessage.TypeA)
					_, err = dohWireQuery(context.Background(), srv.Client(), endpoint, q)
				} else {
					_, err = dohJSONQuery(context.Background(), srv.Client(), endpoint, "rcode.example", dohQueryA)
				}
				var rcode dnsRCodeError
				if !errors.As(err, &rcode) || dnsmessage.RCode(rcode) != code {
					t.Fatalf("rcode type lost: %T %v", err, err)
				}
			})
		}
	}
}

func TestDoHJSONMediaType(t *testing.T) {
	for _, media := range []string{"application/json", "application/dns-json", "text/html"} {
		t.Run(media, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", media)
				io.WriteString(w, `{"Status":0,"Answer":[{"Type":1,"Data":"203.0.113.1"}]}`)
			}))
			defer srv.Close()
			got, err := dohJSONQuery(context.Background(), srv.Client(), strings.TrimPrefix(srv.URL, "https://"), "mime.example", dohQueryA)
			if media == "text/html" {
				if err == nil {
					t.Fatalf("accepted invalid MIME: %v", got)
				}
			} else if err != nil || len(got) != 1 {
				t.Fatalf("valid JSON rejected: %v %v", got, err)
			}
		})
	}
}
