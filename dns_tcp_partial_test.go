package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func tcpFamilies(t *testing.T, reverse bool, reply func(dnsmessage.Type) string) string {
	t.Helper()
	addr, _ := tcpDNSPeer(t, func(c net.Conn) {
		a, err := readTCPDNSQuery(c)
		if err != nil {
			return
		}
		b, err := readTCPDNSQuery(c)
		if err != nil {
			return
		}
		if reverse {
			a, b = b, a
		}
		silent := false
		for _, query := range []dnsmessage.Message{a, b} {
			kind := reply(query.Questions[0].Type)
			msg := query
			msg.Response = true
			msg.Authorities = []dnsmessage.Resource{doHSOA("example.", 10, 10)}
			switch kind {
			case "address":
				msg = tcpDNSAnswer(msg, 30)
			case "nodata":
			case "servfail":
				msg.RCode = dnsmessage.RCodeServerFailure
			case "refused":
				msg.RCode = dnsmessage.RCodeRefused
			case "nxdomain":
				msg.RCode = dnsmessage.RCodeNameError
			case "formerr":
				msg.RCode = dnsmessage.RCodeFormatError
			case "broken":
				msg.Truncated = true
			case "silent":
				silent = true
				continue
			default:
				t.Errorf("unknown result %q", kind)
				return
			}
			if err := writeTCPDNSAnswer(c, msg); err != nil {
				return
			}
		}
		if silent {
			io.Copy(io.Discard, c)
		}
	})
	return addr
}

func TestDNSPartialFamilyTCP(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		for _, tc := range []struct {
			a, b     string
			count    int
			negative bool
		}{
			{"address", "address", 2, false}, {"address", "nodata", 1, false}, {"nodata", "address", 1, false},
			{"address", "servfail", 1, false}, {"servfail", "address", 1, false},
			{"address", "refused", 1, false}, {"refused", "address", 1, false},
			{"address", "nxdomain", 1, false}, {"nxdomain", "address", 1, false},
			{"address", "silent", 1, false}, {"silent", "address", 1, false},
			{"nodata", "nodata", 0, true}, {"nxdomain", "nodata", 0, true},
			{"nodata", "servfail", 0, false}, {"nxdomain", "servfail", 0, false},
			{"address", "broken", 0, false}, {"formerr", "silent", 0, false},
		} {
			t.Run(fmt.Sprintf("%s/%s/reverse=%t", tc.a, tc.b, reverse), func(t *testing.T) {
				addr := tcpFamilies(t, reverse, func(q dnsmessage.Type) string {
					if q == dnsmessage.TypeA {
						return tc.a
					}
					return tc.b
				})
				rules, local := tunnelServers(t, &channelDialer{}, addr)
				defer rules.Stop()
				rules.dns.localLookup = func(context.Context, string) ([]net.IPAddr, error) {
					local.Add(1)
					return nil, errors.New("local unavailable")
				}
				ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
				defer cancel()
				got, err := rules.ResolveAll(ctx, "partial.example")
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

func TestDNSPartialNotCachedTCP(t *testing.T) {
	for _, kind := range []string{"servfail", "nxdomain", "silent"} {
		t.Run(kind, func(t *testing.T) {
			var recovered atomic.Bool
			var calls atomic.Int64
			addr := tcpFamilies(t, true, func(q dnsmessage.Type) string {
				calls.Add(1)
				if q == dnsmessage.TypeAAAA && !recovered.Load() {
					return kind
				}
				return "address"
			})
			rules, local := tunnelServers(t, &channelDialer{}, addr)
			defer rules.Stop()
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

func TestDNSNoFalseNegativeCacheTCP(t *testing.T) {
	var recovered atomic.Bool
	var calls atomic.Int64
	addr := tcpFamilies(t, false, func(q dnsmessage.Type) string {
		calls.Add(1)
		if recovered.Load() {
			return "address"
		}
		if q == dnsmessage.TypeA {
			return "nodata"
		}
		return "servfail"
	})
	rules, local := tunnelServers(t, &channelDialer{}, addr)
	defer rules.Stop()
	if _, err := rules.ResolveAll(context.Background(), "negative.example"); err != nil || local.Load() != 1 {
		t.Fatalf("failed lookup did not fall back: %v", err)
	}
	recovered.Store(true)
	got, err := rules.ResolveAll(context.Background(), "negative.example")
	if err != nil || len(got) != 2 || calls.Load() != 4 || local.Load() != 1 {
		t.Fatalf("negative cache hid recovery: %v %v queries=%d", got, err, calls.Load())
	}
}

func TestDNSTCPPartialAfterRetryEOF(t *testing.T) {
	var connections atomic.Int64
	addr, _ := tcpDNSPeer(t, func(c net.Conn) {
		n := connections.Add(1)
		msg, err := readTCPDNSQuery(c)
		if err != nil {
			return
		}
		if n > 1 {
			return
		}
		if _, err := readTCPDNSQuery(c); err != nil {
			return
		}
		writeTCPDNSAnswer(c, tcpDNSAnswer(msg, 30))
	})
	d := &channelDialer{}
	got, expiry, err := dnsServerLookup(d, addr)(context.Background(), "eof.example")
	if err != nil || len(got) != 1 || expiry.After(time.Now()) || connections.Load() != 2 || d.open.Load() != 0 {
		t.Fatalf("partial=%v expiry=%v err=%v connections=%d active=%d", got, expiry, err, connections.Load(), d.open.Load())
	}
}

func TestDNSTCPCallerDeadlineRejectsPartial(t *testing.T) {
	addr := tcpFamilies(t, false, func(q dnsmessage.Type) string {
		if q == dnsmessage.TypeA {
			return "address"
		}
		return "silent"
	})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	got, _, err := dnsServerLookup(&channelDialer{}, addr)(ctx, "deadline.example")
	if !errors.Is(err, context.DeadlineExceeded) || len(got) != 0 {
		t.Fatalf("expired caller received partial: %v %v", got, err)
	}
}
