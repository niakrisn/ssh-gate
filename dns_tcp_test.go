package main

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func readTCPDNSQuery(c net.Conn) (dnsmessage.Message, error) {
	var msg dnsmessage.Message
	var size [2]byte
	if _, err := io.ReadFull(c, size[:]); err != nil {
		return msg, err
	}
	n := int(binary.BigEndian.Uint16(size[:]))
	if n < 12 {
		return msg, errors.New("short DNS query")
	}
	packet := make([]byte, n)
	if _, err := io.ReadFull(c, packet); err != nil {
		return msg, err
	}
	if err := msg.Unpack(packet); err != nil {
		return msg, err
	}
	if msg.Response || !msg.RecursionDesired || len(msg.Questions) != 1 || msg.Questions[0].Class != dnsmessage.ClassINET {
		return msg, errors.New("bad DNS question")
	}
	return msg, nil
}

func writeTCPDNSAnswer(c net.Conn, msg dnsmessage.Message) error {
	packet, err := msg.Pack()
	if err != nil {
		return err
	}
	_, err = c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(packet))), packet...))
	return err
}

func tcpDNSAnswer(msg dnsmessage.Message, ttl uint32) dnsmessage.Message {
	msg.Response = true
	q := msg.Questions[0]
	var body dnsmessage.ResourceBody = &dnsmessage.AResource{A: [4]byte{203, 0, 113, 1}}
	if q.Type == dnsmessage.TypeAAAA {
		body = &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2001:db8::1").As16()}
	}
	msg.Answers = []dnsmessage.Resource{doHRecord(q.Name.String(), ttl, body)}
	return msg
}

func tcpDNSPeer(t *testing.T, serve func(net.Conn)) (string, *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var opens atomic.Int64
	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			opens.Add(1)
			wg.Add(1)
			go func() { defer wg.Done(); defer c.Close(); c.SetDeadline(time.Now().Add(3 * time.Second)); serve(c) }()
		}
	}()
	t.Cleanup(func() { ln.Close(); <-done; wg.Wait() })
	return ln.Addr().String(), &opens
}

func TestDNSTCPPipelinesFamilies(t *testing.T) {
	addr, opens := tcpDNSPeer(t, func(c net.Conn) {
		first, err := readTCPDNSQuery(c)
		if err != nil {
			return
		}
		second, err := readTCPDNSQuery(c)
		if err != nil {
			return
		}
		if first.ID == second.ID || first.Questions[0].Type == second.Questions[0].Type {
			t.Error("A/AAAA do not have distinct IDs and types")
			return
		}
		// Replies deliberately arrive in the opposite order, on one channel.
		if err := writeTCPDNSAnswer(c, tcpDNSAnswer(second, 30)); err != nil {
			return
		}
		writeTCPDNSAnswer(c, tcpDNSAnswer(first, 30))
	})
	d := &channelDialer{}
	rules, local := tunnelServers(t, d, addr)
	defer rules.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	got, err := rules.ResolveAll(ctx, "pipeline.example")
	if err != nil || len(got) != 2 || opens.Load() != 1 || local.Load() != 0 {
		t.Fatalf("answer=%v err=%v channels=%d local=%d", got, err, opens.Load(), local.Load())
	}
}

func TestDNSTCPTTLZeroNotCached(t *testing.T) {
	var questions atomic.Int64
	addr, _ := tcpDNSPeer(t, func(c net.Conn) {
		for {
			msg, err := readTCPDNSQuery(c)
			if err != nil {
				return
			}
			questions.Add(1)
			if err := writeTCPDNSAnswer(c, tcpDNSAnswer(msg, 0)); err != nil {
				return
			}
		}
	})
	rules, local := tunnelServers(t, &channelDialer{}, addr)
	defer rules.Stop()
	for range 2 {
		got, err := rules.ResolveAll(context.Background(), "zero.example")
		if err != nil || len(got) != 2 {
			t.Fatalf("answer=%v err=%v", got, err)
		}
	}
	if questions.Load() != 4 || local.Load() != 0 {
		t.Fatalf("TTL=0 queries=%d local=%d", questions.Load(), local.Load())
	}
}

func TestDNSTCPFraming(t *testing.T) {
	for _, kind := range []string{"fragmented", "short", "ID", "question", "type", "class", "TC"} {
		t.Run(kind, func(t *testing.T) {
			addr, opens := tcpDNSPeer(t, func(c net.Conn) {
				first, err := readTCPDNSQuery(c)
				if err != nil {
					return
				}
				second, err := readTCPDNSQuery(c)
				if err != nil {
					return
				}
				if kind == "fragmented" {
					for _, msg := range []dnsmessage.Message{first, second} {
						answer := tcpDNSAnswer(msg, 30)
						packet, err := answer.Pack()
						if err != nil {
							t.Error(err)
							return
						}
						frame := append(binary.BigEndian.AppendUint16(nil, uint16(len(packet))), packet...)
						for _, b := range frame {
							if _, err := c.Write([]byte{b}); err != nil {
								return
							}
						}
					}
					return
				}
				// A valid positive must not hide a malformed second response.
				if err := writeTCPDNSAnswer(c, tcpDNSAnswer(first, 30)); err != nil {
					return
				}
				if kind == "short" {
					c.Write([]byte{0, 1, 0})
					return
				}
				answer := tcpDNSAnswer(second, 30)
				switch kind {
				case "ID":
					for answer.ID == first.ID || answer.ID == second.ID {
						answer.ID++
					}
				case "question":
					answer.Questions[0].Name = dnsmessage.MustNewName("other.example.")
				case "type":
					answer.Questions[0].Type = dnsmessage.TypeTXT
				case "class":
					answer.Questions[0].Class = dnsmessage.ClassCHAOS
				case "TC":
					answer.Truncated = true
				}
				writeTCPDNSAnswer(c, answer)
			})
			d := &channelDialer{}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			got, _, err := dnsServerLookup(d, addr)(ctx, "framing.example")
			if kind == "fragmented" {
				if err != nil || len(got) != 2 {
					t.Fatalf("fragmented=%v %v", got, err)
				}
			} else if err == nil || len(got) != 0 || temporaryDNSFailure(err) {
				t.Fatalf("malformed reply accepted: %v %v", got, err)
			}
			if opens.Load() != 1 || d.open.Load() != 0 {
				t.Fatalf("channels opened=%d active=%d", opens.Load(), d.open.Load())
			}
		})
	}
}

func TestDNSTCPServerClosesAfterFirstReply(t *testing.T) {
	for _, firstType := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		t.Run(firstType.String(), func(t *testing.T) {
			var connection atomic.Int64
			var a, aaaa atomic.Int64
			record := func(msg dnsmessage.Message) {
				if msg.Questions[0].Type == dnsmessage.TypeA {
					a.Add(1)
				} else {
					aaaa.Add(1)
				}
			}
			addr, opens := tcpDNSPeer(t, func(c net.Conn) {
				index := connection.Add(1)
				first, err := readTCPDNSQuery(c)
				if err != nil {
					return
				}
				record(first)
				if index == 1 {
					second, err := readTCPDNSQuery(c)
					if err != nil {
						return
					}
					record(second)
					if first.Questions[0].Type != firstType {
						first = second
					}
				} else if first.Questions[0].Type == firstType {
					t.Error("retried the completed family")
				}
				writeTCPDNSAnswer(c, tcpDNSAnswer(first, 30))
			})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			got, _, err := dnsServerLookup(&channelDialer{}, addr)(ctx, "retry.example")
			if err != nil || len(got) != 2 || opens.Load() != 2 || a.Load()+aaaa.Load() != 3 {
				t.Fatalf("retry=%v err=%v connections=%d A=%d AAAA=%d", got, err, opens.Load(), a.Load(), aaaa.Load())
			}
		})
	}
}

func TestDNSTCPAnswerTTL(t *testing.T) {
	for _, tc := range []struct {
		name          string
		negative, soa bool
		ttl, minimum  uint32
		want          time.Duration
	}{
		{"positive cap", false, false, 60, 0, 30 * time.Second},
		{"CNAME minimum", false, true, 3, 0, 3 * time.Second},
		{"negative cap", true, true, 50, 12, 10 * time.Second},
		{"SOA minimum", true, true, 50, 2, 2 * time.Second},
		{"negative without SOA", true, false, 50, 12, 0},
		{"negative zero", true, true, 50, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, _ := tcpDNSPeer(t, func(c net.Conn) {
				for {
					msg, err := readTCPDNSQuery(c)
					if err != nil {
						return
					}
					if tc.negative {
						msg.Response = true
						msg.RCode = dnsmessage.RCodeNameError
						if tc.soa {
							msg.Authorities = []dnsmessage.Resource{doHSOA("example.", tc.ttl, tc.minimum)}
						}
					} else {
						msg = tcpDNSAnswer(msg, 60)
						if tc.soa {
							name := msg.Questions[0].Name.String()
							msg.Answers[0].Header.Name = dnsmessage.MustNewName("alias.example.")
							msg.Answers = append(msg.Answers, doHRecord(name, tc.ttl, &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("alias.example.")}))
						}
					}
					if err := writeTCPDNSAnswer(c, msg); err != nil {
						return
					}
				}
			})
			rules, local := tunnelServers(t, &channelDialer{}, addr)
			defer rules.Stop()
			before := time.Now()
			got, err := rules.ResolveAll(context.Background(), "ttl.example")
			after := time.Now()
			if tc.negative {
				if !errors.Is(err, errNotFound) {
					t.Fatalf("negative=%v", err)
				}
			} else if err != nil || len(got) != 2 {
				t.Fatalf("positive=%v %v", got, err)
			}
			rules.dns.mu.Lock()
			entry, present := rules.dns.cache["ttl.example"]
			rules.dns.mu.Unlock()
			if tc.want == 0 {
				if present {
					t.Fatal("negative without TTL was cached")
				}
			} else if !present || entry.expires.Before(before.Add(tc.want)) || entry.expires.After(after.Add(tc.want)) {
				t.Fatalf("expiry=%v want %v from receipt, present=%t", entry.expires, tc.want, present)
			}
			if local.Load() != 0 {
				t.Fatal("authoritative result used local fallback")
			}
		})
	}
}

func TestDNSTCPCancelOverSSH(t *testing.T) {
	addr, _ := tcpDNSPeer(t, func(c net.Conn) { io.Copy(io.Discard, c) })
	f := startForwardingSSH(t, addr)
	t.Cleanup(f.d.stop)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, _, err := dnsServerLookup(f.d, addr)(ctx, "silent.example")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error=%v", err)
	}
	select {
	case <-f.closed:
	case <-time.After(time.Second):
		t.Fatal("DNS retained its SSH channel")
	}
	if f.active.Load() != 0 {
		t.Fatalf("active channels=%d", f.active.Load())
	}
}
