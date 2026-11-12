package main

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func readDoHWireQuery(r *http.Request) (dnsmessage.Message, error) {
	var msg dnsmessage.Message
	query := r.URL.Query()
	if r.Method != http.MethodGet || r.Header.Get("Accept") != "application/dns-message" ||
		len(query) != 1 || len(query["dns"]) != 1 {
		return msg, errors.New("expected a binary DoH GET")
	}
	packet, err := base64.RawURLEncoding.DecodeString(query.Get("dns"))
	if err != nil {
		return msg, err
	}
	if err := msg.Unpack(packet); err != nil {
		return msg, err
	}
	if msg.ID != 0 || msg.Response || !msg.RecursionDesired || len(msg.Questions) != 1 ||
		msg.Questions[0].Class != dnsmessage.ClassINET {
		return msg, errors.New("unexpected DNS question")
	}
	return msg, nil
}

func doHRecord(name string, ttl uint32, body dnsmessage.ResourceBody) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name: dnsmessage.MustNewName(name), Class: dnsmessage.ClassINET, TTL: ttl,
		},
		Body: body,
	}
}

func doHSOA(zone string, ttl, minimum uint32) dnsmessage.Resource {
	return doHRecord(zone, ttl, &dnsmessage.SOAResource{
		NS: dnsmessage.MustNewName("ns.example."), MBox: dnsmessage.MustNewName("hostmaster.example."),
		MinTTL: minimum,
	})
}

func writeDoHWireResponse(t *testing.T, w http.ResponseWriter, msg dnsmessage.Message) {
	t.Helper()
	packet, err := msg.Pack()
	if err != nil {
		t.Errorf("pack DNS response: %v", err)
		http.Error(w, "invalid test response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/dns-message")
	w.Write(packet)
}

func TestDoHWireQuery(t *testing.T) {
	const name = "xn--bcher-kva.example."
	const alias = "target.example."
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		msg, err := readDoHWireQuery(r)
		if err != nil {
			t.Error(err)
			http.Error(w, "invalid DNS question", http.StatusBadRequest)
			return
		}
		q := msg.Questions[0]
		if r.URL.Path != "/dns-query" || q.Name.String() != name {
			t.Errorf("path = %s, question = %s", r.URL.Path, q.Name)
		}
		msg.Response = true
		msg.Answers = []dnsmessage.Resource{
			doHRecord(name, 20, &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(alias)}),
			doHRecord("unrelated.example.", 1, &dnsmessage.AResource{A: [4]byte{192, 0, 2, 2}}),
		}
		switch q.Type {
		case dnsmessage.TypeA:
			msg.Answers = append(msg.Answers, doHRecord(alias, 30, &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}}))
		case dnsmessage.TypeAAAA:
			addr := netip.MustParseAddr("2001:db8::1")
			msg.Answers = append(msg.Answers, doHRecord(alias, 30, &dnsmessage.AAAAResource{AAAA: addr.As16()}))
		default:
			t.Errorf("unexpected question type %v", q.Type)
		}
		writeDoHWireResponse(t, w, msg)
	}))
	defer srv.Close()

	for _, tc := range []struct {
		qtype dnsmessage.Type
		want  string
	}{
		{dnsmessage.TypeA, "192.0.2.1"},
		{dnsmessage.TypeAAAA, "2001:db8::1"},
	} {
		t.Run(tc.qtype.String(), func(t *testing.T) {
			q, err := newDoHWireQuestion("bücher.example.", tc.qtype)
			if err != nil {
				t.Fatal(err)
			}
			got, err := dohWireQuery(context.Background(), srv.Client(), srv.Listener.Addr().String(), q)
			if err != nil || !slices.Equal(got.addrs, []netip.Addr{netip.MustParseAddr(tc.want)}) {
				t.Fatalf("response = (%v, %v), want %s", got.addrs, err, tc.want)
			}
		})
	}
}

func TestDoHWireResponseErrors(t *testing.T) {
	q, err := newDoHWireQuestion("query.example", dnsmessage.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(*dnsmessage.Message)
		body []byte
		mime string
		code int
		want string
	}{
		{name: "http error", code: 503, want: "HTTP status 503"},
		{name: "mime mismatch", mime: "application/dns-json", want: "expected application/dns-message"},
		{name: "oversize", body: make([]byte, 65536), want: "exceeds 65535"},
		{name: "malformed", body: []byte{0, 1}, want: "invalid DNS response"},
		{name: "truncated", edit: func(msg *dnsmessage.Message) { msg.Truncated = true }, want: "invalid DNS response header"},
		{name: "id mismatch", edit: func(msg *dnsmessage.Message) { msg.ID = 1 }, want: "invalid DNS response header"},
		{name: "question mismatch", edit: func(msg *dnsmessage.Message) { msg.Questions[0].Type = dnsmessage.TypeAAAA }, want: "question mismatch"},
		{name: "servfail", edit: func(msg *dnsmessage.Message) { msg.RCode = dnsmessage.RCodeServerFailure }, want: dnsmessage.RCodeServerFailure.String()},
		{name: "cname loop", edit: func(msg *dnsmessage.Message) {
			msg.Answers = []dnsmessage.Resource{doHRecord("query.example.", 10, &dnsmessage.CNAMEResource{CNAME: msg.Questions[0].Name})}
		}, want: "CNAME loop"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				msg, err := readDoHWireQuery(r)
				if err != nil {
					t.Error(err)
					http.Error(w, "invalid DNS question", http.StatusBadRequest)
					return
				}
				if tc.code != 0 {
					w.WriteHeader(tc.code)
					return
				}
				if tc.mime != "" {
					w.Header().Set("Content-Type", tc.mime)
					return
				}
				if tc.body != nil {
					w.Header().Set("Content-Type", dohWireMediaType)
					w.Write(tc.body)
					return
				}
				msg.Response = true
				tc.edit(&msg)
				writeDoHWireResponse(t, w, msg)
			}))
			defer srv.Close()
			_, err := dohWireQuery(context.Background(), srv.Client(), srv.Listener.Addr().String(), q)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %s", err, tc.want)
			}
		})
	}
}

func TestDoHWireFreshness(t *testing.T) {
	q, err := newDoHWireQuestion("query.example", dnsmessage.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	const name = "query.example."
	addr := &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}}
	receivedAt := time.Unix(1_700_000_000, 0)
	for _, tc := range []struct {
		name    string
		age     string
		answers []dnsmessage.Resource
		soa     []dnsmessage.Resource
		nx      bool
		want    time.Duration
	}{
		{name: "age", age: "8", answers: []dnsmessage.Resource{doHRecord(name, 10, addr)}, want: 2 * time.Second},
		{name: "expired", age: "10", answers: []dnsmessage.Resource{doHRecord(name, 10, addr)}},
		{name: "invalid age", age: "-1", answers: []dnsmessage.Resource{doHRecord(name, 10, addr)}},
		{name: "cname limit", answers: []dnsmessage.Resource{
			doHRecord(name, 3, &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("alias.example.")}),
			doHRecord("alias.example.", 10, addr),
		}, want: 3 * time.Second},
		{name: "nxdomain soa ttl", nx: true, soa: []dnsmessage.Resource{doHSOA("example.", 6, 10)}, age: "1", want: 5 * time.Second},
		{name: "nodata soa minimum", soa: []dnsmessage.Resource{doHSOA("example.", 10, 4)}, age: "1", want: 3 * time.Second},
		{name: "nxdomain without soa", nx: true},
		{name: "unrelated soa", soa: []dnsmessage.Resource{doHSOA("other.example.", 6, 10)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg := dnsmessage.Message{
				Header: dnsmessage.Header{Response: true}, Questions: []dnsmessage.Question{q.question},
				Answers: tc.answers, Authorities: tc.soa,
			}
			if tc.nx {
				msg.RCode = dnsmessage.RCodeNameError
			}
			packet, err := msg.Pack()
			if err != nil {
				t.Fatal(err)
			}
			var age []string
			if tc.age != "" {
				age = []string{tc.age}
			}
			got, err := decodeDoHWireAnswer(packet, q.question, receivedAt, age)
			if tc.nx && !errors.Is(err, errNotFound) || !tc.nx && err != nil {
				t.Fatalf("error = %v, NXDOMAIN = %t", err, tc.nx)
			}
			if got.validUntil.Sub(receivedAt) != tc.want {
				t.Fatalf("remaining TTL = %v, want %v", got.validUntil.Sub(receivedAt), tc.want)
			}
		})
	}
}

func TestDoHRedirectOrigin(t *testing.T) {
	initial := httptest.NewRequest(http.MethodGet, "https://dns.example/dns-query", nil)
	for _, tc := range []struct {
		target string
		allow  bool
	}{
		{"https://DNS.example:443/answer", true},
		{"https://dns.example:444/answer", false},
		{"https://other.example/answer", false},
		{"http://dns.example:443/answer", false},
	} {
		t.Run(tc.target, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.target, nil)
			if err := checkDoHRedirect(req, []*http.Request{initial}); (err == nil) != tc.allow {
				t.Fatalf("redirect %s: %v, want allowed=%t", tc.target, err, tc.allow)
			}
		})
	}
}

func TestDoHCacheExpiry(t *testing.T) {
	for _, tc := range []struct {
		name     string
		lifetime time.Duration
		negative bool
		local    bool
		fixedTTL time.Duration
	}{
		{name: "positive bounded by DNS", lifetime: 2 * time.Second},
		{name: "positive capped by cache", lifetime: time.Minute, fixedTTL: dnsCacheTTL},
		{name: "positive expired", lifetime: -time.Second},
		{name: "negative bounded by DNS", lifetime: 2 * time.Second, negative: true},
		{name: "negative capped by cache", lifetime: time.Minute, negative: true, fixedTTL: dnsNegativeTTL},
		{name: "negative expired", lifetime: -time.Second, negative: true},
		{name: "local answer uses its own TTL", lifetime: -time.Second, negative: true, local: true, fixedTTL: dnsCacheTTL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const name = "query.example"
			rules, err := NewRuleEngine("")
			if err != nil {
				t.Fatal(err)
			}
			cache := rules.dns
			cache.localOnNXDomain = tc.local
			cache.localLookup = func(context.Context, string) ([]net.IPAddr, error) {
				if !tc.local {
					t.Error("unexpected local lookup")
				}
				return []net.IPAddr{{IP: net.IPv4(192, 0, 2, 2)}}, nil
			}
			deadline := time.Now().Add(tc.lifetime)
			cache.tunnel = []*upstream{{
				name: "dns.example",
				lookup: func(context.Context, string) ([]netip.Addr, time.Time, error) {
					if tc.negative {
						return nil, deadline, errNotFound
					}
					return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, deadline, nil
				},
			}}
			before := time.Now()
			addrs, localDirect, err := cache.resolveTunnel(context.Background(), name)
			after := time.Now()
			wantNegative := tc.negative && !tc.local
			if wantNegative {
				if !errors.Is(err, errNotFound) {
					t.Fatalf("resolve error = %v, want not found", err)
				}
			} else if err != nil || len(addrs) != 1 || localDirect != tc.local {
				t.Fatalf("resolve = (%v, %t, %v)", addrs, localDirect, err)
			}
			entry, ok := cache.cache[name]
			if tc.lifetime < 0 && !tc.local {
				if ok {
					t.Fatal("expired answer cached")
				}
				return
			}
			if !ok || entry.neg != wantNegative || entry.localDirect != tc.local {
				t.Fatalf("cache entry = %+v, present=%t", entry, ok)
			}
			if tc.fixedTTL == 0 {
				if !entry.expires.Equal(deadline) {
					t.Fatalf("expires = %v, want %v", entry.expires, deadline)
				}
			} else if entry.expires.Before(before.Add(tc.fixedTTL)) || entry.expires.After(after.Add(tc.fixedTTL)) {
				t.Fatalf("expires = %v, want fixed TTL %v", entry.expires, tc.fixedTTL)
			}
		})
	}
}

func TestDoHFormatSelection(t *testing.T) {
	const host = "format.example"
	const jsonA = `{"Status":0,"Answer":[{"Type":1,"Data":"192.0.2.1"}]}`
	const jsonAAAA = `{"Status":0,"Answer":[{"Type":28,"Data":"2001:db8::1"}]}`
	type step struct {
		format   string
		qtype    string
		status   int
		rcode    dnsmessage.RCode
		json     string
		body     string
		redirect bool
	}
	wireA := step{format: "wire", qtype: "A"}
	wireAAAA := step{format: "wire", qtype: "AAAA"}
	rejectWire := step{format: "wire", qtype: "A", status: 400}
	jsonStepA := step{format: "json", qtype: "A", json: jsonA}
	jsonStepAAAA := step{format: "json", qtype: "AAAA", json: jsonAAAA}
	for _, tc := range []struct {
		name   string
		steps  []step
		nx     bool
		failed string
	}{
		{name: "standard", steps: []step{wireA, wireAAAA}},
		{name: "retry 400", steps: []step{rejectWire, jsonStepA, jsonStepAAAA}},
		{name: "retry 406", steps: []step{{format: "wire", qtype: "A", status: 406}, jsonStepA, jsonStepAAAA}},
		{name: "retry 415", steps: []step{{format: "wire", qtype: "A", status: 415}, jsonStepA, jsonStepAAAA}},
		{name: "nxdomain", steps: []step{{format: "wire", qtype: "A", rcode: dnsmessage.RCodeNameError}}, nx: true},
		{name: "servfail", steps: []step{{format: "wire", qtype: "A", rcode: dnsmessage.RCodeServerFailure}, {format: "wire", qtype: "AAAA", rcode: dnsmessage.RCodeServerFailure}}, failed: dnsmessage.RCodeServerFailure.String()},
		{name: "refused", steps: []step{{format: "wire", qtype: "A", rcode: dnsmessage.RCodeRefused}, {format: "wire", qtype: "AAAA", rcode: dnsmessage.RCodeRefused}}, failed: dnsmessage.RCodeRefused.String()},
		{name: "rate limit", steps: []step{{format: "wire", qtype: "A", status: 429}, {format: "wire", qtype: "AAAA", status: 429}}, failed: "HTTP status 429"},
		{name: "http error", steps: []step{{format: "wire", qtype: "A", status: 503}, {format: "wire", qtype: "AAAA", status: 503}}, failed: "HTTP status 503"},
		{name: "bad DNS body", steps: []step{{format: "wire", qtype: "A", body: "broken"}}, failed: "invalid DNS response"},
		{name: "blocked redirect", steps: []step{{format: "wire", qtype: "A", redirect: true}}, failed: "redirect must use HTTPS"},
		{name: "JSON response to wire query", steps: []step{{format: "wire", qtype: "A", json: jsonA}}, failed: "expected application/dns-message"},
		{name: "AAAA rejects wire", steps: []step{wireA, {format: "wire", qtype: "AAAA", status: 400}}, failed: "HTTP status 400"},
		{name: "JSON HTTP error is not nxdomain", steps: []step{rejectWire, {format: "json", qtype: "A", status: 502, json: `{"Status":3}`}, {format: "json", qtype: "AAAA", status: 502, json: `{"Status":3}`}}, failed: "HTTP status 400, JSON retry: doh: HTTP status 502"},
		{name: "JSON status missing", steps: []step{rejectWire, {format: "json", qtype: "A", json: "{}"}}, failed: "HTTP status 400, JSON retry:"},
		{name: "JSON nxdomain", steps: []step{rejectWire, {format: "json", qtype: "A", json: `{"Status":3}`}}, nx: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int64
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				i := calls.Add(1) - 1
				if i >= int64(len(tc.steps)) {
					t.Errorf("unexpected request %s", r.URL)
					http.Error(w, "unexpected request", http.StatusInternalServerError)
					return
				}
				expect := tc.steps[i]
				var msg dnsmessage.Message
				if expect.format == "wire" {
					var err error
					msg, err = readDoHWireQuery(r)
					if err != nil {
						t.Errorf("request %d: %v", i, err)
						http.Error(w, "invalid test request", http.StatusInternalServerError)
						return
					}
					wantType := dnsmessage.TypeA
					if expect.qtype == "AAAA" {
						wantType = dnsmessage.TypeAAAA
					}
					if q := msg.Questions[0]; q.Type != wantType || q.Name.String() != host+"." {
						t.Errorf("request %d: unexpected question %+v", i, q)
					}
				} else if r.Method != http.MethodGet || r.Header.Get("Accept") != "application/dns-json" ||
					r.URL.Query().Get("name") != host || r.URL.Query().Get("type") != expect.qtype || r.URL.Query().Has("dns") {
					t.Errorf("request %d: expected JSON %s, got %s", i, expect.qtype, r.URL)
				}
				if r.URL.Path != "/dns-query" {
					t.Errorf("unexpected path %s", r.URL.Path)
				}
				switch {
				case expect.redirect:
					http.Redirect(w, r, "http://"+r.Host+"/blocked", http.StatusFound)
				case expect.json != "":
					w.Header().Set("Content-Type", "application/dns-json")
					if expect.status != 0 {
						w.WriteHeader(expect.status)
					}
					io.WriteString(w, expect.json)
				case expect.status != 0:
					w.WriteHeader(expect.status)
				case expect.body != "":
					w.Header().Set("Content-Type", dohWireMediaType)
					io.WriteString(w, expect.body)
				default:
					msg.Response = true
					msg.RCode = expect.rcode
					if msg.RCode == dnsmessage.RCodeSuccess {
						var body dnsmessage.ResourceBody = &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}}
						if expect.qtype == "AAAA" {
							body = &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2001:db8::1").As16()}
						}
						msg.Answers = []dnsmessage.Resource{doHRecord(host+".", 60, body)}
					}
					writeDoHWireResponse(t, w, msg)
				}
			}))
			defer srv.Close()

			rules, err := NewRuleEngine("")
			if err != nil {
				t.Fatal(err)
			}
			d, b := setBootstrap(t, srv)
			rules.SetDOH(b.addr, d)
			rules.dns.dohClient.Transport.(*http.Transport).TLSClientConfig = b.tls
			var localCalls int
			local := netip.MustParseAddr("192.0.2.9")
			rules.dns.localLookup = func(context.Context, string) ([]net.IPAddr, error) {
				localCalls++
				return []net.IPAddr{{IP: local.AsSlice()}}, nil
			}

			got, err := rules.ResolveAll(context.Background(), host)
			status := rules.DNSStatus()
			server := status.Servers[0]
			switch {
			case tc.nx:
				if !errors.Is(err, errNotFound) || len(got) != 0 || localCalls != 0 || server.OK != 1 || server.Fail != 0 {
					t.Fatalf("NXDOMAIN = (%v, %v), local calls=%d, status=%+v", got, err, localCalls, status)
				}
			case tc.failed != "":
				if err != nil || !slices.Equal(got, []netip.Addr{local}) || localCalls != 1 ||
					server.OK != 0 || server.Fail != 1 || !strings.Contains(server.Error, tc.failed) {
					t.Fatalf("fallback = (%v, %v), local calls=%d, status=%+v, want error %q", got, err, localCalls, status, tc.failed)
				}
			default:
				want := []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")}
				if err != nil || !slices.Equal(got, want) || localCalls != 0 || server.OK != 1 || server.Fail != 0 {
					t.Fatalf("DoH = (%v, %v), local calls=%d, status=%+v", got, err, localCalls, status)
				}
			}
			if got := calls.Load(); got != int64(len(tc.steps)) {
				t.Fatalf("DoH requests = %d, want %d", got, len(tc.steps))
			}
		})
	}
}

type doHRoundTripper func(*http.Request) (*http.Response, error)

func (f doHRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDoHFormatSelectionDeadline(t *testing.T) {
	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatal(err)
	}
	rules.SetDOH("dns.example", testDialer{})
	cache := rules.dns
	var calls, localCalls int
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	overall, _ := ctx.Deadline()
	cache.dohClient.Transport = doHRoundTripper(func(r *http.Request) (*http.Response, error) {
		calls++
		deadline, ok := r.Context().Deadline()
		switch calls {
		case 1:
			if !ok || deadline.After(time.Now().Add(time.Until(overall)/2)) {
				t.Errorf("first A consumed more than half the remaining budget: %v", deadline)
			}
			if !ok || r.Header.Get("Accept") != dohWireMediaType {
				t.Errorf("first request: deadline present=%t, Accept=%s", ok, r.Header.Get("Accept"))
			}
			return &http.Response{StatusCode: 406, Body: io.NopCloser(strings.NewReader(""))}, nil
		case 2:
			if !ok || deadline.After(time.Now().Add(time.Until(overall)/2)) || r.URL.Query().Get("type") != "A" ||
				r.Header.Get("Accept") != "application/dns-json" {
				t.Errorf("unexpected retry: deadline=%v (overall %v), request=%v", deadline, overall, r.URL)
				return nil, errors.New("unexpected retry")
			}
			<-r.Context().Done()
			return nil, r.Context().Err()
		case 3:
			if !ok || !deadline.Equal(overall) || r.URL.Query().Get("type") != "AAAA" {
				t.Errorf("AAAA renewed deadline or changed format: %v %v", deadline, r.URL)
			}
			<-r.Context().Done()
			return nil, r.Context().Err()
		default:
			t.Error("unexpected request after deadline")
			return nil, errors.New("unexpected request")
		}
	})
	cache.localLookup = func(context.Context, string) ([]net.IPAddr, error) {
		localCalls++
		return []net.IPAddr{{IP: net.IPv4(192, 0, 2, 9)}}, nil
	}
	result, err := cache.lookup(ctx, "deadline.example")
	server := rules.DNSStatus().Servers[0]
	if err != nil || len(result.addrs) != 1 || result.authoritative || calls != 3 || localCalls != 1 ||
		server.Fail != 1 || !strings.Contains(server.Error, context.DeadlineExceeded.Error()) {
		t.Fatalf("lookup = (%+v, %v), requests=%d, local calls=%d, status=%+v", result, err, calls, localCalls, server)
	}
}

func TestDoHFormatSelectionInvalidQuestion(t *testing.T) {
	rules, err := NewRuleEngine("")
	if err != nil {
		t.Fatal(err)
	}
	rules.SetDOH("dns.example", testDialer{})
	rules.dns.dohClient.Transport = doHRoundTripper(func(r *http.Request) (*http.Response, error) {
		t.Errorf("invalid name reached DoH: %s", r.URL)
		return nil, errors.New("unexpected request")
	})
	rules.dns.localLookup = func(context.Context, string) ([]net.IPAddr, error) {
		return nil, errNotFound
	}
	_, _ = rules.ResolveAll(context.Background(), "bad..example")
	server := rules.DNSStatus().Servers[0]
	if server.Paused || server.Fail != 1 || !strings.Contains(server.Error, "invalid DNS question") {
		t.Fatalf("invalid question status = %+v", server)
	}
}

func TestDoHCacheExpiryWire(t *testing.T) {
	for _, tc := range []struct {
		name    string
		ageA    string
		ttlAAAA uint32
		nodata  bool
		want    time.Duration
	}{
		{name: "A expires first", ageA: "8", ttlAAAA: 20, want: 2 * time.Second},
		{name: "AAAA NODATA expires first", ttlAAAA: 2, nodata: true, want: 2 * time.Second},
		{name: "A is expired", ageA: "10", ttlAAAA: 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const host = "expiry.example"
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				msg, err := readDoHWireQuery(r)
				if err != nil {
					t.Error(err)
					http.Error(w, "invalid test request", http.StatusInternalServerError)
					return
				}
				name := msg.Questions[0].Name.String()
				msg.Response = true
				switch msg.Questions[0].Type {
				case dnsmessage.TypeA:
					if tc.ageA != "" {
						w.Header().Set("Age", tc.ageA)
					}
					msg.Answers = []dnsmessage.Resource{doHRecord(name, 10, &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}})}
				case dnsmessage.TypeAAAA:
					if tc.nodata {
						msg.Authorities = []dnsmessage.Resource{doHSOA("example.", 60, tc.ttlAAAA)}
					} else {
						addr := netip.MustParseAddr("2001:db8::1")
						msg.Answers = []dnsmessage.Resource{doHRecord(name, tc.ttlAAAA, &dnsmessage.AAAAResource{AAAA: addr.As16()})}
					}
				default:
					t.Error("unexpected question type")
				}
				writeDoHWireResponse(t, w, msg)
			}))
			defer srv.Close()
			rules, err := NewRuleEngine("")
			if err != nil {
				t.Fatal(err)
			}
			d, b := setBootstrap(t, srv)
			rules.SetDOH(b.addr, d)
			rules.dns.dohClient.Transport.(*http.Transport).TLSClientConfig = b.tls
			rules.dns.localLookup = func(context.Context, string) ([]net.IPAddr, error) {
				t.Error("unexpected local lookup")
				return nil, errNotFound
			}

			before := time.Now()
			addrs, err := rules.ResolveAll(context.Background(), host)
			after := time.Now()
			if err != nil || len(addrs) == 0 || addrs[0] != netip.MustParseAddr("192.0.2.1") {
				t.Fatalf("ResolveAll = (%v, %v)", addrs, err)
			}
			entry, ok := rules.dns.cache[host]
			if tc.want == 0 {
				if ok {
					t.Fatal("expired DNS answer was cached")
				}
				return
			}
			if !ok || entry.expires.Before(before.Add(tc.want)) || entry.expires.After(after.Add(tc.want)) {
				t.Fatalf("cached expiry = %v, present=%t, want %v from receipt", entry.expires, ok, tc.want)
			}
		})
	}
}
