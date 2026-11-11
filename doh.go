package main

import (
	"cmp"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/idna"
)

const (
	dohWireMediaType = "application/dns-message"
	dohWireMaxBody   = 65535
)

func checkDoHRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("doh: stopped after 10 redirects")
	}
	origin := via[0].URL
	if req.URL.Scheme != "https" || !strings.EqualFold(origin.Hostname(), req.URL.Hostname()) ||
		cmp.Or(origin.Port(), "443") != cmp.Or(req.URL.Port(), "443") {
		return errors.New("doh: redirect must use HTTPS on the original host and port")
	}
	return nil
}

// dohHTTPStatus is returned only for a received non-2xx HTTP response.
type dohHTTPStatus int

func (s dohHTTPStatus) Error() string {
	return fmt.Sprintf("doh: HTTP status %d", int(s))
}

type dohWireQuestion struct {
	question dnsmessage.Question
	encoded  string
}

func newDoHWireQuestion(host string, qtype dnsmessage.Type) (dohWireQuestion, error) {
	if strings.IndexFunc(host, func(r rune) bool { return r > 127 }) >= 0 {
		ascii, err := idna.Lookup.ToASCII(host)
		if err != nil {
			return dohWireQuestion{}, fmt.Errorf("doh: invalid DNS name: %w", err)
		}
		host = ascii
	}
	name, err := dnsmessage.NewName(strings.TrimSuffix(host, ".") + ".")
	if err != nil {
		return dohWireQuestion{}, fmt.Errorf("doh: invalid DNS name: %w", err)
	}
	question := dnsmessage.Question{Name: name, Type: qtype, Class: dnsmessage.ClassINET}
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{RecursionDesired: true},
		Questions: []dnsmessage.Question{question},
	}
	packet, err := msg.Pack()
	if err != nil {
		return dohWireQuestion{}, fmt.Errorf("doh: invalid DNS question: %w", err)
	}
	return dohWireQuestion{question: question, encoded: base64.RawURLEncoding.EncodeToString(packet)}, nil
}

type dohWireAnswer struct {
	addrs      []netip.Addr
	validUntil time.Time
}

func dohWireQuery(ctx context.Context, client *http.Client, endpoint string, q dohWireQuestion) (dohWireAnswer, error) {
	u := url.URL{Scheme: "https", Host: endpoint, Path: "/dns-query", RawQuery: "dns=" + q.encoded}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return dohWireAnswer{}, err
	}
	req.Header.Set("Accept", dohWireMediaType)
	resp, err := client.Do(req)
	if err != nil {
		return dohWireAnswer{}, err
	}
	receivedAt := time.Now()
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return dohWireAnswer{}, dohHTTPStatus(resp.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType != dohWireMediaType {
		return dohWireAnswer{}, errors.New("doh: expected application/dns-message")
	}
	packet, err := io.ReadAll(io.LimitReader(resp.Body, dohWireMaxBody+1))
	if err != nil {
		return dohWireAnswer{}, err
	}
	if len(packet) > dohWireMaxBody {
		return dohWireAnswer{}, errors.New("doh: DNS response exceeds 65535 bytes")
	}
	return decodeDoHWireAnswer(packet, q.question, receivedAt, resp.Header.Values("Age"))
}

func decodeDoHWireAnswer(packet []byte, want dnsmessage.Question, receivedAt time.Time, age []string) (dohWireAnswer, error) {
	var msg dnsmessage.Message
	if err := msg.Unpack(packet); err != nil {
		return dohWireAnswer{}, fmt.Errorf("doh: invalid DNS response: %w", err)
	}
	if !msg.Response || msg.OpCode != 0 || msg.ID != 0 || msg.Truncated {
		return dohWireAnswer{}, errors.New("doh: invalid DNS response header")
	}
	if len(msg.Questions) != 1 {
		return dohWireAnswer{}, errors.New("doh: DNS response must contain one question")
	}
	got := msg.Questions[0]
	if got.Type != want.Type || got.Class != want.Class || !strings.EqualFold(got.Name.String(), want.Name.String()) {
		return dohWireAnswer{}, errors.New("doh: DNS response question mismatch")
	}
	if msg.RCode != dnsmessage.RCodeSuccess && msg.RCode != dnsmessage.RCodeNameError {
		return dohWireAnswer{}, fmt.Errorf("doh: DNS %s", msg.RCode)
	}

	name, ttl, err := dohCanonicalName(want.Name, msg.Answers)
	if err != nil {
		return dohWireAnswer{}, err
	}
	var out dohWireAnswer
	if msg.RCode == dnsmessage.RCodeSuccess {
		for _, rr := range msg.Answers {
			h := rr.Header
			if h.Class != want.Class || h.Type != want.Type || !strings.EqualFold(h.Name.String(), name) {
				continue
			}
			switch body := rr.Body.(type) {
			case *dnsmessage.AResource:
				out.addrs = append(out.addrs, netip.AddrFrom4(body.A))
			case *dnsmessage.AAAAResource:
				out.addrs = append(out.addrs, netip.AddrFrom16(body.AAAA).Unmap())
			}
			ttl = min(ttl, h.TTL)
		}
	}
	if len(out.addrs) == 0 {
		ttl = min(ttl, dohNegativeTTL(name, msg.Authorities))
	}
	out.validUntil = receivedAt.Add(dohRemainingTTL(ttl, age))
	if msg.RCode == dnsmessage.RCodeNameError {
		return out, errNotFound
	}
	return out, nil
}

// dohCanonicalName follows the aliases in this answer and bounds the result
// by the shortest TTL in the chain.
func dohCanonicalName(question dnsmessage.Name, records []dnsmessage.Resource) (string, uint32, error) {
	aliases := make(map[string]dnsmessage.Resource)
	for _, rr := range records {
		if rr.Header.Class == dnsmessage.ClassINET && rr.Header.Type == dnsmessage.TypeCNAME {
			aliases[strings.ToLower(rr.Header.Name.String())] = rr
		}
	}
	name := strings.ToLower(question.String())
	ttl := ^uint32(0)
	for range len(aliases) + 1 {
		rr, ok := aliases[name]
		if !ok {
			return name, ttl, nil
		}
		ttl = min(ttl, rr.Header.TTL)
		name = strings.ToLower(rr.Body.(*dnsmessage.CNAMEResource).CNAME.String())
	}
	return "", 0, errors.New("doh: DNS CNAME loop")
}

func dohNegativeTTL(name string, authorities []dnsmessage.Resource) uint32 {
	var ttl uint32
	var zoneLength int
	for _, rr := range authorities {
		soa, ok := rr.Body.(*dnsmessage.SOAResource)
		if !ok || rr.Header.Class != dnsmessage.ClassINET {
			continue
		}
		zone := strings.ToLower(rr.Header.Name.String())
		if zone != "." && name != zone && !strings.HasSuffix(name, "."+zone) {
			continue
		}
		candidate := min(rr.Header.TTL, soa.MinTTL)
		switch {
		case len(zone) > zoneLength:
			zoneLength = len(zone)
			ttl = candidate
		case len(zone) == zoneLength:
			ttl = min(ttl, candidate)
		}
	}
	return ttl
}

func dohRemainingTTL(ttl uint32, age []string) time.Duration {
	if len(age) == 0 {
		return time.Duration(ttl) * time.Second
	}
	if len(age) != 1 {
		return 0
	}
	seconds, err := strconv.ParseUint(strings.TrimSpace(age[0]), 10, 64)
	if err != nil || seconds >= uint64(ttl) {
		return 0
	}
	return time.Duration(uint64(ttl)-seconds) * time.Second
}
