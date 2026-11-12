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
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
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
	question, packet, err := newDNSQuestion(host, qtype, 0)
	if err != nil {
		return dohWireQuestion{}, fmt.Errorf("doh: %w", err)
	}
	return dohWireQuestion{question: question, encoded: base64.RawURLEncoding.EncodeToString(packet)}, nil
}

func dohWireQuery(ctx context.Context, client *http.Client, endpoint string, q dohWireQuestion) (dnsAnswer, error) {
	u := url.URL{Scheme: "https", Host: endpoint, Path: "/dns-query", RawQuery: "dns=" + q.encoded}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return dnsAnswer{}, err
	}
	req.Header.Set("Accept", dohWireMediaType)
	resp, err := client.Do(req)
	if err != nil {
		return dnsAnswer{}, err
	}
	receivedAt := time.Now()
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return dnsAnswer{}, dohHTTPStatus(resp.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType != dohWireMediaType {
		return dnsAnswer{}, errors.New("doh: expected application/dns-message")
	}
	packet, err := io.ReadAll(io.LimitReader(resp.Body, dohWireMaxBody+1))
	if err != nil {
		return dnsAnswer{}, err
	}
	if len(packet) > dohWireMaxBody {
		return dnsAnswer{}, errors.New("doh: DNS response exceeds 65535 bytes")
	}
	return decodeDoHWireAnswer(packet, q.question, receivedAt, resp.Header.Values("Age"))
}

func decodeDoHWireAnswer(packet []byte, want dnsmessage.Question, receivedAt time.Time, age []string) (dnsAnswer, error) {
	decoded, err := decodeDNSAnswer(packet, want, 0)
	answer := dnsAnswer{addrs: decoded.addrs, validUntil: receivedAt.Add(dohRemainingTTL(decoded.ttl, age))}
	if err != nil {
		err = fmt.Errorf("doh: %w", err)
	}
	return answer, err
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
