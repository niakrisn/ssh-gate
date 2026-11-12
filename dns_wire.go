package main

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/idna"
)

// dnsWireAnswer carries DNS TTL before transport-specific cache adjustments.
type dnsWireAnswer struct {
	addrs []netip.Addr
	ttl   uint32
}

func newDNSQuestion(host string, qtype dnsmessage.Type, id uint16) (dnsmessage.Question, []byte, error) {
	if strings.IndexFunc(host, func(r rune) bool { return r > 127 }) >= 0 {
		ascii, err := idna.Lookup.ToASCII(host)
		if err != nil {
			return dnsmessage.Question{}, nil, fmt.Errorf("invalid DNS name: %w", err)
		}
		host = ascii
	}
	name, err := dnsmessage.NewName(strings.TrimSuffix(host, ".") + ".")
	if err != nil {
		return dnsmessage.Question{}, nil, fmt.Errorf("invalid DNS name: %w", err)
	}
	question := dnsmessage.Question{Name: name, Type: qtype, Class: dnsmessage.ClassINET}
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{question},
	}
	packet, err := msg.Pack()
	if err != nil {
		return dnsmessage.Question{}, nil, fmt.Errorf("invalid DNS question: %w", err)
	}
	return question, packet, nil
}

func decodeDNSAnswer(packet []byte, want dnsmessage.Question, id uint16) (dnsWireAnswer, error) {
	var msg dnsmessage.Message
	if err := msg.Unpack(packet); err != nil {
		return dnsWireAnswer{}, fmt.Errorf("invalid DNS response: %w", err)
	}
	if !msg.Response || msg.OpCode != 0 || msg.ID != id || msg.Truncated {
		return dnsWireAnswer{}, errors.New("invalid DNS response header")
	}
	if len(msg.Questions) != 1 {
		return dnsWireAnswer{}, errors.New("DNS response must contain one question")
	}
	got := msg.Questions[0]
	if got.Type != want.Type || got.Class != want.Class || !strings.EqualFold(got.Name.String(), want.Name.String()) {
		return dnsWireAnswer{}, errors.New("DNS response question mismatch")
	}
	if msg.RCode != dnsmessage.RCodeSuccess && msg.RCode != dnsmessage.RCodeNameError {
		return dnsWireAnswer{}, dnsRCodeError(msg.RCode)
	}

	name, ttl, err := dnsCanonicalName(want.Name, msg.Answers)
	if err != nil {
		return dnsWireAnswer{}, err
	}
	var out dnsWireAnswer
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
		ttl = min(ttl, negativeSOATTL(name, msg.Authorities))
	}
	out.ttl = ttl
	if msg.RCode == dnsmessage.RCodeNameError {
		return out, dnsRCodeError(msg.RCode)
	}
	return out, nil
}

// dnsCanonicalName follows the aliases in this answer and bounds the result
// by the shortest TTL in the chain.
func dnsCanonicalName(question dnsmessage.Name, records []dnsmessage.Resource) (string, uint32, error) {
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
	return "", 0, errors.New("DNS CNAME loop")
}

func negativeSOATTL(name string, authorities []dnsmessage.Resource) uint32 {
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
