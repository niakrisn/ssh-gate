package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/net/dns/dnsmessage"
)

type dnsAnswer struct {
	addrs      []netip.Addr
	validUntil time.Time
}

type dnsFamilyResult struct {
	answer dnsAnswer
	err    error
}

type dnsRCodeError dnsmessage.RCode

func (e dnsRCodeError) Error() string { return fmt.Sprintf("DNS %s", dnsmessage.RCode(e)) }
func (e dnsRCodeError) Is(target error) bool {
	return target == errNotFound && dnsmessage.RCode(e) == dnsmessage.RCodeNameError
}

// A negative DNS answer is distinct from a transient resolver failure.
// Unknown errors are protocol/trust failures and cannot be masked by an IP.
func temporaryDNSFailure(err error) bool {
	if errors.Is(err, errUnreachable) {
		return true
	}
	var rcode dnsRCodeError
	if errors.As(err, &rcode) {
		return dnsmessage.RCode(rcode) == dnsmessage.RCodeServerFailure || dnsmessage.RCode(rcode) == dnsmessage.RCodeRefused
	}
	var status dohHTTPStatus
	if errors.As(err, &status) {
		return status == 429 || status >= 500 && status < 600
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EPIPE) {
		return true
	}
	var network net.Error
	return errors.As(err, &network) && network.Timeout()
}

func combineDNSFamilies(a, b dnsFamilyResult, now time.Time) (dnsAnswer, error) {
	results := [2]dnsFamilyResult{a, b}
	for _, result := range results {
		if result.err != nil && !errors.Is(result.err, errNotFound) && !temporaryDNSFailure(result.err) {
			return dnsAnswer{}, result.err
		}
	}
	answer := dnsAnswer{validUntil: a.answer.validUntil}
	if b.answer.validUntil.Before(answer.validUntil) {
		answer.validUntil = b.answer.validUntil
	}
	if answer.validUntil.IsZero() {
		answer.validUntil = now
	}
	for _, result := range results {
		if result.err == nil {
			answer.addrs = append(answer.addrs, result.answer.addrs...)
		}
	}
	if len(answer.addrs) > 0 {
		if a.err != nil || b.err != nil {
			answer.validUntil = now
		}
		return answer, nil
	}
	// Without any addresses, a temporary failure must not become a cached
	// absence. This also covers contradictory negative/failure responses.
	for _, result := range results {
		if result.err != nil && temporaryDNSFailure(result.err) {
			return dnsAnswer{}, result.err
		}
	}
	return answer, errNotFound
}

// One warning per resolver per minute keeps repeated missing-family errors
// visible without flooding the bounded log queues.
func warnDNSPartial(last *atomic.Int64, resolver, host string, cause error) {
	now := time.Now()
	previous := last.Load()
	if previous != 0 && now.Sub(time.Unix(0, previous)) < time.Minute {
		return
	}
	if last.CompareAndSwap(previous, now.UnixNano()) {
		log.Warn().Str("resolver", resolver).Str("host", host).Err(cause).Msg("DNS partial answer; not cached")
	}
}
