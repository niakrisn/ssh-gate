package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// dnsServerLookup exchanges explicit DNS packets on one SSH TCP channel.
// It never consults system hosts/search policy. A peer that closes after
// one complete response gets one retry for only the unanswered family.
func dnsServerLookup(d dialer, server string) func(context.Context, string) ([]netip.Addr, time.Time, error) {
	var lastWarning atomic.Int64
	return func(ctx context.Context, host string) ([]netip.Addr, time.Time, error) {
		ctx, cancel := context.WithTimeout(ctx, tunnelLookupTimeout)
		defer cancel()
		work, stop := context.WithCancelCause(ctx)
		defer stop(context.Canceled)
		var ids [4]byte
		if _, err := rand.Read(ids[:]); err != nil {
			return nil, time.Time{}, err
		}
		transaction := [2]uint16{binary.BigEndian.Uint16(ids[:2]), binary.BigEndian.Uint16(ids[2:])}
		if transaction[0] == transaction[1] {
			transaction[1]++
		}
		var questions [2]dnsmessage.Question
		var packets [2][]byte
		for i, qtype := range [2]dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
			question, packet, err := newDNSQuestion(host, qtype, transaction[i])
			if err != nil {
				return nil, time.Time{}, err
			}
			questions[i], packets[i] = question, packet
		}
		var results [2]dnsFamilyResult
		var received [2]bool
		count := 0
		opened := false
		var familyTimer *time.Timer
		defer func() {
			if familyTimer != nil {
				familyTimer.Stop()
			}
		}()
		exchange := func() error {
			conn, err := d.DialContext(ctxWithNoTrack(work), "tcp", server)
			if err != nil {
				return fmt.Errorf("%w: %w", errUnreachable, err)
			}
			opened = true
			stopClose := context.AfterFunc(work, func() { conn.Close() })
			defer func() { stopClose(); conn.Close() }()
			// Send both questions before reading, without a worker per family.
			for i, packet := range packets {
				if received[i] {
					continue
				}
				frame := append(binary.BigEndian.AppendUint16(nil, uint16(len(packet))), packet...)
				if _, err := conn.Write(frame); err != nil {
					return err
				}
			}
			for count < 2 {
				var size [2]byte
				if _, err := io.ReadFull(conn, size[:]); err != nil {
					return err
				}
				n := int(binary.BigEndian.Uint16(size[:]))
				if n < 12 {
					return fmt.Errorf("DNS TCP response too short: %d", n)
				}
				packet := make([]byte, n)
				if _, err := io.ReadFull(conn, packet); err != nil {
					return err
				}
				id := binary.BigEndian.Uint16(packet[:2])
				i := -1
				for index, want := range transaction {
					if id == want && !received[index] {
						i = index
						break
					}
				}
				if i < 0 {
					return fmt.Errorf("DNS TCP response has unexpected ID %d", id)
				}
				decoded, err := decodeDNSAnswer(packet, questions[i], id)
				if err != nil && !errors.Is(err, errNotFound) && !temporaryDNSFailure(err) {
					return err
				}
				ttl := dnsCacheTTL
				if len(decoded.addrs) == 0 {
					ttl = dnsNegativeTTL
				}
				ttl = min(ttl, time.Duration(decoded.ttl)*time.Second)
				results[i] = dnsFamilyResult{answer: dnsAnswer{addrs: decoded.addrs, validUntil: time.Now().Add(ttl)}, err: err}
				received[i] = true
				count++
				if len(decoded.addrs) > 0 && familyTimer == nil {
					familyTimer = time.AfterFunc(250*time.Millisecond, func() { stop(context.DeadlineExceeded) })
				}
			}
			return nil
		}
		var err error
		for attempt := 0; attempt < 2; attempt++ {
			if work.Err() != nil {
				err = context.Cause(work)
				break
			}
			err = exchange()
			if work.Err() != nil {
				err = context.Cause(work)
				break
			}
			closed := errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET)
			if err == nil || count != 1 || !closed {
				break
			}
		}
		if err := ctx.Err(); err != nil {
			if !opened {
				return nil, time.Time{}, fmt.Errorf("%w: %w", errUnreachable, err)
			}
			return nil, time.Time{}, err
		}
		if err != nil {
			for i := range received {
				if !received[i] {
					results[i].err = err
				}
			}
		}
		answer, err := combineDNSFamilies(results[0], results[1], time.Now())
		if err == nil && (results[0].err != nil || results[1].err != nil) {
			warnDNSPartial(&lastWarning, server, host, errors.Join(results[0].err, results[1].err))
		}
		return answer.addrs, answer.validUntil, err
	}
}
