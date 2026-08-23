package main

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// IPFamily controls which address families direct connections may use.
type IPFamily int

const (
	FamilyBoth IPFamily = iota
	FamilyIPv4
	FamilyIPv6
)

func (f IPFamily) String() string {
	switch f {
	case FamilyIPv4:
		return "ipv4"
	case FamilyIPv6:
		return "ipv6"
	default:
		return "both"
	}
}

func parseIPFamily(raw string) (IPFamily, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "both", "auto":
		return FamilyBoth, nil
	case "ipv4", "v4":
		return FamilyIPv4, nil
	case "ipv6", "v6":
		return FamilyIPv6, nil
	}
	return FamilyBoth, fmt.Errorf("invalid DIRECT_IP_FAMILY %q: want ipv4, ipv6, or both", raw)
}

func familyMatches(f IPFamily, ip net.IP) bool {
	switch f {
	case FamilyIPv4:
		return ip.To4() != nil
	case FamilyIPv6:
		return ip.To4() == nil
	default:
		return true
	}
}

// directDialer handles direct TCP connections with timeout.
var directDialer = &net.Dialer{
	Timeout:   5 * time.Second,
	KeepAlive: 30 * time.Second,
}

// dialDirect resolves host and dials the first matching address that accepts
// the connection. Returns (conn, selectedIP, error); selectedIP is empty on error.
func dialDirect(ctx context.Context, host string, port int, family IPFamily) (net.Conn, string, error) {
	t0 := time.Now()
	var addrs []net.IPAddr
	var err error

	if ip := net.ParseIP(host); ip != nil {
		addrs = []net.IPAddr{{IP: ip}}
	} else {
		addrs, err = net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, "", fmt.Errorf("resolve %s: %w", host, err)
		}
	}

	if len(addrs) > 0 {
		ipStrs := make([]string, len(addrs))
		for i, a := range addrs {
			ipStrs[i] = a.IP.String()
		}
		log.Debug().Str("host", host).Str("family", family.String()).Strs("addrs", ipStrs).
			Int64("ms", time.Since(t0).Milliseconds()).Msg("dial resolve")
	}

	var dialErr error
	matched := false
	for _, a := range addrs {
		if !familyMatches(family, a.IP) {
			continue
		}
		matched = true
		network := "tcp4"
		if a.IP.To4() == nil {
			network = "tcp6"
		}
		addr := net.JoinHostPort(a.IP.String(), strconv.Itoa(port))
		conn, dErr := directDialer.DialContext(ctx, network, addr)
		if dErr == nil {
			return conn, a.IP.String(), nil
		}
		dialErr = dErr
		log.Debug().Str("ip", a.IP.String()).Err(dErr).Msg("dial direct: attempt failed")
	}

	if !matched {
		return nil, "", fmt.Errorf("dial %s:%d: no %s addresses", host, port, family)
	}
	if dialErr != nil {
		return nil, "", fmt.Errorf("dial %s:%d: %w", host, port, dialErr)
	}
	return nil, "", fmt.Errorf("dial %s:%d: no addresses", host, port)
}
