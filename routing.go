package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
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

// dialDirectIP dials one already-resolved address with the direct dialer's
// timeout. Resolution and the address choice (route policy, family filter)
// happen in the Opener.
func dialDirectIP(ctx context.Context, ip netip.Addr, port int, family IPFamily) (net.Conn, error) {
	if !familyMatches(family, ip.AsSlice()) {
		return nil, fmt.Errorf("dial %s:%d: no %s addresses", ip, port, family)
	}
	network := "tcp4"
	if !ip.Is4() {
		network = "tcp6"
	}
	conn, err := directDialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), strconv.Itoa(port)))
	if err != nil {
		return nil, fmt.Errorf("dial %s:%d: %w", ip, port, err)
	}
	return conn, nil
}
