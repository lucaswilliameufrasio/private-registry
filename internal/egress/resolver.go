package egress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"
)

type literalResolver struct{}

func (literalResolver) LookupNetIP(_ context.Context, _ string, host string) ([]netip.Addr, error) {
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" {
		return nil, errors.New("outbound DNS server is not configured")
	}
	return []netip.Addr{ip}, nil
}

// explicitResolver sends DNS queries only to the explicitly authorized IP and
// port, never to system-selected resolvers. Domain queries are absolute, so
// local DNS search domains cannot silently expand an integration hostname.
type explicitResolver struct {
	resolver *net.Resolver
}

func newExplicitResolver(server netip.AddrPort) (resolver, error) {
	address := server.Addr()
	if !server.IsValid() || server.Port() == 0 || address.Is4In6() || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() || address == netip.MustParseAddr("255.255.255.255") {
		return nil, errors.New("outbound DNS server must be an explicit unicast IP and port")
	}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	return &explicitResolver{resolver: &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			if network != "udp" && network != "tcp" {
				return nil, errors.New("outbound DNS network denied")
			}
			return dialer.DialContext(ctx, network, server.String())
		},
	}}, nil
}

func (r *explicitResolver) LookupNetIP(ctx context.Context, _ string, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil && ip.Zone() == "" {
		return []netip.Addr{ip}, nil
	}
	return r.resolver.LookupNetIP(ctx, "ip", strings.TrimSuffix(host, ".")+".")
}
