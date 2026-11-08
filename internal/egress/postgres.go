package egress

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// RestrictPostgresUnix confines a local PostgreSQL connection and cancellation
// to the one socket selected by the configured directory and port. No TCP
// fallbacks or DNS lookups are allowed.
func RestrictPostgresUnix(config *pgx.ConnConfig) (*pgx.ConnConfig, error) {
	if config == nil || !filepath.IsAbs(config.Host) || filepath.Clean(config.Host) != config.Host || config.Port == 0 {
		return nil, errors.New("PostgreSQL local socket configuration is invalid")
	}
	for _, fallback := range config.Fallbacks {
		if fallback == nil || fallback.Host != config.Host || fallback.Port != config.Port {
			return nil, errors.New("PostgreSQL local socket fallback is invalid")
		}
	}
	_, address := pgconn.NetworkAddress(config.Host, config.Port)
	result := config.Copy()
	result.LookupFunc = func(context.Context, string) ([]string, error) {
		return nil, errors.New("PostgreSQL local socket cannot resolve network hosts")
	}
	dialer := net.Dialer{Timeout: 10 * time.Second}
	result.DialFunc = func(ctx context.Context, network, requested string) (net.Conn, error) {
		if network != "unix" || requested != address {
			return nil, errors.New("PostgreSQL local socket destination denied")
		}
		return dialer.DialContext(ctx, "unix", address)
	}
	return result, nil
}

// RestrictPostgres returns a copy restricted to one explicitly configured TCP
// host, port and set of networks. It requires hostname-verified TLS and rejects
// Unix sockets and all driver fallbacks. The original config is not modified.
// Without explicit DNS configuration, the hostname must be a literal IP.
// Other clients or subprocesses remain outside this policy.
func RestrictPostgres(config *pgx.ConnConfig, networks []netip.Prefix) (*pgx.ConnConfig, error) {
	return restrictPostgres(config, networks, literalResolver{})
}

// RestrictPostgresWithDNS permits hostname resolution only through the
// explicitly supplied DNS server; no system-selected resolver is used.
func RestrictPostgresWithDNS(config *pgx.ConnConfig, networks []netip.Prefix, dns netip.AddrPort) (*pgx.ConnConfig, error) {
	lookup, err := newExplicitResolver(dns)
	if err != nil {
		return nil, err
	}
	return restrictPostgres(config, networks, lookup)
}

func restrictPostgres(config *pgx.ConnConfig, networks []netip.Prefix, lookup resolver) (*pgx.ConnConfig, error) {
	if config == nil || lookup == nil || len(networks) == 0 || len(networks) > 256 || config.Port == 0 || len(config.Fallbacks) != 0 || config.TLSConfig == nil || config.TLSConfig.InsecureSkipVerify {
		return nil, errors.New("PostgreSQL outbound policy requires one TLS-verified TCP destination")
	}
	host := strings.ToLower(config.Host)
	if host == "" || strings.HasPrefix(host, "/") || strings.ContainsAny(host, "%/\\") || strings.HasSuffix(host, ".") || !strings.EqualFold(config.TLSConfig.ServerName, host) {
		return nil, errors.New("PostgreSQL outbound hostname is invalid or not TLS verified")
	}
	for _, ch := range host {
		if !((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '-' || ch == ':') {
			return nil, errors.New("PostgreSQL outbound hostname is invalid")
		}
	}
	allowed := make([]netip.Prefix, 0, len(networks))
	for _, network := range networks {
		if !network.IsValid() || network != network.Masked() || network.Addr().Is4In6() || network.Addr().Zone() != "" {
			return nil, errors.New("PostgreSQL outbound network is invalid")
		}
		allowed = append(allowed, network)
	}
	port := strconv.Itoa(int(config.Port))
	permits := func(ip netip.Addr) bool {
		if !ip.IsValid() || ip.Zone() != "" {
			return false
		}
		ip = ip.Unmap()
		for _, prefix := range allowed {
			if prefix.Contains(ip) {
				return true
			}
		}
		return false
	}
	result := config.Copy()
	result.TLSConfig.MinVersion = max(result.TLSConfig.MinVersion, tls.VersionTLS12)
	result.LookupFunc = func(ctx context.Context, requestedHost string) ([]string, error) {
		if !strings.EqualFold(requestedHost, host) {
			return nil, errors.New("PostgreSQL outbound hostname denied")
		}
		addresses, err := lookup.LookupNetIP(ctx, "ip", host)
		if err != nil || len(addresses) == 0 || len(addresses) > 64 {
			return nil, errors.New("PostgreSQL outbound resolution failed")
		}
		var result []string
		for _, ip := range addresses {
			if permits(ip) {
				result = append(result, ip.Unmap().String())
			}
		}
		if len(result) == 0 {
			return nil, errors.New("PostgreSQL outbound addresses denied")
		}
		return result, nil
	}
	dialer := net.Dialer{Timeout: 10 * time.Second}
	result.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" {
			return nil, errors.New("PostgreSQL outbound network denied")
		}
		ipText, requestedPort, err := net.SplitHostPort(address)
		if err != nil || requestedPort != port {
			return nil, errors.New("PostgreSQL outbound destination denied")
		}
		ip, err := netip.ParseAddr(ipText)
		if err != nil || !permits(ip) {
			return nil, errors.New("PostgreSQL outbound address denied")
		}
		return dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.Unmap().String(), port))
	}
	return result, nil
}
