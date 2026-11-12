package egress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// TCPDialer connects only to one host and port, and only when that host
// resolves inside the allowed networks. It is for protocols other than
// HTTPS, such as SMTP.
type TCPDialer struct {
	policy  *policy
	address string
}

// NewTCPDialer accepts address as host:port. Without a DNS server, only a
// literal IP host can resolve; with one, hostnames resolve exclusively
// through it.
func NewTCPDialer(address string, cidrs []netip.Prefix, dns netip.AddrPort) (*TCPDialer, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errors.New("outbound TCP destination is invalid")
	}
	host = strings.ToLower(host)
	number, err := strconv.Atoi(port)
	if host == "" || strings.HasSuffix(host, ".") || strings.Contains(host, "%") || err != nil || number < 1 || number > 65535 || strconv.Itoa(number) != port {
		return nil, errors.New("outbound TCP destination is invalid")
	}
	for _, ch := range host {
		if !((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '-' || ch == ':') {
			return nil, errors.New("outbound TCP destination is invalid")
		}
	}
	var lookup resolver = literalResolver{}
	if dns.IsValid() {
		lookup, err = newExplicitResolver(dns)
		if err != nil {
			return nil, err
		}
	}
	canonical := net.JoinHostPort(host, port)
	p := &policy{allowed: make(map[string][]netip.Prefix), lookup: lookup, dialer: net.Dialer{Timeout: 10 * time.Second}}
	if len(cidrs) == 0 || len(cidrs) > 256 {
		return nil, errors.New("outbound TCP networks are invalid")
	}
	for _, prefix := range cidrs {
		if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
			return nil, errors.New("outbound TCP network is invalid")
		}
		p.allowed[canonical] = append(p.allowed[canonical], prefix)
	}
	return &TCPDialer{policy: p, address: canonical}, nil
}

// Address returns the only destination this dialer connects to.
func (d *TCPDialer) Address() string { return d.address }

// Host returns the destination hostname, for TLS server name checks.
func (d *TCPDialer) Host() string {
	host, _, _ := net.SplitHostPort(d.address)
	return host
}

// Dial connects to the configured destination.
func (d *TCPDialer) Dial(ctx context.Context) (net.Conn, error) {
	if d == nil || d.policy == nil {
		return nil, errors.New("outbound TCP dialer is unavailable")
	}
	return d.policy.dialContext(ctx, "tcp", d.address)
}
