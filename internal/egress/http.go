// Package egress contains experimental, integration-scoped outbound controls.
// It is not a process-wide network sandbox.
package egress

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Destination is one exact HTTPS origin and the address ranges to which that
// origin is allowed to resolve. Empty rules deny every request.
type Destination struct {
	Origin string
	CIDRs  []netip.Prefix
}

type resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type policy struct {
	allowed map[string][]netip.Prefix
	lookup  resolver
	dialer  net.Dialer
}

// NewHTTPSClient returns a client which does not use environment proxies or
// follow redirects. Without explicit DNS configuration, only literal IP
// origins can resolve. Addresses are checked before dialing;
// TLS certificate validation still uses the original hostname. This client
// does not restrict other network clients, DNS traffic, or the host process.
func NewHTTPSClient(destinations []Destination, roots *x509.CertPool) (*http.Client, error) {
	return newHTTPSClient(destinations, roots, literalResolver{})
}

// NewHTTPSClientWithDNS permits hostname resolution exclusively through the
// explicitly supplied DNS server. No system-selected DNS server is used.
func NewHTTPSClientWithDNS(destinations []Destination, roots *x509.CertPool, dns netip.AddrPort) (*http.Client, error) {
	lookup, err := newExplicitResolver(dns)
	if err != nil {
		return nil, err
	}
	return newHTTPSClient(destinations, roots, lookup)
}

func newHTTPSClient(destinations []Destination, roots *x509.CertPool, lookup resolver) (*http.Client, error) {
	p, err := newPolicy(destinations, lookup)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           p.dialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       30 * time.Second,
		MaxIdleConns:          16,
		MaxConnsPerHost:       8,
	}
	return &http.Client{
		Transport: &guardedTransport{policy: p, next: transport},
		Timeout:   2 * time.Minute,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

func newPolicy(destinations []Destination, lookup resolver) (*policy, error) {
	if lookup == nil || len(destinations) > 256 {
		return nil, errors.New("outbound HTTPS policy is invalid")
	}
	p := &policy{allowed: make(map[string][]netip.Prefix), lookup: lookup, dialer: net.Dialer{Timeout: 10 * time.Second}}
	for _, destination := range destinations {
		address, err := originAddress(destination.Origin)
		if err != nil || len(destination.CIDRs) == 0 || len(destination.CIDRs) > 256 {
			return nil, errors.New("outbound HTTPS destination is invalid")
		}
		if _, exists := p.allowed[address]; exists {
			return nil, errors.New("outbound HTTPS destination is duplicated")
		}
		for _, prefix := range destination.CIDRs {
			if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
				return nil, errors.New("outbound HTTPS network is invalid")
			}
			p.allowed[address] = append(p.allowed[address], prefix)
		}
	}
	return p, nil
}

func originAddress(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.Opaque != "" {
		return "", errors.New("invalid HTTPS origin")
	}
	return canonicalAddress(u)
}

func canonicalAddress(u *url.URL) (string, error) {
	host := strings.ToLower(u.Hostname())
	if host == "" || strings.HasSuffix(host, ".") || strings.Contains(host, "%") {
		return "", errors.New("invalid HTTPS hostname")
	}
	for _, ch := range host {
		if !((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '-' || ch == ':') {
			return "", errors.New("invalid HTTPS hostname")
		}
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 || strconv.Itoa(number) != port {
		return "", errors.New("invalid HTTPS port")
	}
	return net.JoinHostPort(host, port), nil
}

type guardedTransport struct {
	policy *policy
	next   *http.Transport
}

func (g *guardedTransport) CloseIdleConnections() {
	g.next.CloseIdleConnections()
}

func (g *guardedTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request == nil || request.URL == nil || request.URL.Scheme != "https" || request.URL.User != nil || request.URL.Opaque != "" || (request.Host != "" && request.Host != request.URL.Host) {
		return nil, errors.New("outbound HTTPS request rejected")
	}
	address, err := canonicalAddress(request.URL)
	if err != nil || len(g.policy.allowed[address]) == 0 {
		return nil, errors.New("outbound HTTPS destination denied")
	}
	return g.next.RoundTrip(request)
}

func (p *policy) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" {
		return nil, errors.New("outbound network denied")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errors.New("outbound destination denied")
	}
	prefixes := p.allowed[net.JoinHostPort(strings.ToLower(host), port)]
	if len(prefixes) == 0 {
		return nil, errors.New("outbound destination denied")
	}
	addresses, err := p.lookup.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addresses) == 0 || len(addresses) > 64 {
		return nil, errors.New("outbound destination resolution failed")
	}
	for _, ip := range addresses {
		ip = ip.Unmap()
		for _, prefix := range prefixes {
			if prefix.Contains(ip) {
				conn, err := p.dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
				if err == nil {
					return conn, nil
				}
				break
			}
		}
	}
	return nil, errors.New("outbound destination address denied or unavailable")
}
