package egress

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

type syntheticResolver struct {
	addresses []netip.Addr
	err       error
}

type changingResolver struct{ denied atomic.Bool }

func (r *changingResolver) LookupNetIP(_ context.Context, _, _ string) ([]netip.Addr, error) {
	if r.denied.Load() {
		return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
	}
	return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
}

func TestHTTPSClientWithExplicitDNS(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(5), DNSNames: []string{"fixture.example"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		response.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
	defer server.Close()
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	origin := "https://fixture.example:" + port
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	destinations := []Destination{{Origin: origin, CIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}}
	withoutDNS, err := NewHTTPSClient(destinations, roots)
	if err != nil {
		t.Fatal(err)
	}
	if response, err := withoutDNS.Get(origin); err == nil {
		_ = response.Body.Close()
		t.Fatal("hostname worked without an explicit DNS server")
	}
	if requests.Load() != 0 {
		t.Fatal("request without DNS policy reached the HTTPS fixture")
	}
	dns, queries, invalid := startSyntheticDNS(t)
	client, err := NewHTTPSClientWithDNS(destinations, roots, dns)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Get(origin)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil || response.StatusCode != http.StatusNoContent || requests.Load() != 1 || queries.Load() == 0 || invalid.Load() {
		t.Fatal("HTTPS did not use the expected explicit DNS and TLS origin")
	}
	client.CloseIdleConnections()
	changing := &changingResolver{}
	rebindingClient, err := newHTTPSClient(destinations, roots, changing)
	if err != nil {
		t.Fatal(err)
	}
	response, err = rebindingClient.Get(origin)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	rebindingClient.CloseIdleConnections()
	changing.denied.Store(true)
	if response, err := rebindingClient.Get(origin); err == nil {
		_ = response.Body.Close()
		t.Fatal("DNS rebinding escaped the authorized networks")
	}
	if requests.Load() != 2 {
		t.Fatal("DNS rebinding reached the HTTPS fixture")
	}
}

func (r syntheticResolver) LookupNetIP(_ context.Context, _, _ string) ([]netip.Addr, error) {
	return r.addresses, r.err
}

func TestHTTPSClientDeniesByDefaultAndRestrictsOrigins(t *testing.T) {
	var requests int
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests++
		_, _ = io.WriteString(response, "synthetic")
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	denied, err := NewHTTPSClient(nil, roots)
	if err != nil {
		t.Fatal(err)
	}
	if response, err := denied.Get(server.URL); err == nil {
		_ = response.Body.Close()
		t.Fatal("empty policy allowed an outbound request")
	}
	if requests != 0 {
		t.Fatal("denied request reached the destination")
	}
	wrongIP, err := NewHTTPSClient([]Destination{{Origin: server.URL, CIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}}, roots)
	if err != nil {
		t.Fatal(err)
	}
	if response, err := wrongIP.Get(server.URL); err == nil {
		_ = response.Body.Close()
		t.Fatal("destination outside authorized networks was reached")
	}
	if requests != 0 {
		t.Fatal("unapproved network reached the destination")
	}
	untrustedTLS, err := NewHTTPSClient([]Destination{{Origin: server.URL, CIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}}, x509.NewCertPool())
	if err != nil {
		t.Fatal(err)
	}
	if response, err := untrustedTLS.Get(server.URL); err == nil {
		_ = response.Body.Close()
		t.Fatal("untrusted TLS certificate was accepted")
	}
	if requests != 0 {
		t.Fatal("TLS verification failure reached the HTTP handler")
	}
	allowed, err := NewHTTPSClient([]Destination{{Origin: server.URL, CIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}}, roots)
	if err != nil {
		t.Fatal(err)
	}
	response, err := allowed.Get(server.URL + "/path?query=allowed")
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || string(body) != "synthetic" || requests != 1 {
		t.Fatal("authorized request did not reach its destination")
	}
	request, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "unapproved.example"
	if response, err := allowed.Do(request); err == nil {
		_ = response.Body.Close()
		t.Fatal("request with overridden Host was accepted")
	}
	if requests != 1 {
		t.Fatal("overridden Host reached the destination")
	}
	allowed.CloseIdleConnections()
}

func TestHTTPSClientDoesNotFollowRedirectsOrEnvironmentProxy(t *testing.T) {
	var redirected int
	target := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		redirected++
		response.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, target.URL, http.StatusFound)
	}))
	defer server.Close()
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("NO_PROXY", "")
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	client, err := NewHTTPSClient([]Destination{{Origin: server.URL, CIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}}, roots)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	closeErr := response.Body.Close()
	if closeErr != nil || response.StatusCode != http.StatusFound || redirected != 0 {
		t.Fatal("client followed redirect or failed to ignore environment proxy")
	}
}

func TestHTTPSPolicyRejectsAmbiguousDestinations(t *testing.T) {
	for _, origin := range []string{"http://example.test", "https://user@example.test", "https://example.test/path", "https://example.test?x=1", "https://example.test.", "https://example.test:0443", "https://[fe80::1%25eth0]"} {
		if _, err := NewHTTPSClient([]Destination{{Origin: origin, CIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}}, nil); err == nil {
			t.Fatalf("ambiguous origin accepted: %q", origin)
		}
	}
	if _, err := NewHTTPSClient([]Destination{{Origin: "https://example.test"}}, nil); err == nil {
		t.Fatal("origin without explicit networks accepted")
	}
	if _, err := NewHTTPSClient([]Destination{{Origin: "https://example.test", CIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/24")}}}, nil); err == nil {
		t.Fatal("noncanonical network accepted")
	}
}

func TestDialChecksResolvedAddressAtEachNewConnection(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	origin := "https://fixture.example:" + port
	address := net.JoinHostPort("fixture.example", port)
	destinations := []Destination{{Origin: origin, CIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}}
	p, err := newPolicy(destinations, syntheticResolver{addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}})
	if err != nil {
		t.Fatal(err)
	}
	if conn, err := p.dialContext(context.Background(), "tcp", address); err == nil {
		_ = conn.Close()
		t.Fatal("DNS answer outside authorized networks was accepted")
	}
	p.lookup = syntheticResolver{addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("127.0.0.1")}}
	conn, err := p.dialContext(context.Background(), "tcp", address)
	if err != nil {
		t.Fatal("authorized address was not dialed:", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	p.lookup = syntheticResolver{err: errors.New("synthetic DNS failure")}
	if conn, err := p.dialContext(context.Background(), "tcp", address); err == nil {
		_ = conn.Close()
		t.Fatal("DNS failure reused a previous address")
	}
	if conn, err := p.dialContext(context.Background(), "udp", address); err == nil {
		_ = conn.Close()
		t.Fatal("non-TCP network was accepted")
	}
}
