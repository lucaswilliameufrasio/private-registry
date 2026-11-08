package egress

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func postgresFixtureConfig(t *testing.T) *pgx.ConnConfig {
	t.Helper()
	config, err := pgx.ParseConfig("host=fixture.example port=5432 user=synthetic dbname=synthetic sslmode=verify-full")
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func TestRestrictedPostgresUsesVerifiedTLSWithRealPgx(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture.example"}, DNSNames: []string{"fixture.example"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	serverResult := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverResult <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		var request [8]byte
		if _, err := io.ReadFull(conn, request[:]); err != nil || !bytes.Equal(request[:], []byte{0, 0, 0, 8, 4, 210, 22, 47}) {
			serverResult <- errors.New("missing PostgreSQL TLS negotiation")
			return
		}
		if _, err := conn.Write([]byte("S")); err != nil {
			serverResult <- err
			return
		}
		secure := tls.Server(conn, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
		if err := secure.Handshake(); err != nil {
			serverResult <- err
			return
		}
		var startup [1]byte
		_, err = secure.Read(startup[:])
		serverResult <- err
	}()
	config := postgresFixtureConfig(t)
	config.Port = uint16(port)
	config.TLSConfig.RootCAs = x509.NewCertPool()
	config.TLSConfig.RootCAs.AddCert(certificate)
	restricted, err := restrictPostgres(config, []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, syntheticResolver{addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connection, err := pgx.ConnectConfig(ctx, restricted)
	if err == nil {
		_ = connection.Close(ctx)
		t.Fatal("synthetic endpoint unexpectedly completed a PostgreSQL session")
	}
	if err := <-serverResult; err != nil {
		t.Fatalf("pgx did not negotiate verified TLS before startup: %v", err)
	}
}

func TestRestrictedPostgresCancelUsesApprovedPeer(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"fixture.example"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	serverResult := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverResult <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		var sslRequest [8]byte
		if _, err := io.ReadFull(conn, sslRequest[:]); err != nil || !bytes.Equal(sslRequest[:], []byte{0, 0, 0, 8, 4, 210, 22, 47}) {
			serverResult <- errors.New("missing TLS negotiation")
			return
		}
		if _, err := conn.Write([]byte("S")); err != nil {
			serverResult <- err
			return
		}
		secure := tls.Server(conn, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
		if err := secure.Handshake(); err != nil {
			serverResult <- err
			return
		}
		var size [4]byte
		if _, err := io.ReadFull(secure, size[:]); err != nil {
			serverResult <- err
			return
		}
		length := binary.BigEndian.Uint32(size[:])
		if length < 8 || length > 4096 {
			serverResult <- errors.New("invalid startup length")
			return
		}
		if _, err := io.CopyN(io.Discard, secure, int64(length-4)); err != nil {
			serverResult <- err
			return
		}
		// AuthenticationOk, BackendKeyData and ReadyForQuery are synthetic;
		// this is a protocol fixture, not a PostgreSQL server.
		messages := []byte{'R', 0, 0, 0, 8, 0, 0, 0, 0, 'K', 0, 0, 0, 12, 0, 0, 0, 1, 0, 0, 0, 2, 'Z', 0, 0, 0, 5, 'I'}
		if _, err := secure.Write(messages); err != nil {
			serverResult <- err
			return
		}
		cancelConn, err := listener.Accept()
		if err != nil {
			serverResult <- err
			return
		}
		defer cancelConn.Close()
		_ = cancelConn.SetDeadline(time.Now().Add(5 * time.Second))
		var cancelSSLRequest [8]byte
		if _, err := io.ReadFull(cancelConn, cancelSSLRequest[:]); err != nil || !bytes.Equal(cancelSSLRequest[:], []byte{0, 0, 0, 8, 4, 210, 22, 47}) {
			serverResult <- errors.New("missing cancellation TLS negotiation")
			return
		}
		if _, err := cancelConn.Write([]byte("S")); err != nil {
			serverResult <- err
			return
		}
		secureCancel := tls.Server(cancelConn, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
		if err := secureCancel.Handshake(); err != nil {
			serverResult <- err
			return
		}
		var cancelRequest [16]byte
		if _, err := io.ReadFull(secureCancel, cancelRequest[:]); err != nil || !bytes.Equal(cancelRequest[:], []byte{0, 0, 0, 16, 4, 210, 22, 46, 0, 0, 0, 1, 0, 0, 0, 2}) {
			serverResult <- errors.New("invalid PostgreSQL cancellation request")
			return
		}
		if err := secureCancel.Close(); err != nil {
			serverResult <- err
			return
		}
		serverResult <- nil
	}()
	config := postgresFixtureConfig(t)
	config.Port = uint16(port)
	config.TLSConfig.RootCAs = x509.NewCertPool()
	config.TLSConfig.RootCAs.AddCert(certificate)
	restricted, err := restrictPostgres(config, []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, syntheticResolver{addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := pgx.ConnectConfig(ctx, restricted)
	if err != nil {
		t.Fatal("synthetic PostgreSQL connection failed:", err)
	}
	defer conn.Close(context.Background())
	if err := conn.PgConn().CancelRequest(ctx); err != nil {
		t.Fatal("synthetic PostgreSQL cancel failed:", err)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}

func TestRestrictPostgresRejectsUnsafeConfigurations(t *testing.T) {
	networks := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	for _, tc := range []struct {
		name   string
		change func(*pgx.ConnConfig)
	}{
		{"plaintext", func(config *pgx.ConnConfig) { config.TLSConfig = nil }},
		{"unverified TLS", func(config *pgx.ConnConfig) { config.TLSConfig.InsecureSkipVerify = true }},
		{"wrong TLS name", func(config *pgx.ConnConfig) { config.TLSConfig.ServerName = "other.example" }},
		{"fallback", func(config *pgx.ConnConfig) {
			config.Fallbacks = []*pgconn.FallbackConfig{{Host: "other.example", Port: 5432}}
		}},
		{"socket", func(config *pgx.ConnConfig) { config.Host = "/var/run/postgresql" }},
		{"empty port", func(config *pgx.ConnConfig) { config.Port = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := postgresFixtureConfig(t)
			tc.change(config)
			if _, err := RestrictPostgres(config, networks); err == nil {
				t.Fatal("unsafe PostgreSQL configuration accepted")
			}
		})
	}
	if _, err := RestrictPostgres(postgresFixtureConfig(t), nil); err == nil {
		t.Fatal("PostgreSQL configuration accepted without allowed networks")
	}
	if _, err := RestrictPostgres(postgresFixtureConfig(t), []netip.Prefix{netip.MustParsePrefix("192.0.2.1/24")}); err == nil {
		t.Fatal("PostgreSQL configuration accepted a noncanonical network")
	}
}

func TestRestrictPostgresUnixRejectsNetworkAndOtherSockets(t *testing.T) {
	directory := t.TempDir()
	config, err := pgx.ParseConfig("user=synthetic dbname=synthetic sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	config.Host = directory
	config.Port = 5432
	config.Fallbacks = nil
	restricted, err := RestrictPostgresUnix(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restricted.LookupFunc(context.Background(), "fixture.example"); err == nil {
		t.Fatal("local PostgreSQL policy allowed DNS lookup")
	}
	for _, tc := range []struct {
		network string
		address string
	}{
		{"tcp", "127.0.0.1:5432"},
		{"unix", directory + "/other.sock"},
	} {
		if conn, err := restricted.DialFunc(context.Background(), tc.network, tc.address); err == nil {
			_ = conn.Close()
			t.Fatal("local PostgreSQL policy allowed a different destination")
		}
	}
	config.Fallbacks = []*pgconn.FallbackConfig{{Host: "fixture.example", Port: 5432}}
	if _, err := RestrictPostgresUnix(config); err == nil {
		t.Fatal("local PostgreSQL policy accepted a network fallback")
	}
}

func TestRestrictPostgresFiltersLookupAndChecksDial(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	original := postgresFixtureConfig(t)
	original.Port = uint16(port)
	lookup := syntheticResolver{addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("127.0.0.1")}}
	restricted, err := restrictPostgres(original, []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if restricted == original || restricted.TLSConfig == original.TLSConfig || restricted.TLSConfig.MinVersion < tls.VersionTLS12 {
		t.Fatal("PostgreSQL config was not copied with TLS minimum")
	}
	addresses, err := restricted.LookupFunc(context.Background(), "fixture.example")
	if err != nil || len(addresses) != 1 || addresses[0] != "127.0.0.1" {
		t.Fatalf("PostgreSQL DNS was not filtered: %v", err)
	}
	if _, err := restricted.LookupFunc(context.Background(), "other.example"); err == nil {
		t.Fatal("unapproved PostgreSQL host resolved")
	}
	for _, destination := range []string{net.JoinHostPort("192.0.2.1", portText), net.JoinHostPort("127.0.0.1", "1"), net.JoinHostPort("fixture.example", portText)} {
		if conn, err := restricted.DialFunc(context.Background(), "tcp", destination); err == nil {
			_ = conn.Close()
			t.Fatal("unapproved PostgreSQL dial succeeded")
		}
	}
	conn, err := restricted.DialFunc(context.Background(), "tcp", net.JoinHostPort("127.0.0.1", portText))
	if err != nil {
		t.Fatal("approved PostgreSQL dial failed:", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if conn, err := restricted.DialFunc(context.Background(), "unix", "/synthetic/socket"); err == nil {
		_ = conn.Close()
		t.Fatal("PostgreSQL Unix socket bypassed network policy")
	}
}
