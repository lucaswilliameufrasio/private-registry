//go:build integration

package egress

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"private-registry/internal/testinfra"
)

func TestRestrictedPostgresWithRealTLSFixture(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	fixture, err := testinfra.StartPostgres(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := fixture.Stop(); err != nil {
			t.Errorf("stop PostgreSQL fixture: %v", err)
		}
	})
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(3), DNSNames: []string{"fixture.example"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.EnableSyntheticTLS(ctx, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})); err != nil {
		t.Fatal(err)
	}
	local, err := pgx.Connect(ctx, fixture.DSN())
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close(context.Background())
	for {
		var enabled string
		if err := local.QueryRow(ctx, "SHOW ssl").Scan(&enabled); err != nil {
			t.Fatal(err)
		}
		if enabled == "on" {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("PostgreSQL fixture did not enable TLS")
		case <-time.After(20 * time.Millisecond):
		}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	var connections atomic.Int64
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			incoming, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer incoming.Close()
				_ = incoming.SetDeadline(time.Now().Add(30 * time.Second))
				_ = fixture.ProxyLoopback(ctx, incoming)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		workers.Wait()
	})
	_, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	config, err := pgx.ParseConfig("host=fixture.example user=postgres dbname=postgres sslmode=verify-full")
	if err != nil {
		t.Fatal(err)
	}
	config.Port = uint16(port)
	config.TLSConfig.RootCAs = x509.NewCertPool()
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	config.TLSConfig.RootCAs.AddCert(certificate)
	resolver := syntheticResolver{addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	restricted, err := restrictPostgres(config, []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, resolver)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := pgx.ConnectConfig(ctx, restricted)
	if err != nil {
		t.Fatal("connect to TLS PostgreSQL fixture:", err)
	}
	var answer int
	if err := connection.QueryRow(ctx, "SELECT 42").Scan(&answer); err != nil || answer != 42 {
		_ = connection.Close(ctx)
		t.Fatalf("TLS PostgreSQL query failed: %v", err)
	}
	queryResult := make(chan error, 1)
	go func() {
		_, err := connection.Exec(ctx, "SELECT pg_sleep(10)")
		queryResult <- err
	}()
	started := false
	for !started {
		if err := local.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid = $1 AND state = 'active' AND query = 'SELECT pg_sleep(10)')`, connection.PgConn().PID()).Scan(&started); err != nil {
			_ = connection.Close(ctx)
			t.Fatal(err)
		}
		if !started {
			select {
			case <-ctx.Done():
				_ = connection.Close(context.Background())
				t.Fatal("PostgreSQL TLS query did not start")
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
	if err := connection.PgConn().CancelRequest(ctx); err != nil {
		_ = connection.Close(ctx)
		t.Fatal("cancel TLS PostgreSQL query:", err)
	}
	var pgErr *pgconn.PgError
	if err := <-queryResult; !errors.As(err, &pgErr) || pgErr.Code != "57014" {
		_ = connection.Close(ctx)
		t.Fatalf("TLS PostgreSQL query was not canceled: %v", err)
	}
	if err := connection.Close(ctx); err != nil {
		t.Fatal(err)
	}
	denied, err := restrictPostgres(config, []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, resolver)
	if err != nil {
		t.Fatal(err)
	}
	beforeDenied := connections.Load()
	if conn, err := pgx.ConnectConfig(ctx, denied); err == nil {
		_ = conn.Close(ctx)
		t.Fatal("PostgreSQL connection to disallowed IP was accepted")
	} else if errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("denied PostgreSQL connection timed out rather than failing closed")
	}
	if connections.Load() != beforeDenied {
		t.Fatal("denied PostgreSQL address reached the proxy")
	}
	wrongTrust := config.Copy()
	wrongTrust.TLSConfig.RootCAs = x509.NewCertPool()
	wrongTrust, err = restrictPostgres(wrongTrust, []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, resolver)
	if err != nil {
		t.Fatal(err)
	}
	if conn, err := pgx.ConnectConfig(ctx, wrongTrust); err == nil {
		_ = conn.Close(ctx)
		t.Fatal("PostgreSQL TLS connection accepted an untrusted certificate")
	}
}
