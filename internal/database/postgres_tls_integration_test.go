//go:build integration

package database

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"private-registry/internal/config"
	"private-registry/internal/testinfra"
)

func TestDatabaseOpenPostgresTCPRequiresExplicitNetworkAndVerifiedTLS(t *testing.T) {
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
	template := &x509.Certificate{SerialNumber: big.NewInt(4), DNSNames: []string{"fixture.example"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := fixture.EnableSyntheticTLS(ctx, certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})); err != nil {
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
	var reached atomic.Int64
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			incoming, err := listener.Accept()
			if err != nil {
				return
			}
			reached.Add(1)
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
	certPath := filepath.Join(t.TempDir(), "synthetic-ca.pem")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	dsn := fmt.Sprintf("host=127.0.0.1 port=%d user=postgres dbname=postgres sslmode=verify-full sslrootcert=%s", port, certPath)
	cfg := config.Config{DatabaseDriver: config.Postgres, DatabaseDSN: dsn, DatabaseMaxOpenConns: 1}
	if db, err := Open(ctx, cfg); err == nil {
		_ = db.Close()
		t.Fatal("PostgreSQL TCP worked without an allowed network")
	}
	cfg.DatabaseAllowedNetworks = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	if db, err := Open(ctx, cfg); err == nil {
		_ = db.Close()
		t.Fatal("PostgreSQL TCP worked outside the allowed network")
	}
	if reached.Load() != 0 {
		t.Fatal("denied PostgreSQL TCP request reached the fixture")
	}
	cfg.DatabaseAllowedNetworks = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	db, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal("open allowed TLS PostgreSQL:", err)
	}
	var answer int
	if err := db.QueryRowContext(ctx, "SELECT 42").Scan(&answer); err != nil || answer != 42 {
		_ = db.Close()
		t.Fatalf("allowed PostgreSQL query failed: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	beforeHostname := reached.Load()
	cfg.DatabaseDSN = fmt.Sprintf("host=fixture.example port=%d user=postgres dbname=postgres sslmode=verify-full sslrootcert=%s", port, certPath)
	if db, err := Open(ctx, cfg); err == nil {
		_ = db.Close()
		t.Fatal("hostname worked without an explicit DNS server")
	}
	if reached.Load() != beforeHostname {
		t.Fatal("hostname without DNS policy reached the fixture")
	}
	dns, queries, invalid := startSyntheticDatabaseDNS(t)
	cfg.DatabaseDNSServer = dns
	db, err = Open(ctx, cfg)
	if err != nil {
		t.Fatal("open PostgreSQL using explicitly configured DNS:", err)
	}
	if err := db.QueryRowContext(ctx, "SELECT 43").Scan(&answer); err != nil || answer != 43 {
		_ = db.Close()
		t.Fatalf("PostgreSQL hostname query failed: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if queries.Load() == 0 || invalid.Load() {
		t.Fatal("PostgreSQL DNS did not use the expected absolute name")
	}
}

func startSyntheticDatabaseDNS(t *testing.T) (netip.AddrPort, *atomic.Int64, *atomic.Bool) {
	t.Helper()
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var queries atomic.Int64
	var invalid atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 2048)
		for {
			n, remote, err := server.ReadFrom(buffer)
			if err != nil {
				return
			}
			queries.Add(1)
			question := buffer[:n]
			if len(question) < 17 {
				invalid.Store(true)
				continue
			}
			position := 12
			var labels []string
			for position < len(question) && question[position] != 0 {
				length := int(question[position])
				position++
				if length == 0 || length > 63 || position+length > len(question) {
					invalid.Store(true)
					break
				}
				labels = append(labels, string(question[position:position+length]))
				position += length
			}
			if position+5 > len(question) || strings.ToLower(strings.Join(labels, ".")) != "fixture.example" {
				invalid.Store(true)
				continue
			}
			position++
			queryType := binary.BigEndian.Uint16(question[position : position+2])
			questionEnd := position + 4
			response := make([]byte, 12, questionEnd+16)
			copy(response[:2], question[:2])
			binary.BigEndian.PutUint16(response[2:4], 0x8180)
			binary.BigEndian.PutUint16(response[4:6], 1)
			response = append(response, question[12:questionEnd]...)
			if queryType == 1 {
				binary.BigEndian.PutUint16(response[6:8], 1)
				response = append(response, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 127, 0, 0, 1)
			}
			if _, err := server.WriteTo(response, remote); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = server.Close()
		<-done
	})
	address, err := netip.ParseAddrPort(server.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	return address, &queries, &invalid
}
