package egress

import (
	"context"
	"net"
	"net/netip"
	"testing"
)

func TestTCPDialerAllowsOnlyConfiguredNetworks(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	address := listener.Addr().String()
	allowed, err := NewTCPDialer(address, []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, netip.AddrPort{})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := allowed.Dial(context.Background())
	if err != nil {
		t.Fatalf("allowed dial: %v", err)
	}
	_ = conn.Close()
	denied, err := NewTCPDialer(address, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, netip.AddrPort{})
	if err != nil {
		t.Fatal(err)
	}
	if conn, err := denied.Dial(context.Background()); err == nil {
		_ = conn.Close()
		t.Fatal("dial outside the allowed networks succeeded")
	}
	// A hostname cannot resolve without an explicit DNS server.
	named, err := NewTCPDialer("localhost:25", []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, netip.AddrPort{})
	if err != nil {
		t.Fatal(err)
	}
	if conn, err := named.Dial(context.Background()); err == nil {
		_ = conn.Close()
		t.Fatal("hostname resolved without a DNS server")
	}
	for _, bad := range []string{"", "host", "host:0", "host:99999", "ho st:25", "host.:25"} {
		if _, err := NewTCPDialer(bad, []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, netip.AddrPort{}); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	if _, err := NewTCPDialer(address, nil, netip.AddrPort{}); err == nil {
		t.Fatal("accepted empty networks")
	}
}
