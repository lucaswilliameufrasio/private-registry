package egress

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestOutboundDNSRequiresExplicitServer(t *testing.T) {
	if _, err := (literalResolver{}).LookupNetIP(context.Background(), "ip", "fixture.example"); err == nil {
		t.Fatal("hostname resolved without an authorized DNS server")
	}
	if addresses, err := (literalResolver{}).LookupNetIP(context.Background(), "ip", "127.0.0.1"); err != nil || len(addresses) != 1 || addresses[0] != netip.MustParseAddr("127.0.0.1") {
		t.Fatal("literal address could not be used without DNS")
	}
	for _, server := range []netip.AddrPort{{}, netip.MustParseAddrPort("0.0.0.0:53"), netip.MustParseAddrPort("224.0.0.1:53"), netip.MustParseAddrPort("127.0.0.1:0"), netip.MustParseAddrPort("[::ffff:127.0.0.1]:53")} {
		if _, err := newExplicitResolver(server); err == nil {
			t.Fatal("invalid DNS server was accepted")
		}
	}
}

func TestOutboundDNSUsesExplicitServerForTCPFallback(t *testing.T) {
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := net.Listen("tcp", udp.LocalAddr().String())
	if err != nil {
		_ = udp.Close()
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	var udpCount, tcpCount atomic.Int64
	workers.Add(2)
	go func() {
		defer workers.Done()
		buffer := make([]byte, 2048)
		for {
			n, remote, err := udp.ReadFrom(buffer)
			if err != nil {
				return
			}
			response, ok := dnsFallbackResponse(buffer[:n], true)
			if !ok {
				continue
			}
			udpCount.Add(1)
			_, _ = udp.WriteTo(response, remote)
		}
	}()
	go func() {
		defer workers.Done()
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				var length [2]byte
				if _, err := io.ReadFull(conn, length[:]); err != nil {
					return
				}
				size := int(binary.BigEndian.Uint16(length[:]))
				if size < 17 || size > 2048 {
					return
				}
				query := make([]byte, size)
				if _, err := io.ReadFull(conn, query); err != nil {
					return
				}
				response, ok := dnsFallbackResponse(query, false)
				if !ok {
					return
				}
				tcpCount.Add(1)
				binary.BigEndian.PutUint16(length[:], uint16(len(response)))
				_, _ = conn.Write(append(length[:], response...))
			}()
		}
	}()
	t.Cleanup(func() {
		_ = udp.Close()
		_ = tcp.Close()
		workers.Wait()
	})
	server, err := netip.ParseAddrPort(udp.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	lookup, err := newExplicitResolver(server)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addresses, err := lookup.LookupNetIP(ctx, "ip", "fixture.example")
	if err != nil || len(addresses) != 1 || addresses[0] != netip.MustParseAddr("127.0.0.1") || udpCount.Load() == 0 || tcpCount.Load() == 0 {
		t.Fatalf("DNS TCP fallback failed: %v", err)
	}
}

func dnsFallbackResponse(question []byte, truncated bool) ([]byte, bool) {
	if len(question) < 17 {
		return nil, false
	}
	position := 12
	var labels []string
	for position < len(question) && question[position] != 0 {
		length := int(question[position])
		position++
		if length == 0 || length > 63 || position+length > len(question) {
			return nil, false
		}
		labels = append(labels, string(question[position:position+length]))
		position += length
	}
	if position+5 > len(question) || strings.ToLower(strings.Join(labels, ".")) != "fixture.example" {
		return nil, false
	}
	position++
	queryType := binary.BigEndian.Uint16(question[position : position+2])
	questionEnd := position + 4
	response := make([]byte, 12, questionEnd+16)
	copy(response[:2], question[:2])
	flags := uint16(0x8180)
	if truncated {
		flags |= 0x0200
	}
	binary.BigEndian.PutUint16(response[2:4], flags)
	binary.BigEndian.PutUint16(response[4:6], 1)
	response = append(response, question[12:questionEnd]...)
	if !truncated && queryType == 1 {
		binary.BigEndian.PutUint16(response[6:8], 1)
		response = append(response, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 127, 0, 0, 1)
	}
	return response, true
}

func TestOutboundDNSUsesOnlyConfiguredServerAndAbsoluteName(t *testing.T) {
	serverAddress, queries, invalid := startSyntheticDNS(t)
	lookup, err := newExplicitResolver(serverAddress)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addresses, err := lookup.LookupNetIP(ctx, "ip", "fixture.example")
	if err != nil || len(addresses) != 1 || addresses[0] != netip.MustParseAddr("127.0.0.1") || queries.Load() == 0 || invalid.Load() {
		t.Fatalf("explicit DNS did not resolve the expected absolute name: %v", err)
	}
}

func startSyntheticDNS(t *testing.T) (netip.AddrPort, *atomic.Int64, *atomic.Bool) {
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
	serverAddress, err := netip.ParseAddrPort(server.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	return serverAddress, &queries, &invalid
}
