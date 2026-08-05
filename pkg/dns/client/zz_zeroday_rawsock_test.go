// Zero-day audit: end-to-end robustness of the REAL running DNS proxy against
// malformed raw packets, exercising miekg's socket read/deframe loop + ServeDNS.
package client

import (
	"encoding/binary"
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"

	dnsProto "istio.io/istio/pkg/dns/proto"
)

func startRealProxy(t *testing.T) *LocalDNSServer {
	t.Helper()
	h, err := NewLocalDNSServer("ns1", "ns1.svc.cluster.local", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	h.resolvConfServers = nil // no upstream network
	h.searchNamespaces = []string{"ns1.svc.cluster.local"}
	h.UpdateLookupTable(&dnsProto.NameTable{Table: map[string]*dnsProto.NameTable_NameInfo{
		"productpage.ns1.svc.cluster.local": {Ips: []string{"9.9.9.9"}, Registry: "Kubernetes", Namespace: "ns1", Shortname: "productpage"},
		"*.wildcard":                        {Ips: []string{"10.10.10.10"}, Registry: "External"},
	}})
	h.StartDNS()
	t.Cleanup(h.Close)
	return h
}

// addrs returns the udp and tcp proxy listen addresses.
func proxyAddrs(h *LocalDNSServer) (udp, tcp string) {
	for _, p := range h.dnsProxies {
		if p.protocol == "udp" && udp == "" {
			udp = p.Address()
		}
		if p.protocol == "tcp" && tcp == "" {
			tcp = p.Address()
		}
	}
	return
}

func TestRawMalformedPacketsDoNotCrash(t *testing.T) {
	h := startRealProxy(t)
	udpAddr, tcpAddr := proxyAddrs(h)

	rnd := rand.New(rand.NewSource(1))
	payloads := [][]byte{
		{},                                  // empty
		{0x00},                              // 1 byte
		{0xff, 0xff, 0xff, 0xff},            // garbage header
		make([]byte, 12),                    // header only, zero counts
		func() []byte { b := make([]byte, 12); binary.BigEndian.PutUint16(b[4:], 0xffff); return b }(), // huge qdcount, no body
		func() []byte { b := make([]byte, 12); binary.BigEndian.PutUint16(b[6:], 0xffff); return b }(), // huge ancount
		// compression-pointer loop: header + qd=1 + name that points to itself
		func() []byte {
			b := make([]byte, 12)
			binary.BigEndian.PutUint16(b[4:], 1)
			b = append(b, 0xc0, 0x0c) // pointer to offset 12 (itself)
			b = append(b, 0x00, 0x01, 0x00, 0x01)
			return b
		}(),
	}
	// add a pile of random blobs
	for i := 0; i < 2000; i++ {
		n := rnd.Intn(600)
		b := make([]byte, n)
		rnd.Read(b)
		payloads = append(payloads, b)
	}

	// UDP blast
	uc, err := net.Dial("udp", udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range payloads {
		_ = uc.SetWriteDeadline(time.Now().Add(time.Second))
		_, _ = uc.Write(p)
	}
	uc.Close()

	// TCP blast (raw, with and without proper length prefix)
	for _, p := range payloads {
		c, err := net.DialTimeout("tcp", tcpAddr, time.Second)
		if err != nil {
			continue
		}
		_ = c.SetDeadline(time.Now().Add(time.Second))
		// half the time send a bogus 2-byte length prefix, half send raw
		if len(p)%2 == 0 {
			var lp [2]byte
			binary.BigEndian.PutUint16(lp[:], uint16(rnd.Intn(70000)))
			_, _ = c.Write(lp[:])
		}
		_, _ = c.Write(p)
		c.Close()
	}

	// The proxy must still be alive and answer a valid query.
	client := dns.Client{Timeout: 3 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion("productpage.ns1.svc.cluster.local.", dns.TypeA)
	res, _, err := client.Exchange(m, udpAddr)
	if err != nil {
		t.Fatalf("proxy died / unresponsive after malformed traffic: %v", err)
	}
	if len(res.Answer) != 1 {
		t.Fatalf("expected 1 answer after survival, got %d: %v", len(res.Answer), res)
	}
	t.Logf("proxy survived %d malformed payloads and answered correctly", len(payloads))
}
