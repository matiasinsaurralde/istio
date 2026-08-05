// Zero-day audit fuzz harness. Drives the REAL ServeDNS / lookupHost handler.
// Placed in package client to reach the unexported dnsProxy + handler internals.
package client

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"

	dnsProto "istio.io/istio/pkg/dns/proto"
)

// fakeRW is a dns.ResponseWriter that actually packs the response, exercising
// the full response-building + Pack path (like a real writer would), but never
// touches the network.
type fakeRW struct{}

func (fakeRW) LocalAddr() net.Addr        { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53} }
func (fakeRW) RemoteAddr() net.Addr       { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5000} }
func (fakeRW) WriteMsg(m *dns.Msg) error  { _, err := m.Pack(); return err }
func (fakeRW) Write(b []byte) (int, error) { return len(b), nil }
func (fakeRW) Close() error               { return nil }
func (fakeRW) TsigStatus() error          { return nil }
func (fakeRW) TsigTimersOnly(bool)        {}
func (fakeRW) Hijack()                    {}

// buildFuzzServer builds a LocalDNSServer with a rich table (wildcards, cnames,
// headless multi-IP, dual-stack) and NO upstream servers (so cache-miss returns
// SERVFAIL locally with zero network I/O).
func buildFuzzServer(tb testing.TB) *LocalDNSServer {
	tb.Helper()
	h, err := NewLocalDNSServer("ns1", "ns1.svc.cluster.local", "localhost:0")
	if err != nil {
		tb.Fatal(err)
	}
	// No upstream -> queryUpstream returns serverFailure without touching the net.
	h.resolvConfServers = nil
	h.searchNamespaces = []string{"ns1.svc.cluster.local", "svc.cluster.local", "cluster.local"}
	h.UpdateLookupTable(&dnsProto.NameTable{
		Table: map[string]*dnsProto.NameTable_NameInfo{
			"www.google.com":                    {Ips: []string{"1.1.1.1"}, Registry: "External"},
			"productpage.ns1.svc.cluster.local": {Ips: []string{"9.9.9.9"}, Registry: "Kubernetes", Namespace: "ns1", Shortname: "productpage"},
			"example.ns2.svc.cluster.local":     {Ips: []string{"10.10.10.10"}, Registry: "Kubernetes", Namespace: "ns2", Shortname: "example"},
			"details.ns2.svc.cluster.remote":    {Ips: []string{"11.11.11.11", "12.12.12.12", "13.13.13.13", "14.14.14.14"}, Registry: "Kubernetes", Namespace: "ns2", Shortname: "details"},
			"dual.localhost":                    {Ips: []string{"2.2.2.2", "2001:db8::ff00:42:8329"}, Registry: "External"},
			"*.b.wildcard":                      {Ips: []string{"11.11.11.11"}, Registry: "External"},
			"*.wildcard":                        {Ips: []string{"10.10.10.10"}, Registry: "External"},
			"*.svc.mesh.company.net":            {Ips: []string{"10.1.2.3"}, Registry: "External"},
			"example.localhost.":                {Ips: []string{"3.3.3.3"}, Registry: "External"},
		},
	})
	return h
}

func fuzzProxies(h *LocalDNSServer) []*dnsProxy {
	return []*dnsProxy{
		{protocol: "udp", resolver: h, upstreamClient: &dns.Client{Net: "udp", DialTimeout: time.Millisecond}},
		{protocol: "tcp", resolver: h, upstreamClient: &dns.Client{Net: "tcp", DialTimeout: time.Millisecond}},
	}
}

// FuzzServeDNSRaw feeds arbitrary bytes: unpack via miekg (real wire parser),
// then drive the real ServeDNS with the resulting message over udp + tcp.
func FuzzServeDNSRaw(f *testing.F) {
	h := buildFuzzServer(f)
	proxies := fuzzProxies(h)
	rw := fakeRW{}

	seed := func(name string, qtype uint16, edns bool) {
		m := new(dns.Msg)
		m.SetQuestion(name, qtype)
		if edns {
			m.SetEdns0(4096, false)
		}
		if b, err := m.Pack(); err == nil {
			f.Add(b)
		}
	}
	seed("productpage.ns1.svc.cluster.local.", dns.TypeA, false)
	seed("foo.wildcard.", dns.TypeA, false)
	seed("a.b.wildcard.", dns.TypeAAAA, false)
	seed("foo.svc.mesh.company.net.ns1.svc.cluster.local.", dns.TypeA, true)
	seed("dual.localhost.", dns.TypeAAAA, false)
	seed("www.bing.com.", dns.TypeA, false)          // cache miss
	seed(".", dns.TypeA, false)                       // root
	seed("productpage.ns1.svc.cluster.local.", dns.TypeANY, false)

	f.Fuzz(func(t *testing.T, data []byte) {
		req := new(dns.Msg)
		if err := req.Unpack(data); err != nil {
			return
		}
		for _, p := range proxies {
			// req is mutated (SetReply shares slices); use a fresh copy per proxy.
			h.ServeDNS(p, rw, req.Copy())
		}
	})
}

// FuzzServeDNSStructured builds the message from a fuzzed qname + qtype so the
// engine can reach lookupHost/response-building without needing a valid wire packet.
func FuzzServeDNSStructured(f *testing.F) {
	h := buildFuzzServer(f)
	proxies := fuzzProxies(h)
	rw := fakeRW{}

	f.Add("productpage.ns1.svc.cluster.local.", uint16(dns.TypeA), true, false)
	f.Add("foo.wildcard.ns1.svc.cluster.local.", uint16(dns.TypeA), false, false)
	f.Add("a.b.c.d.e.f.g.wildcard.", uint16(dns.TypeAAAA), false, true)
	f.Add("....", uint16(dns.TypeA), false, false)
	f.Add("*.wildcard.", uint16(dns.TypeA), false, false)

	f.Fuzz(func(t *testing.T, name string, qtype uint16, edns bool, tcp bool) {
		m := new(dns.Msg)
		m.Question = []dns.Question{{Name: name, Qtype: qtype, Qclass: dns.ClassINET}}
		m.Id = dns.Id()
		if edns {
			m.SetEdns0(4096, false)
		}
		p := proxies[0]
		if tcp {
			p = proxies[1]
		}
		h.ServeDNS(p, rw, m)
	})
}

// FuzzLookupHost hammers the name-table lookup + wildcard/cname expansion directly.
func FuzzLookupHost(f *testing.F) {
	h := buildFuzzServer(f)
	lt := h.lookupTable.Load().(*LookupTable)

	f.Add("productpage.ns1.svc.cluster.local.", uint16(dns.TypeA))
	f.Add("foo.wildcard.", uint16(dns.TypeA))
	f.Add("a.b.c.wildcard.", uint16(dns.TypeAAAA))
	f.Add(".", uint16(dns.TypeA))
	f.Add("", uint16(dns.TypeA))
	f.Add("*.*.*.*.", uint16(dns.TypeA))

	f.Fuzz(func(t *testing.T, hostname string, qtype uint16) {
		_, _ = lt.lookupHost(qtype, hostname)
	})
}

// FuzzBuildDNSAnswers exercises search-domain expansion / alt-host generation
// with adversarial host + namespace strings.
func FuzzBuildDNSAnswers(f *testing.F) {
	f.Add("productpage.", "ns1.svc.cluster.local", "ns1", "ns1.svc.cluster.local")
	f.Add("a.b.", "", "", "")
	f.Add(".", ".", ".", ".")

	f.Fuzz(func(t *testing.T, host, search, ns, domain string) {
		h, err := NewLocalDNSServer(ns, domain, "localhost:0")
		if err != nil {
			return
		}
		h.searchNamespaces = []string{search}
		lt := &LookupTable{
			allHosts: map[string]struct{}{},
			name4:    map[string][]dns.RR{},
			name6:    map[string][]dns.RR{},
			cname:    map[string][]dns.RR{},
		}
		lt.buildDNSAnswers(map[string]struct{}{host: {}}, []netip.Addr{netip.MustParseAddr("1.2.3.4")}, nil, h.searchNamespaces)
	})
}
