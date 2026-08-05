package caidentity

// Probe: enumerate peer-address strings to find which ones cause
// isTrustedAddress()/isInRange() in xfcc_authenticator.go to PANIC via
// netip.MustParseAddr(ip). We replicate the exact stdlib call sequence used by
// the real code:
//
//   ip, _, err := net.SplitHostPort(addr)   // if err -> returns false, safe
//   ... netip.MustParseAddr(ip)              // panics if ip is not a valid IP
//
// A peer address is "dangerous" iff SplitHostPort succeeds AND netip.ParseAddr(ip) fails.

import (
	"net"
	"net/netip"
	"testing"
)

func splitThenParsePanics(addr string) (dangerous bool, host string, splitErr error) {
	host, _, splitErr = net.SplitHostPort(addr)
	if splitErr != nil {
		return false, host, splitErr // real code returns false here -> safe
	}
	if _, err := netip.ParseAddr(host); err != nil {
		return true, host, nil // MustParseAddr would panic on this host
	}
	return false, host, nil
}

func TestXfccDangerousPeerAddresses(t *testing.T) {
	candidates := []string{
		// normal, safe
		"127.0.0.1:2301",
		"10.1.2.3:15012",
		"[2001:db8::1]:80",
		"[fe80::1%eth0]:80", // ipv6 zone
		"1.2.3.4",           // no port -> split err -> safe
		// suspicious
		":15012",         // empty host
		"[]:15012",       // empty host in brackets
		"gateway:15012",  // hostname
		"localhost:15012",// hostname
		"example.com:80", // hostname
		"unix:1234",      // hostname-ish
		"@:0",            // abstract-ish
		"[::]:0",         // unspecified ipv6 (valid)
		":0",             // empty host
	}
	for _, c := range candidates {
		dangerous, host, splitErr := splitThenParsePanics(c)
		status := "safe"
		if dangerous {
			status = "*** DANGEROUS (would panic netip.MustParseAddr) ***"
		}
		t.Logf("addr=%-22q -> host=%-14q splitErr=%v : %s", c, host, splitErr, status)
	}
}

// Confirm the panic actually fires through the same call netip.MustParseAddr uses.
func TestNetipMustParseAddrPanics(t *testing.T) {
	for _, host := range []string{"", "gateway", "example.com"} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Logf("CONFIRMED netip.MustParseAddr(%q) panics: %v", host, r)
					return
				}
				t.Errorf("netip.MustParseAddr(%q) did NOT panic", host)
			}()
			_ = netip.MustParseAddr(host)
		}()
	}
}
