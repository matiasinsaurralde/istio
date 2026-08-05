package caidentity

// Demonstrate that the REAL XfccAuthenticator.Authenticate panics when the gRPC
// peer address is a host:port whose host is not a parseable IP. This proves the
// vulnerable code path end-to-end. Reachability caveat: in a standard istiod
// deployment the gRPC peer is a *net.TCPAddr (numeric) or strAddr(r.RemoteAddr)
// (also numeric), so a non-IP host is not normally produced by the transport.

import (
	"context"
	"net"
	"testing"

	"github.com/alecholmes/xfccparser"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	"istio.io/istio/pkg/security"
	"istio.io/istio/security/pkg/server/ca/authenticate"
)

// fakeAddr is a net.Addr whose String() returns an attacker-shaped value.
type fakeAddr struct{ s string }

func (f fakeAddr) Network() string { return "tcp" }
func (f fakeAddr) String() string  { return f.s }

func callXfcc(t *testing.T, peerAddr string) (panicked any) {
	t.Helper()
	ctx := peer.NewContext(context.Background(), &peer.Peer{Addr: fakeAddr{peerAddr}})
	md := metadata.MD{}
	// Any well-formed XFCC header so we pass the len checks and reach isTrustedAddress.
	md.Append(xfccparser.ForwardedClientCertHeader,
		`URI=spiffe://cluster.local/ns/attacker/sa/attacker`)
	ctx = metadata.NewIncomingContext(ctx, md)

	auth := &authenticate.XfccAuthenticator{}
	defer func() {
		if r := recover(); r != nil {
			panicked = r
		}
	}()
	_, _ = auth.Authenticate(security.AuthContext{GrpcContext: ctx})
	return nil
}

func TestXfccRealAuthenticatorPanic(t *testing.T) {
	// Sanity: numeric peer does not panic (returns not-trusted since default CIDR empty).
	if p := callXfcc(t, "10.0.0.5:12345"); p != nil {
		t.Fatalf("unexpected panic for numeric peer: %v", p)
	} else {
		t.Logf("numeric peer 10.0.0.5:12345 -> no panic (as expected)")
	}

	// Non-IP host peer addresses -> real code panics at netip.MustParseAddr.
	for _, addr := range []string{"gateway:15012", ":15012"} {
		p := callXfcc(t, addr)
		if p == nil {
			t.Errorf("expected panic for peer %q, got none", addr)
			continue
		}
		t.Logf("CONFIRMED real XfccAuthenticator.Authenticate panics for peer=%q: %v", addr, p)
	}
}

var _ = net.TCPAddr{}
