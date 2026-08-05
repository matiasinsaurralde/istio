// ZERO-DAY AUDIT reproducer: fork's custom debug-endpoint namespace authorization.
// Internal (package xds) test so it can drive the ACTUAL unexported code paths:
//   getDebugConnection / getProxyConnection / ConfigDump / DebugGen.Generate
// Canonical copy kept under .zeroday/scratch/debug-auth/ ; this copy lives in the
// package dir because Go requires internal tests to sit beside the package.
package xds

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pilot/pkg/model"
	v3 "istio.io/istio/pilot/pkg/xds/v3"
	"istio.io/istio/pkg/spiffe"
	"istio.io/istio/pkg/util/sets"
)

// buildServerWithProxies constructs a minimal but REAL DiscoveryServer and registers
// two connected proxies in different namespaces (team-a attacker, team-b victim).
func buildServerWithProxies(t *testing.T) (*DiscoveryServer, *Connection, *Connection) {
	t.Helper()
	s := &DiscoveryServer{
		adsClients:    map[string]*Connection{},
		debugHandlers: map[string]string{},
		// Env left nil on purpose: getDebugConnection falls back to
		// constants.IstioSystemNamespace ("istio-system") when Env is nil.
	}

	mk := func(id, ns string) *Connection {
		p := &model.Proxy{
			Type:            model.SidecarProxy,
			ID:              id,
			ConfigNamespace: ns,
			Metadata:        &model.NodeMetadata{Namespace: ns},
		}
		c := newConnection("10.0.0.1:1111", nil)
		c.s = s
		c.proxy = p
		c.SetID(connectionID(p.ID))
		c.MarkInitialized()
		s.addCon(c.ID(), c)
		return c
	}

	conA := mk("podA.team-a", "team-a") // attacker's own connection
	conB := mk("podB.team-b", "team-b") // victim in another namespace
	return s, conA, conB
}

// reqWithNS mimics what allowAuthenticatedOrLocalhost (HTTP path) and processDebugRequest
// (XDS path) both do: stash the caller namespace under CallerNamespaceKey{}.
func reqWithNS(target, callerNS string, setNS bool) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/debug/config_dump?proxyID="+target, nil)
	if setNS {
		r = r.WithContext(context.WithValue(r.Context(), CallerNamespaceKey{}, callerNS))
	}
	return r
}

// TestCore_getDebugConnection exercises the exact gate the whole family relies on.
func TestCore_getDebugConnection(t *testing.T) {
	if !features.EnableDebugEndpointAuth {
		t.Fatal("ENABLE_DEBUG_ENDPOINT_AUTH default should be true")
	}
	s, _, conB := buildServerWithProxies(t)
	_ = conB

	cases := []struct {
		name      string
		target    string // proxyID query value (substring-matched against con.ID())
		callerNS  string
		setNS     bool
		wantAllow bool
	}{
		{"cross-ns denied (attacker team-a -> victim team-b)", "podB.team-b", "team-a", true, false},
		{"same-ns allowed (team-b -> team-b)", "podB.team-b", "team-b", true, true},
		{"substring proxyID 'team-b' still namespace-checked", "team-b", "team-a", true, false},
		{"substring proxyID 'podB' still namespace-checked", "podB", "team-a", true, false},
		{"system-ns caller bypasses (allowed by design)", "podB.team-b", "istio-system", true, true},
		{"EMPTY callerNS skips the gate (latent bypass)", "podB.team-b", "", true, true},
		{"no ns in context (localhost path) skips the gate", "podB.team-b", "", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := reqWithNS(tc.target, tc.callerNS, tc.setNS)
			proxyID, con := s.getDebugConnection(req)
			gotAllow := con != nil
			if gotAllow != tc.wantAllow {
				t.Fatalf("target=%q callerNS=%q setNS=%v => allow=%v (con=%v), want allow=%v",
					tc.target, tc.callerNS, tc.setNS, gotAllow, con, tc.wantAllow)
			}
			t.Logf("target=%q callerNS=%q setNS=%v => proxyID=%q allow=%v", tc.target, tc.callerNS, tc.setNS, proxyID, gotAllow)
		})
	}
}

// TestXDSPath_DebugGen drives the full XDS DebugType path end to end via the real
// DebugGen.Generate -> processDebugRequest -> internalMux -> ConfigDump -> getDebugConnection.
func TestXDSPath_DebugGen(t *testing.T) {
	s, _, conB := buildServerWithProxies(t)
	internalMux := s.InitDebug(http.NewServeMux(), false, nil)
	dg := NewDebugGen(s, "istio-system", internalMux)

	victimTarget := "podB.team-b" // substring of conB.ID()
	if !strings.Contains(conB.ID(), victimTarget) {
		t.Fatalf("precondition: conB.ID()=%q must contain %q", conB.ID(), victimTarget)
	}

	run := func(callerNS string) string {
		proxyA := &model.Proxy{
			Type:            model.SidecarProxy,
			ID:              "podA.team-a",
			ConfigNamespace: "team-a",
			Metadata:        &model.NodeMetadata{Namespace: "team-a"},
			VerifiedIdentity: &spiffe.Identity{
				TrustDomain: "cluster.local", Namespace: callerNS, ServiceAccount: "sa-a",
			},
		}
		// types=eds keeps ConfigDump on the light path (no nil LastPushContext deref)
		// while still proving whether the gate was passed.
		w := &model.WatchedResource{
			TypeUrl:       v3.DebugType,
			ResourceNames: sets.New("config_dump?proxyID=" + victimTarget + "&types=eds"),
		}
		res, _, err := dg.Generate(proxyA, w, &model.PushRequest{Forced: true})
		if err != nil {
			return "ERR:" + err.Error()
		}
		if len(res) != 1 {
			t.Fatalf("expected 1 resource, got %d", len(res))
		}
		return string(res[0].Resource.Value)
	}

	// Attacker: real mesh cert => VerifiedIdentity.Namespace == "team-a".
	body := run("team-a")
	t.Logf("cross-ns (caller team-a) response body: %s", body)
	if !strings.Contains(body, "Proxy not connected") {
		t.Fatalf("CROSS-NAMESPACE LEAK: caller team-a got a config_dump for team-b proxy: %s", body)
	}

	// Latent bypass demonstration: IF an identity with empty namespace were presented,
	// the gate is skipped and the victim's dump is returned.
	bodyEmpty := run("")
	t.Logf("empty-ns caller response body: %s", bodyEmpty)
	if strings.Contains(bodyEmpty, "Proxy not connected") {
		t.Logf("empty-ns did NOT reach the victim (gate held)")
	} else {
		t.Logf("empty-ns REACHED the victim proxy (gate skipped) -> latent bypass confirmed at code level")
	}
}
