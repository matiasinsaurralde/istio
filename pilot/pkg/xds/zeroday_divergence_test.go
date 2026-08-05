package xds

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"istio.io/istio/pilot/pkg/model"
	v3 "istio.io/istio/pilot/pkg/xds/v3"
	"istio.io/istio/pkg/spiffe"
	"istio.io/istio/pkg/util/sets"
)

// safeAllowlist replicates parseAndValidateDebugRequest's allowlist decision, capturing any
// panic (the real code does `u, _ := url.Parse(...)` then `u.Path` with no nil/err check).
func safeAllowlist(resourceName string) (allowed bool, panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			panicked = true
		}
	}()
	u, _ := url.Parse(resourceName)
	debugType := u.Path
	_, allowed = activeNamespaceDebuggers[debugType]
	return
}

// TestAllowlistVsDispatch prints, for each crafted resourceName, the allowlist verdict vs the
// handler the internal mux actually dispatches, and flags divergences + parser panics.
func TestAllowlistVsDispatch(t *testing.T) {
	s := &DiscoveryServer{adsClients: map[string]*Connection{}, debugHandlers: map[string]string{}}
	internalMux := s.InitDebug(http.NewServeMux(), true, func() map[string]string { return nil })

	candidates := []string{
		"config_dump", "config_dump?proxyID=x", "config_dump#/../mesh",
		"config_dump/../configz", "config_dump%2f..%2fconfigz", "config_dump;/../mesh",
		"config_dump ", "config_dump\t", "config_dump\n", "config_dump\x7f",
		"config_dump%zz", "config_dump%", "config_dump%2", "%00", "\x00",
		"./config_dump", "config_dump/", "ndsz", "edsz", "configz", "mesh", "syncz",
	}

	for _, name := range candidates {
		allowed, panicked := safeAllowlist(name)
		pattern, dpanic := dispatchPattern(internalMux, name)
		flag := ""
		if panicked {
			flag = "  <-- ALLOWLIST PANIC (nil deref)"
		} else if allowed && !isGatedPattern(pattern) {
			flag = "  <-- DIVERGENCE (allowed name -> non-gated handler)"
		}
		t.Logf("name=%-20q allow=%-5v panic=%-5v -> pattern=%-22q %s%s", name, allowed, panicked, pattern, dpanic, flag)
		if allowed && !panicked && !isGatedPattern(pattern) {
			t.Errorf("BYPASS: %q passes allowlist but dispatches to non-gated %q", name, pattern)
		}
	}
}

func dispatchPattern(mux *http.ServeMux, resourceName string) (pattern, desc string) {
	defer func() {
		if r := recover(); r != nil {
			desc = fmt.Sprintf("dispatch panic: %v", r)
		}
	}()
	hreq, err := http.NewRequest(http.MethodGet, "/debug/"+resourceName, nil)
	if err != nil {
		return "", "NEWREQ_ERR:" + err.Error()
	}
	_, pattern = mux.Handler(hreq)
	return pattern, "path=" + hreq.URL.Path
}

func isGatedPattern(p string) bool {
	return p == "/debug/config_dump" || p == "/debug/ndsz" || p == "/debug/edsz"
}

// TestRealParseAndValidatePanic drives the ACTUAL parseAndValidateDebugRequest with a resource
// name that url.Parse rejects, proving the real function nil-derefs. Reachable by ANY mesh
// workload over XDS (validateProxyAuthentication only needs VerifiedIdentity + 1 resource name).
func TestRealParseAndValidatePanic(t *testing.T) {
	s := &DiscoveryServer{adsClients: map[string]*Connection{}, debugHandlers: map[string]string{}}
	internalMux := s.InitDebug(http.NewServeMux(), false, nil)
	dg := NewDebugGen(s, "istio-system", internalMux)

	proxy := &model.Proxy{
		Type: model.SidecarProxy, ID: "podA.team-a", ConfigNamespace: "team-a",
		Metadata:         &model.NodeMetadata{Namespace: "team-a"},
		VerifiedIdentity: &spiffe.Identity{TrustDomain: "cluster.local", Namespace: "team-a", ServiceAccount: "sa-a"},
	}
	// A tab is a raw control char -> url.Parse returns (nil, err).
	w := &model.WatchedResource{TypeUrl: v3.DebugType, ResourceNames: sets.New("config_dump\t")}

	// 1) Direct call to the real unexported function.
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("CONFIRMED: real parseAndValidateDebugRequest panicked: %v", r)
			} else {
				t.Errorf("expected panic from parseAndValidateDebugRequest, got none")
			}
		}()
		_, _ = parseAndValidateDebugRequest(proxy, w, dg)
	}()

	// 2) Full generator entry point DebugGen.Generate (the exact XDS dispatch target).
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("CONFIRMED: real DebugGen.Generate panicked (istiod would crash: no recover in gRPC stream path): %v", r)
			} else {
				t.Errorf("expected panic from DebugGen.Generate, got none")
			}
		}()
		_, _, _ = dg.Generate(proxy, w, &model.PushRequest{Forced: true})
	}()
}
