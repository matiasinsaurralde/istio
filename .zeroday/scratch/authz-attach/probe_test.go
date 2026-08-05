// Package authzattach exercises the REAL Istio policy attachment code paths
// (model.AuthorizationPolicies.ListAuthorizationPolicies -> WorkloadPolicyMatcher.ShouldAttachPolicy).
// LOCAL analysis only. Run: go test -run TestProbe -v ./.zeroday/scratch/authz-attach/
package authzattach

import (
	"fmt"
	"testing"

	authpb "istio.io/api/security/v1beta1"
	typev1beta1 "istio.io/api/type/v1beta1"
	"istio.io/api/label"
	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/serviceregistry/provider"
	"istio.io/istio/pkg/config/constants"
	"istio.io/istio/pkg/config/labels"
	"istio.io/istio/pkg/config/schema/gvk"
	"istio.io/istio/pkg/test"
)

const rootNS = "istio-system"

// mkPolicy builds a real model.AuthorizationPolicy wrapping a real proto spec.
func mkPolicy(name, ns string, action authpb.AuthorizationPolicy_Action, sel map[string]string, targetRefs ...*typev1beta1.PolicyTargetReference) model.AuthorizationPolicy {
	spec := &authpb.AuthorizationPolicy{Action: action}
	if sel != nil {
		spec.Selector = &typev1beta1.WorkloadSelector{MatchLabels: sel}
	}
	if len(targetRefs) == 1 {
		spec.TargetRef = targetRefs[0]
	} else if len(targetRefs) > 1 {
		spec.TargetRefs = targetRefs
	}
	return model.AuthorizationPolicy{Name: name, Namespace: ns, Spec: spec}
}

func tr(group, kind, name string) *typev1beta1.PolicyTargetReference {
	return &typev1beta1.PolicyTargetReference{Group: group, Kind: kind, Name: name}
}

// buildAP assembles a real AuthorizationPolicies struct keyed by namespace.
func buildAP(policies ...model.AuthorizationPolicy) *model.AuthorizationPolicies {
	ap := &model.AuthorizationPolicies{
		NamespaceToPolicies: map[string][]model.AuthorizationPolicy{},
		RootNamespace:       rootNS,
	}
	for _, p := range policies {
		ap.NamespaceToPolicies[p.Namespace] = append(ap.NamespaceToPolicies[p.Namespace], p)
	}
	return ap
}

func names(ps []model.AuthorizationPolicy) []string {
	out := []string{}
	for _, p := range ps {
		out = append(out, p.Namespace+"/"+p.Name)
	}
	return out
}

// TestProbe enumerates attachment for a set of interesting proxy/policy combos and prints results.
func TestProbe(t *testing.T) {
	test.SetForTest(t, &features.EnableSelectorBasedK8sGatewayPolicy, true) // DEFAULT

	// A regular sidecar workload in ns "app", labels app=web.
	sidecar := model.WorkloadPolicyMatcher{
		WorkloadNamespace: "app",
		WorkloadLabels:    labels.Instance{"app": "web"},
		IsWaypoint:        false,
		RootNamespace:     rootNS,
	}
	// A Gateway-API gateway workload (has gateway-name label).
	gw := model.WorkloadPolicyMatcher{
		WorkloadNamespace: "app",
		WorkloadLabels:    labels.Instance{label.IoK8sNetworkingGatewayGatewayName.Name: "my-gw", "app": "web"},
		IsWaypoint:        false,
		RootNamespace:     rootNS,
	}
	// A waypoint proxy serving service "web" in ns "app".
	wp := model.WorkloadPolicyMatcher{
		WorkloadNamespace: "app",
		WorkloadLabels:    labels.Instance{label.IoK8sNetworkingGatewayGatewayName.Name: "app-waypoint"},
		IsWaypoint:        true,
		RootNamespace:     rootNS,
		Services:          []model.ServiceInfoForPolicyMatcher{{Name: "web", Namespace: "app", Registry: provider.Kubernetes}},
	}

	scenarios := []struct {
		name string
		m    model.WorkloadPolicyMatcher
		ap   *model.AuthorizationPolicies
	}{
		{
			"sidecar: root DENY no-selector (mesh-wide)",
			sidecar,
			buildAP(mkPolicy("mesh-deny", rootNS, authpb.AuthorizationPolicy_DENY, nil)),
		},
		{
			"sidecar: root DENY selector app=web",
			sidecar,
			buildAP(mkPolicy("mesh-deny", rootNS, authpb.AuthorizationPolicy_DENY, map[string]string{"app": "web"})),
		},
		{
			"sidecar: ns DENY selector app=web",
			sidecar,
			buildAP(mkPolicy("ns-deny", "app", authpb.AuthorizationPolicy_DENY, map[string]string{"app": "web"})),
		},
		{
			"sidecar: DENY with targetRef Service (should be ignored for sidecar)",
			sidecar,
			buildAP(mkPolicy("t-deny", "app", authpb.AuthorizationPolicy_DENY, nil, tr("", "Service", "web"))),
		},
		{
			"gw: DENY targetRef Gateway/my-gw",
			gw,
			buildAP(mkPolicy("gw-deny", "app", authpb.AuthorizationPolicy_DENY, nil, tr(gvk.KubernetesGateway.Group, "Gateway", "my-gw"))),
		},
		{
			"gw: DENY selector app=web (flag=true default -> attaches)",
			gw,
			buildAP(mkPolicy("gw-sel-deny", "app", authpb.AuthorizationPolicy_DENY, map[string]string{"app": "web"})),
		},
		{
			"waypoint: DENY targetRef Service/web",
			wp,
			buildAP(mkPolicy("wp-svc-deny", "app", authpb.AuthorizationPolicy_DENY, nil, tr("", "Service", "web"))),
		},
		{
			"waypoint: DENY targetRef Gateway/app-waypoint",
			wp,
			buildAP(mkPolicy("wp-gw-deny", "app", authpb.AuthorizationPolicy_DENY, nil, tr(gvk.KubernetesGateway.Group, "Gateway", "app-waypoint"))),
		},
		{
			"waypoint: DENY selector (ignored for waypoint per-service)",
			wp,
			buildAP(mkPolicy("wp-sel-deny", "app", authpb.AuthorizationPolicy_DENY, map[string]string{label.IoK8sNetworkingGatewayGatewayName.Name: "app-waypoint"})),
		},
		{
			"waypoint: root GatewayClass/istio-waypoint DENY (mesh-wide waypoint)",
			wp,
			buildAP(mkPolicy("wp-class-deny", rootNS, authpb.AuthorizationPolicy_DENY, nil, tr(gvk.GatewayClass.Group, "GatewayClass", constants.WaypointGatewayClassName))),
		},
	}

	for _, s := range scenarios {
		res := s.ap.ListAuthorizationPolicies(s.m)
		fmt.Printf("[%s]\n  DENY=%v ALLOW=%v AUDIT=%v CUSTOM=%v\n", s.name, names(res.Deny), names(res.Allow), names(res.Audit), names(res.Custom))
	}
}
