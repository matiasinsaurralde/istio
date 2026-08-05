package authzattach

import (
	"fmt"
	"testing"

	authpb "istio.io/api/security/v1beta1"
	"istio.io/api/label"
	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/serviceregistry/provider"
	"istio.io/istio/pkg/config/labels"
	"istio.io/istio/pkg/test"
)

// TestWaypointRootNs checks whether mesh-wide (root-ns) policies attach to a waypoint's
// per-service L7 authz layer, compared to a sidecar. Uses REAL ShouldAttachPolicy via ListAuthorizationPolicies.
func TestWaypointRootNs(t *testing.T) {
	test.SetForTest(t, &features.EnableSelectorBasedK8sGatewayPolicy, true) // DEFAULT

	sidecar := model.WorkloadPolicyMatcher{
		WorkloadNamespace: "app",
		WorkloadLabels:    labels.Instance{"app": "web"},
		IsWaypoint:        false,
		RootNamespace:     rootNS,
	}
	// waypoint per-service builder: IsWaypoint=true, serving svc web in app ns
	waypointPerSvc := model.WorkloadPolicyMatcher{
		WorkloadNamespace: "app",
		WorkloadLabels:    labels.Instance{label.IoK8sNetworkingGatewayGatewayName.Name: "app-waypoint"},
		IsWaypoint:        true,
		RootNamespace:     rootNS,
		Services:          []model.ServiceInfoForPolicyMatcher{{Name: "web", Namespace: "app", Registry: provider.Kubernetes}},
	}
	// waypoint HBONE termination builder: alwaysTreatAsNonWaypoint forces IsWaypoint=false, no Services
	waypointTermination := model.WorkloadPolicyMatcher{
		WorkloadNamespace: "app",
		WorkloadLabels:    labels.Instance{label.IoK8sNetworkingGatewayGatewayName.Name: "app-waypoint"},
		IsWaypoint:        false, // forced by alwaysTreatAsNonWaypoint
		RootNamespace:     rootNS,
	}

	meshWideNoSelectorDeny := buildAP(mkPolicy("mesh-deny", rootNS, authpb.AuthorizationPolicy_DENY, nil))
	meshWideSelectorDeny := buildAP(mkPolicy("mesh-sel-deny", rootNS, authpb.AuthorizationPolicy_DENY, map[string]string{"app": "web"}))

	report := func(label string, m model.WorkloadPolicyMatcher, ap *model.AuthorizationPolicies) {
		res := ap.ListAuthorizationPolicies(m)
		fmt.Printf("  %-42s DENY=%v\n", label, names(res.Deny))
	}

	fmt.Println("=== mesh-wide NO-SELECTOR DENY (root ns) ===")
	report("sidecar", sidecar, meshWideNoSelectorDeny)
	report("waypoint per-service (IsWaypoint=true)", waypointPerSvc, meshWideNoSelectorDeny)
	report("waypoint termination (IsWaypoint=false)", waypointTermination, meshWideNoSelectorDeny)

	fmt.Println("=== mesh-wide SELECTOR app=web DENY (root ns) ===")
	report("sidecar", sidecar, meshWideSelectorDeny)
	report("waypoint per-service (IsWaypoint=true)", waypointPerSvc, meshWideSelectorDeny)
	report("waypoint termination (IsWaypoint=false)", waypointTermination, meshWideSelectorDeny)
}
