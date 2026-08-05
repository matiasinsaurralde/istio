package authzattach

import (
	"fmt"
	"math/rand"
	"testing"

	typev1beta1 "istio.io/api/type/v1beta1"
	"istio.io/api/label"
	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/serviceregistry/provider"
	"istio.io/istio/pkg/config"
	"istio.io/istio/pkg/config/constants"
	"istio.io/istio/pkg/config/labels"
	"istio.io/istio/pkg/config/schema/gvk"
	"istio.io/istio/pkg/test"
	"k8s.io/apimachinery/pkg/types"
)

// mock policy implementing model.TargetablePolicy
type mockPol struct {
	sel    *typev1beta1.WorkloadSelector
	refs   []*typev1beta1.PolicyTargetReference
	single *typev1beta1.PolicyTargetReference
}

func (m *mockPol) GetTargetRef() *typev1beta1.PolicyTargetReference   { return m.single }
func (m *mockPol) GetTargetRefs() []*typev1beta1.PolicyTargetReference { return m.refs }
func (m *mockPol) GetSelector() *typev1beta1.WorkloadSelector         { return m.sel }

// effRefs mirrors model.GetTargetRefs: prefer plural, fall back to singular.
func (m *mockPol) effRefs() []*typev1beta1.PolicyTargetReference {
	if len(m.refs) == 0 && m.single != nil {
		return []*typev1beta1.PolicyTargetReference{m.single}
	}
	return m.refs
}

// independent reference derived from documented Istio semantics.
func refAttach(policyNS string, m *mockPol, p model.WorkloadPolicyMatcher, flag bool) bool {
	gwName, hasGw := p.WorkloadLabels[label.IoK8sNetworkingGatewayGatewayName.Name]
	refs := m.effRefs()
	subset := func(sel map[string]string) bool { return labels.Instance(sel).SubsetOf(p.WorkloadLabels) }
	sel := m.sel.GetMatchLabels()
	if !hasGw {
		if len(refs) > 0 {
			return false
		}
		if m.sel == nil {
			return true
		}
		return subset(sel)
	}
	if len(refs) == 0 {
		if p.IsWaypoint || !flag {
			return false
		}
		if m.sel == nil {
			return true
		}
		return subset(sel)
	}
	canon := func(g string) string {
		if g == "" {
			return "core"
		}
		return g
	}
	for _, r := range refs {
		if p.IsWaypoint && canon(r.Group) == "core" && r.Kind == "Service" {
			for _, s := range p.Services {
				if r.Name == s.Name && policyNS == s.Namespace && s.Registry == provider.Kubernetes {
					return true
				}
			}
		}
		if p.IsWaypoint && canon(r.Group) == "networking.istio.io" && r.Kind == "ServiceEntry" {
			for _, s := range p.Services {
				if r.Name == s.Name && policyNS == s.Namespace && s.Registry == provider.External {
					return true
				}
			}
		}
		if policyNS == p.RootNamespace && p.IsWaypoint && canon(r.Group) == "gateway.networking.k8s.io" && r.Kind == "GatewayClass" && r.Name == constants.WaypointGatewayClassName {
			return true
		}
		if p.WorkloadNamespace != policyNS {
			continue
		}
		if !(r.Namespace == "" || r.Namespace == p.WorkloadNamespace) {
			continue
		}
		if canon(r.Group) == "gateway.networking.k8s.io" && r.Kind == "Gateway" && r.Name == gwName {
			return true
		}
	}
	return false
}

func TestDiffFuzz(t *testing.T) {
	rng := rand.New(rand.NewSource(0xC0FFEE))
	namespaces := []string{"app", "app", "istio-system", "other", ""}
	names := []string{"web", "api", "app-waypoint", "other-gw", constants.WaypointGatewayClassName, ""}
	groups := []string{"", "core", "gateway.networking.k8s.io", "networking.istio.io", "wrong"}
	kinds := []string{"Service", "ServiceEntry", "Gateway", "GatewayClass", "Wrong"}
	refNS := []string{"", "app", "other"}
	labelKeys := []string{"app", label.IoK8sNetworkingGatewayGatewayName.Name, "team"}
	labelVals := []string{"web", "api", "app-waypoint", "x"}

	randLabels := func() map[string]string {
		out := map[string]string{}
		n := rng.Intn(3)
		for i := 0; i < n; i++ {
			out[labelKeys[rng.Intn(len(labelKeys))]] = labelVals[rng.Intn(len(labelVals))]
		}
		return out
	}
	randRef := func() *typev1beta1.PolicyTargetReference {
		return &typev1beta1.PolicyTargetReference{
			Group:     groups[rng.Intn(len(groups))],
			Kind:      kinds[rng.Intn(len(kinds))],
			Name:      names[rng.Intn(len(names))],
			Namespace: refNS[rng.Intn(len(refNS))],
		}
	}

	rootNSv := "istio-system"
	mockKind := config.GroupVersionKind{Group: "mock.istio.io", Version: "v1", Kind: "MockKind"}
	_ = gvk.AuthorizationPolicy

	diverged := 0
	const N = 3_000_000
	for i := 0; i < N; i++ {
		flag := rng.Intn(2) == 0
		test.SetForTest(t, &features.EnableSelectorBasedK8sGatewayPolicy, flag)

		m := &mockPol{}
		switch rng.Intn(4) {
		case 0:
			m.sel = &typev1beta1.WorkloadSelector{MatchLabels: randLabels()}
		case 1:
			nrefs := rng.Intn(3)
			for j := 0; j < nrefs; j++ {
				m.refs = append(m.refs, randRef())
			}
		case 2:
			// singular targetRef fallback path (exercises model.GetTargetRefs)
			m.single = randRef()
		case 3:
			// neither
		}

		wlLabels := randLabels()
		p := model.WorkloadPolicyMatcher{
			WorkloadNamespace: namespaces[rng.Intn(len(namespaces))],
			WorkloadLabels:    wlLabels,
			IsWaypoint:        rng.Intn(2) == 0,
			RootNamespace:     rootNSv,
		}
		// random services
		ns := rng.Intn(3)
		for j := 0; j < ns; j++ {
			reg := provider.Kubernetes
			if rng.Intn(2) == 0 {
				reg = provider.External
			}
			p.Services = append(p.Services, model.ServiceInfoForPolicyMatcher{
				Name:      names[rng.Intn(len(names))],
				Namespace: namespaces[rng.Intn(len(namespaces))],
				Registry:  reg,
			})
		}
		policyNS := namespaces[rng.Intn(len(namespaces))]
		nsName := types.NamespacedName{Name: "p", Namespace: policyNS}

		got := p.ShouldAttachPolicy(mockKind, nsName, m)
		want := refAttach(policyNS, m, p, flag)
		if got != want {
			diverged++
			if diverged <= 20 {
				fmt.Printf("DIVERGE got=%v want=%v flag=%v policyNS=%q sel=%v refs=%v\n  proxy: ns=%q wp=%v labels=%v svcs=%v\n",
					got, want, flag, policyNS, m.sel, m.refs, p.WorkloadNamespace, p.IsWaypoint, p.WorkloadLabels, p.Services)
			}
		}
	}
	fmt.Printf("N=%d diverged=%d\n", N, diverged)
	if diverged > 0 {
		t.Fatalf("found %d divergences between real ShouldAttachPolicy and reference", diverged)
	}
}
