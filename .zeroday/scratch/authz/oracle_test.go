package authzrepro

import (
	"regexp"
	"strings"
	"testing"

	rbacpb "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	matcherpb "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"k8s.io/apimachinery/pkg/types"

	authzpb "istio.io/api/security/v1beta1"
	authzmodel "istio.io/istio/pilot/pkg/security/authz/model"
)

// simEnvoyStringMatch simulates how Envoy evaluates a StringMatcher against s.
func simEnvoyStringMatch(t *testing.T, m *matcherpb.StringMatcher, s string) bool {
	t.Helper()
	ic := m.GetIgnoreCase()
	norm := func(x string) string {
		if ic {
			return strings.ToLower(x)
		}
		return x
	}
	switch p := m.GetMatchPattern().(type) {
	case *matcherpb.StringMatcher_Exact:
		return norm(p.Exact) == norm(s)
	case *matcherpb.StringMatcher_Prefix:
		return strings.HasPrefix(norm(s), norm(p.Prefix))
	case *matcherpb.StringMatcher_Suffix:
		return strings.HasSuffix(norm(s), norm(p.Suffix))
	case *matcherpb.StringMatcher_SafeRegex:
		// Envoy RE2 does a FULL match.
		re := regexp.MustCompile("^(?:" + p.SafeRegex.GetRegex() + ")$")
		return re.MatchString(s)
	default:
		t.Fatalf("unhandled string matcher: %+v", m)
		return false
	}
}

// extractAuthenticatedMatcher pulls the StringMatcher out of a principal produced
// by the identity generators (authenticated / filter_state).
func extractAuthenticatedMatcher(t *testing.T, p *rbacpb.Principal) *matcherpb.StringMatcher {
	t.Helper()
	if a := p.GetAuthenticated(); a != nil {
		return a.GetPrincipalName()
	}
	if fs := p.GetFilterState(); fs != nil {
		return fs.GetStringMatch()
	}
	t.Fatalf("principal is not authenticated/filterstate: %+v", p)
	return nil
}

// buildPrincipalMatcher runs the REAL model.New/Generate for a single source field
// and returns the innermost identity StringMatcher.
func buildIdentityMatcher(t *testing.T, src *authzpb.Source) *matcherpb.StringMatcher {
	t.Helper()
	rule := &authzpb.Rule{From: []*authzpb.Rule_From{{Source: src}}}
	m, err := authzmodel.New(types.NamespacedName{Namespace: "polns", Name: "pol"}, rule)
	if err != nil {
		t.Fatalf("model.New: %v", err)
	}
	pol, err := m.Generate(false, true, rbacpb.RBAC_ALLOW)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// principals[0] is andIds{ orIds{ authenticated } } — dig to the leaf.
	pr := pol.Principals[0]
	// unwrap andIds
	if and := pr.GetAndIds(); and != nil {
		pr = and.GetIds()[0]
	}
	if or := pr.GetOrIds(); or != nil {
		pr = or.GetIds()[0]
	}
	return extractAuthenticatedMatcher(t, pr)
}

// A realistic set of mesh-issued SPIFFE identities (as they appear in peer_principal).
var universe = []string{
	"spiffe://cluster.local/ns/foo/sa/bar",
	"spiffe://cluster.local/ns/foo/sa/baz",
	"spiffe://cluster.local/ns/foo/sa/bar-2",
	"spiffe://cluster.local/ns/foobar/sa/bar",
	"spiffe://cluster.local/ns/xfoo/sa/bar",
	"spiffe://cluster.local/ns/other/sa/bar",
	"spiffe://evil.com/ns/foo/sa/bar",
	"spiffe://cluster.local.evil.com/ns/foo/sa/bar",
	"spiffe://cluster.local/ns/foo/sa/bar/extra",
}

func TestOracle_Principal(t *testing.T) {
	// source.principals: ["cluster.local/ns/foo/sa/bar"] must match ONLY that identity.
	sm := buildIdentityMatcher(t, &authzpb.Source{Principals: []string{"cluster.local/ns/foo/sa/bar"}})
	want := "spiffe://cluster.local/ns/foo/sa/bar"
	for _, id := range universe {
		got := simEnvoyStringMatch(t, sm, id)
		intended := id == want
		if got != intended {
			t.Errorf("PRINCIPAL over/under-match: id=%q got=%v intended=%v matcher=%+v", id, got, intended, sm)
		}
	}
}

func TestOracle_Namespace(t *testing.T) {
	// source.namespaces: ["foo"] must match ONLY identities whose namespace is exactly foo.
	sm := buildIdentityMatcher(t, &authzpb.Source{Namespaces: []string{"foo"}})
	for _, id := range universe {
		got := simEnvoyStringMatch(t, sm, id)
		intended := strings.Contains(id, "/ns/foo/")
		if got != intended {
			t.Errorf("NAMESPACE over/under-match: id=%q got=%v intended=%v regex=%q", id, got, intended, sm.GetSafeRegex().GetRegex())
		}
	}
}

func TestOracle_ServiceAccount(t *testing.T) {
	// source.serviceAccounts: ["foo/bar"] must match ONLY sa bar in ns foo.
	sm := buildIdentityMatcher(t, &authzpb.Source{ServiceAccounts: []string{"foo/bar"}})
	for _, id := range universe {
		got := simEnvoyStringMatch(t, sm, id)
		// intended: standard spiffe with ns=foo and sa=bar (trailing attrs allowed)
		intended := strings.HasPrefix(id, "spiffe://") &&
			regexp.MustCompile(`^spiffe://[^/]+/ns/foo/sa/bar(/.*)?$`).MatchString(id)
		if got != intended {
			t.Errorf("SERVICEACCOUNT match mismatch: id=%q got=%v intended=%v regex=%q", id, got, intended, sm.GetSafeRegex().GetRegex())
		}
	}
}

func TestOracle_TrustDomain(t *testing.T) {
	// source.trustDomains: ["cluster.local"] must match ONLY identities in that trust domain.
	sm := buildIdentityMatcher(t, &authzpb.Source{TrustDomains: []string{"cluster.local"}})
	for _, id := range universe {
		got := simEnvoyStringMatch(t, sm, id)
		intended := strings.HasPrefix(id, "spiffe://cluster.local/")
		if got != intended {
			t.Errorf("TRUSTDOMAIN match mismatch: id=%q got=%v intended=%v matcher=%+v", id, got, intended, sm)
		}
	}
}
