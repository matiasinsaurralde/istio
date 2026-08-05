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

// Build the identity StringMatcher for a single source field via the REAL path,
// returning nil if the field produced no principal.
func idMatcher(t *testing.T, src *authzpb.Source) *matcherpb.StringMatcher {
	rule := &authzpb.Rule{From: []*authzpb.Rule_From{{Source: src}}}
	m, err := authzmodel.New(types.NamespacedName{Namespace: "polns", Name: "pol"}, rule)
	if err != nil {
		return nil
	}
	pol, err := m.Generate(false, true, rbacpb.RBAC_ALLOW)
	if err != nil {
		return nil
	}
	pr := pol.Principals[0]
	if and := pr.GetAndIds(); and != nil {
		if len(and.GetIds()) == 0 {
			return nil
		}
		pr = and.GetIds()[0]
	}
	if or := pr.GetOrIds(); or != nil {
		pr = or.GetIds()[0]
	}
	if a := pr.GetAuthenticated(); a != nil {
		return a.GetPrincipalName()
	}
	if fs := pr.GetFilterState(); fs != nil {
		return fs.GetStringMatch()
	}
	return nil
}

// Rich universe of SPIFFE identities (as they appear in peer principal / cert SAN).
var idUniverse = []string{
	"spiffe://cluster.local/ns/foo/sa/bar",
	"spiffe://cluster.local/ns/foo/sa/baz",
	"spiffe://cluster.local/ns/foo/sa/bar-2",
	"spiffe://cluster.local/ns/foobar/sa/bar",
	"spiffe://cluster.local/ns/foo-prod/sa/bar",
	"spiffe://cluster.local/ns/prod-foo/sa/bar",
	"spiffe://cluster.local/ns/xfoo/sa/bar",
	"spiffe://cluster.local/ns/foo.prod/sa/bar",
	"spiffe://cluster.local/ns/other/sa/bar",
	"spiffe://td2/ns/foo/sa/bar",
	"spiffe://evil.com/ns/foo/sa/bar",
	"spiffe://cluster.local.evil/ns/foo/sa/bar",
	"spiffe://evil.cluster.local/ns/foo/sa/bar",
	"spiffe://cluster.local/ns/foo/sa/bar/x/y",
	"spiffe://cluster.local/k/v/ns/foo/sa/bar",
	"spiffe://cluster.local/ns/foo/x/y/sa/bar",
}

func nsSegment(id string) (string, bool) {
	i := strings.Index(id, "/ns/")
	if i < 0 {
		return "", false
	}
	rest := id[i+4:]
	j := strings.IndexByte(rest, '/')
	if j < 0 {
		return "", false
	}
	return rest[:j], true
}

func tdSegment(id string) (string, bool) {
	if !strings.HasPrefix(id, "spiffe://") {
		return "", false
	}
	rest := id[len("spiffe://"):]
	j := strings.IndexByte(rest, '/')
	if j < 0 {
		return rest, true
	}
	return rest[:j], true
}

// ---------- NAMESPACE ----------
// Intended: the identity's namespace segment matches the pattern (single wildcard).
func TestFuzzDiff_Namespace(t *testing.T) {
	patterns := []string{"foo", "foo*", "*foo", "foo.prod", "foo-prod", "*"}
	for _, pat := range patterns {
		sm := idMatcher(t, &authzpb.Source{Namespaces: []string{pat}})
		if sm == nil {
			t.Fatalf("ns %q produced no matcher", pat)
		}
		for _, id := range idUniverse {
			got := simEnvoyStringMatch(t, sm, id)
			seg, ok := nsSegment(id)
			want := ok && refStringMatch(pat, seg, false)
			if got != want {
				t.Errorf("NAMESPACE pat=%q id=%q got=%v want=%v regex=%q", pat, id, got, want, sm.GetSafeRegex().GetRegex())
			}
		}
	}
}

// ---------- TRUST DOMAIN ----------
func TestFuzzDiff_TrustDomain(t *testing.T) {
	patterns := []string{"cluster.local", "cluster.*", "*local", "cluster.local", "td2", "*"}
	for _, pat := range patterns {
		sm := idMatcher(t, &authzpb.Source{TrustDomains: []string{pat}})
		if sm == nil {
			t.Fatalf("td %q produced no matcher", pat)
		}
		for _, id := range idUniverse {
			got := simEnvoyStringMatch(t, sm, id)
			seg, ok := tdSegment(id)
			want := ok && refStringMatch(pat, seg, false)
			if got != want {
				t.Errorf("TRUSTDOMAIN pat=%q id=%q got=%v want=%v matcher=%+v", pat, id, got, want, sm)
			}
		}
	}
}

// ---------- SERVICE ACCOUNT ----------
// Intended: standard spiffe with matching ns and sa segments (allowing k/v attrs & trailing).
func TestFuzzDiff_ServiceAccount(t *testing.T) {
	// value ns/sa (no wildcards allowed by Istio)
	cases := []struct{ ns, sa string }{
		{"foo", "bar"}, {"foo", "baz"}, {"foobar", "bar"}, {"foo", "bar-2"},
	}
	for _, c := range cases {
		sm := idMatcher(t, &authzpb.Source{ServiceAccounts: []string{c.ns + "/" + c.sa}})
		if sm == nil {
			t.Fatalf("sa %q/%q produced no matcher", c.ns, c.sa)
		}
		// Reference: standard spiffe id whose ns==c.ns and sa==c.sa exactly.
		want := regexp.MustCompile(`^spiffe://[^/]+/ns/` + regexp.QuoteMeta(c.ns) + `/sa/` + regexp.QuoteMeta(c.sa) + `(/.*)?$`)
		for _, id := range idUniverse {
			got := simEnvoyStringMatch(t, sm, id)
			ref := want.MatchString(id)
			// Note: the real regex intentionally also allows k/v attrs between segments;
			// only flag cases where the real matcher matches something the STRICT reference rejects
			// AND that something is a different sa/ns (a real over-match).
			if got && !ref {
				ns, _ := nsSegment(id)
				// determine actual sa segment
				saSeg := ""
				if k := strings.LastIndex(id, "/sa/"); k >= 0 {
					saSeg = id[k+4:]
					if s := strings.IndexByte(saSeg, '/'); s >= 0 {
						saSeg = saSeg[:s]
					}
				}
				if ns != c.ns || saSeg != c.sa {
					t.Errorf("SERVICEACCOUNT OVER-MATCH val=%q/%q id=%q (nsSeg=%q saSeg=%q) regex=%q", c.ns, c.sa, id, ns, saSeg, sm.GetSafeRegex().GetRegex())
				}
			}
		}
	}
}

// ---------- PRINCIPAL ----------
func principalRef(pat, id string) bool {
	// matcher prepends spiffe://
	if pat == "*" {
		return id != "" // regex .+
	}
	if strings.HasPrefix(pat, "*") {
		// spiffe://.*<suffix>
		suf := pat[1:]
		return strings.HasPrefix(id, "spiffe://") && strings.HasSuffix(id, suf)
	}
	if strings.HasSuffix(pat, "*") {
		return strings.HasPrefix(id, "spiffe://"+pat[:len(pat)-1])
	}
	return id == "spiffe://"+pat
}

func TestFuzzDiff_Principal(t *testing.T) {
	patterns := []string{
		"cluster.local/ns/foo/sa/bar",
		"cluster.local/ns/foo/sa/*",
		"*/ns/foo/sa/bar",
		"cluster.local/ns/foo/sa/bar*",
		"*/sa/bar",
		"*",
	}
	for _, pat := range patterns {
		sm := idMatcher(t, &authzpb.Source{Principals: []string{pat}})
		if sm == nil {
			t.Fatalf("principal %q produced no matcher", pat)
		}
		for _, id := range idUniverse {
			got := simEnvoyStringMatch(t, sm, id)
			want := principalRef(pat, id)
			if got != want {
				t.Errorf("PRINCIPAL pat=%q id=%q got=%v want=%v matcher=%+v", pat, id, got, want, sm)
			}
		}
	}
}
