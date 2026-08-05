package authzrepro

import (
	"strings"
	"testing"

	rbacpb "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	matcherpb "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"k8s.io/apimachinery/pkg/types"

	authzpb "istio.io/api/security/v1beta1"
	authzmodel "istio.io/istio/pilot/pkg/security/authz/model"
)

// A JWT payload: claim -> value (string or []string).
type payload map[string]any

// simValueMatch simulates Envoy ValueMatcher against a resolved metadata value.
func simValueMatch(t *testing.T, vm *matcherpb.ValueMatcher, val any) bool {
	t.Helper()
	switch p := vm.GetMatchPattern().(type) {
	case *matcherpb.ValueMatcher_StringMatch:
		s, ok := val.(string)
		if !ok {
			return false
		}
		return simEnvoyStringMatch(t, p.StringMatch, s)
	case *matcherpb.ValueMatcher_ListMatch:
		lst, ok := val.([]string)
		if !ok {
			return false
		}
		// oneOf: any element matches
		one := p.ListMatch.GetOneOf()
		for _, e := range lst {
			if simValueMatch(t, one, e) {
				return true
			}
		}
		return false
	case *matcherpb.ValueMatcher_OrMatch:
		for _, sub := range p.OrMatch.GetValueMatchers() {
			if simValueMatch(t, sub, val) {
				return true
			}
		}
		return false
	default:
		t.Fatalf("unhandled value matcher: %+v", vm)
		return false
	}
}

// simMetadataMatch simulates Envoy MetadataMatcher against a jwt payload.
func simMetadataMatch(t *testing.T, mm *matcherpb.MetadataMatcher, pl payload) bool {
	t.Helper()
	// path is [payload, claim...]; we only support single claim after "payload"
	segs := mm.GetPath()
	if len(segs) < 2 {
		t.Fatalf("unexpected path len: %+v", segs)
	}
	// first seg is "payload"
	claim := segs[1].GetKey()
	// nested claims not exercised here
	val, ok := pl[claim]
	if !ok {
		return false // claim absent -> no match
	}
	// If nested path deeper, walk (not used in these tests)
	return simValueMatch(t, mm.GetValue(), val)
}

// simPrincipal evaluates an rbac Principal tree against a jwt payload (identity side).
func simPrincipal(t *testing.T, pr *rbacpb.Principal, pl payload) bool {
	t.Helper()
	switch id := pr.GetIdentifier().(type) {
	case *rbacpb.Principal_Any:
		return id.Any
	case *rbacpb.Principal_AndIds:
		for _, p := range id.AndIds.GetIds() {
			if !simPrincipal(t, p, pl) {
				return false
			}
		}
		return true
	case *rbacpb.Principal_OrIds:
		for _, p := range id.OrIds.GetIds() {
			if simPrincipal(t, p, pl) {
				return true
			}
		}
		return false
	case *rbacpb.Principal_NotId:
		return !simPrincipal(t, id.NotId, pl)
	case *rbacpb.Principal_Metadata:
		return simMetadataMatch(t, id.Metadata, pl)
	default:
		t.Fatalf("unhandled principal for jwt: %T", id)
		return false
	}
}

func buildPrincipal0(t *testing.T, src *authzpb.Source) *rbacpb.Principal {
	rule := &authzpb.Rule{From: []*authzpb.Rule_From{{Source: src}}}
	m, err := authzmodel.New(types.NamespacedName{Namespace: "ns", Name: "p"}, rule)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pol, err := m.Generate(false, true, rbacpb.RBAC_ALLOW)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return pol.Principals[0]
}

// ---- request principal (iss/sub) oracle ----
func TestJwtOracle_RequestPrincipal(t *testing.T) {
	type tc struct {
		pattern string
		match   func(iss, sub string) bool
	}
	cases := []tc{
		{"iss.example.com/subject", func(iss, sub string) bool { return iss == "iss.example.com" && sub == "subject" }},
		{"iss.example.com/*", func(iss, sub string) bool { return iss == "iss.example.com" && sub != "" }},
		{"*/subject", func(iss, sub string) bool { return iss != "" && sub == "subject" }},
		{"*", func(iss, sub string) bool { return iss != "" && sub != "" }},
		{"iss.example.com/sub*", func(iss, sub string) bool { return iss == "iss.example.com" && strings.HasPrefix(sub, "sub") }},
	}
	issList := []string{"iss.example.com", "evil.com", "iss.example.com.evil", ""}
	subList := []string{"subject", "subject2", "sub", "admin", ""}

	for _, c := range cases {
		t.Run(c.pattern, func(t *testing.T) {
			pr := buildPrincipal0(t, &authzpb.Source{RequestPrincipals: []string{c.pattern}})
			for _, iss := range issList {
				for _, sub := range subList {
					pl := payload{}
					if iss != "" {
						pl["iss"] = iss
					}
					if sub != "" {
						pl["sub"] = sub
					}
					got := simPrincipal(t, pr, pl)
					want := c.match(iss, sub)
					if got != want {
						t.Errorf("REQPRINCIPAL pat=%q iss=%q sub=%q got=%v want=%v", c.pattern, iss, sub, got, want)
					}
				}
			}
		})
	}
}

// buildPrincipalFromWhen builds a rule with a single When condition and returns principal[0].
func buildPrincipalFromWhen(t *testing.T, c *authzpb.Condition) *rbacpb.Principal {
	rule := &authzpb.Rule{When: []*authzpb.Condition{c}}
	m, err := authzmodel.New(types.NamespacedName{Namespace: "ns", Name: "p"}, rule)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pol, err := m.Generate(false, true, rbacpb.RBAC_ALLOW)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return pol.Principals[0]
}

// ---- claims oracle: scalar and array claims ----
func TestJwtOracle_Claims(t *testing.T) {
	// request.auth.claims[groups]: ["admin"]
	pr := buildPrincipalFromWhen(t, &authzpb.Condition{Key: "request.auth.claims[groups]", Values: []string{"admin"}})
	payloads := []struct {
		pl   payload
		want bool
	}{
		{payload{"groups": "admin"}, true},
		{payload{"groups": "user"}, false},
		{payload{"groups": []string{"admin", "user"}}, true},
		{payload{"groups": []string{"user"}}, false},
		{payload{"groups": []string{"superadmin"}}, false},
		{payload{}, false},
		{payload{"groups": "superadmin"}, false},
	}
	for _, p := range payloads {
		got := simPrincipal(t, pr, p.pl)
		if got != p.want {
			t.Errorf("CLAIMS groups=admin payload=%v got=%v want=%v", p.pl, got, p.want)
		}
	}
}

// ---- audiences oracle ----
func TestJwtOracle_Audiences(t *testing.T) {
	// audiences come from When condition request.auth.audiences
	pr := buildPrincipalFromWhen(t, &authzpb.Condition{Key: "request.auth.audiences", Values: []string{"aud1"}})
	payloads := []struct {
		pl   payload
		want bool
	}{
		{payload{"aud": "aud1"}, true},
		{payload{"aud": "aud2"}, false},
		{payload{"aud": []string{"aud1", "aud2"}}, true},
		{payload{"aud": []string{"aud2"}}, false},
		{payload{}, false},
	}
	for _, p := range payloads {
		got := simPrincipal(t, pr, p.pl)
		if got != p.want {
			t.Errorf("AUDIENCES aud1 payload=%v got=%v want=%v", p.pl, got, p.want)
		}
	}
}
