package authzrepro

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	rbacpb "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	routepb "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	matcherpb "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"k8s.io/apimachinery/pkg/types"

	authzpb "istio.io/api/security/v1beta1"
	authzmodel "istio.io/istio/pilot/pkg/security/authz/model"
)

// req models the request attributes Envoy would see.
type req struct {
	path    string // :path incl query
	method  string // :method
	host    string // :authority
	port    uint32
	headers map[string]string
}

func (r req) headerVal(name string) (string, bool) {
	switch name {
	case ":method":
		return r.method, true
	case ":authority":
		return r.host, true
	}
	v, ok := r.headers[strings.ToLower(name)]
	return v, ok
}

func ssm(t *testing.T, m *matcherpb.StringMatcher, s string) bool {
	return simEnvoyStringMatch(t, m, s)
}

// evalHeader simulates Envoy's HeaderMatcher evaluation (only the specifiers we emit).
func evalHeader(t *testing.T, h *routepb.HeaderMatcher, r req) bool {
	t.Helper()
	name := h.GetName()
	val, present := r.headerVal(name)
	res := false
	switch spec := h.GetHeaderMatchSpecifier().(type) {
	case *routepb.HeaderMatcher_PresentMatch:
		res = present == spec.PresentMatch
	case *routepb.HeaderMatcher_StringMatch:
		res = present && ssm(t, spec.StringMatch, val)
	case *routepb.HeaderMatcher_ExactMatch:
		res = present && val == spec.ExactMatch
	case *routepb.HeaderMatcher_PrefixMatch:
		res = present && strings.HasPrefix(val, spec.PrefixMatch)
	default:
		t.Fatalf("unhandled header specifier: %+v", h)
	}
	if h.GetInvertMatch() {
		res = !res
	}
	return res
}

// evalPathMatcher simulates Envoy UrlPath (operates on the path with query stripped).
func evalPathMatcher(t *testing.T, pm *matcherpb.PathMatcher, r req) bool {
	t.Helper()
	p := r.path
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	return ssm(t, pm.GetPath(), p)
}

// evalPermission recursively simulates Envoy RBAC Permission evaluation.
func evalPermission(t *testing.T, perm *rbacpb.Permission, r req) bool {
	t.Helper()
	switch rule := perm.GetRule().(type) {
	case *rbacpb.Permission_Any:
		return rule.Any
	case *rbacpb.Permission_AndRules:
		for _, p := range rule.AndRules.GetRules() {
			if !evalPermission(t, p, r) {
				return false
			}
		}
		return true
	case *rbacpb.Permission_OrRules:
		for _, p := range rule.OrRules.GetRules() {
			if evalPermission(t, p, r) {
				return true
			}
		}
		return false
	case *rbacpb.Permission_NotRule:
		return !evalPermission(t, rule.NotRule, r)
	case *rbacpb.Permission_Header:
		return evalHeader(t, rule.Header, r)
	case *rbacpb.Permission_UrlPath:
		return evalPathMatcher(t, rule.UrlPath, r)
	case *rbacpb.Permission_DestinationPort:
		return r.port == rule.DestinationPort
	default:
		t.Fatalf("unhandled permission rule: %T %+v", rule, perm)
		return false
	}
}

// buildPermission runs the REAL model path for a rule and returns permissions[0].
func buildPermission(t *testing.T, rule *authzpb.Rule, action rbacpb.RBAC_Action) *rbacpb.Permission {
	t.Helper()
	m, err := authzmodel.New(types.NamespacedName{Namespace: "polns", Name: "pol"}, rule)
	if err != nil {
		t.Fatalf("model.New: %v", err)
	}
	pol, err := m.Generate(false, true, action)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return pol.Permissions[0]
}

func to(op *authzpb.Operation) *authzpb.Rule {
	return &authzpb.Rule{To: []*authzpb.Rule_To{{Operation: op}}}
}

// ---- PATH ORACLE ----
func TestPermOracle_Path(t *testing.T) {
	cases := []struct {
		name   string
		op     *authzpb.Operation
		action rbacpb.RBAC_Action
		// intended reports whether the author intends this request to MATCH the rule.
		intended func(r req) bool
	}{
		{
			name:     "exact /admin",
			op:       &authzpb.Operation{Paths: []string{"/admin"}},
			action:   rbacpb.RBAC_ALLOW,
			intended: func(r req) bool { return strings.Split(r.path, "?")[0] == "/admin" },
		},
		{
			name:     "prefix /admin/*",
			op:       &authzpb.Operation{Paths: []string{"/admin/*"}},
			action:   rbacpb.RBAC_ALLOW,
			intended: func(r req) bool { return strings.HasPrefix(strings.Split(r.path, "?")[0], "/admin/") },
		},
		{
			name:     "suffix */admin",
			op:       &authzpb.Operation{Paths: []string{"*/admin"}},
			action:   rbacpb.RBAC_ALLOW,
			intended: func(r req) bool { return strings.HasSuffix(strings.Split(r.path, "?")[0], "/admin") },
		},
		{
			name:     "notPaths /health (deny)",
			op:       &authzpb.Operation{NotPaths: []string{"/health"}},
			action:   rbacpb.RBAC_DENY,
			intended: func(r req) bool { return strings.Split(r.path, "?")[0] != "/health" },
		},
	}
	paths := []string{"/admin", "/admin/", "/admin/x", "/x/admin", "/health", "/HEALTH", "/admin?x=1", "/", "//admin", "/admin/../etc"}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			perm := buildPermission(t, to(tc.op), tc.action)
			for _, p := range paths {
				r := req{path: p, method: "GET", host: "h", port: 80}
				got := evalPermission(t, perm, r)
				want := tc.intended(r)
				if got != want {
					t.Errorf("PATH %q: got=%v intended=%v", p, got, want)
				}
			}
		})
	}
}

// ---- HOST ORACLE ----
func TestPermOracle_Host(t *testing.T) {
	perm := buildPermission(t, to(&authzpb.Operation{Hosts: []string{"*.example.com"}}), rbacpb.RBAC_ALLOW)
	hosts := []string{"a.example.com", "A.EXAMPLE.COM", "example.com", "a.example.com:8080", "evil.com", "a.example.com.evil.com"}
	for _, h := range hosts {
		r := req{path: "/", method: "GET", host: h, port: 80}
		got := evalPermission(t, perm, r)
		// intended: authority ends with .example.com (case-insensitive). Note port makes it NOT match a bare suffix.
		want := strings.HasSuffix(strings.ToLower(h), ".example.com")
		if got != want {
			t.Errorf("HOST %q: got=%v intended=%v", h, got, want)
		}
	}
}

// ---- METHOD ORACLE ----
func TestPermOracle_Method(t *testing.T) {
	perm := buildPermission(t, to(&authzpb.Operation{Methods: []string{"GET"}}), rbacpb.RBAC_ALLOW)
	for _, mth := range []string{"GET", "get", "POST", "GETX"} {
		r := req{path: "/", method: mth, host: "h", port: 80}
		got := evalPermission(t, perm, r)
		want := mth == "GET"
		if got != want {
			t.Errorf("METHOD %q: got=%v intended=%v", mth, got, want)
		}
	}
}

// ---- COMPOSITION ORACLE: methods AND notPaths in one operation ----
func TestPermOracle_Composition(t *testing.T) {
	// ALLOW GET to everything except /health.
	op := &authzpb.Operation{Methods: []string{"GET"}, NotPaths: []string{"/health"}}
	perm := buildPermission(t, to(op), rbacpb.RBAC_ALLOW)
	type tc struct {
		r    req
		want bool
	}
	cases := []tc{
		{req{path: "/x", method: "GET", port: 80}, true},
		{req{path: "/health", method: "GET", port: 80}, false},
		{req{path: "/x", method: "POST", port: 80}, false},
		{req{path: "/health", method: "POST", port: 80}, false},
	}
	for _, c := range cases {
		got := evalPermission(t, perm, c.r)
		if got != c.want {
			t.Errorf("COMPOSITION %+v: got=%v want=%v", c.r, got, c.want)
		}
	}
}

// ---- PORTS: ensure ports are not silently dropped ----
func TestPermOracle_Port(t *testing.T) {
	perm := buildPermission(t, to(&authzpb.Operation{Ports: []string{"8080"}}), rbacpb.RBAC_ALLOW)
	for _, p := range []uint32{8080, 80, 443} {
		r := req{path: "/", method: "GET", port: p}
		got := evalPermission(t, perm, r)
		want := p == 8080
		if got != want {
			t.Errorf("PORT %d: got=%v want=%v", p, got, want)
		}
	}
}

func TestPermOracle_Dump(t *testing.T) {
	// Sanity: print a couple trees for manual inspection.
	perm := buildPermission(t, to(&authzpb.Operation{Hosts: []string{"*.example.com"}}), rbacpb.RBAC_ALLOW)
	fmt.Printf("host tree: %s\n", perm.String())
}

var _ = regexp.MustCompile
