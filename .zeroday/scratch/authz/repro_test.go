package authzrepro

import (
	"fmt"
	"testing"

	rbacpb "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	"k8s.io/apimachinery/pkg/types"

	authzpb "istio.io/api/security/v1beta1"
	authzmodel "istio.io/istio/pilot/pkg/security/authz/model"
	"istio.io/istio/pkg/util/protomarshal"
)

// dump runs the REAL model.New + Generate path and prints the resulting policy YAML.
func dump(t *testing.T, label string, rule *authzpb.Rule, action rbacpb.RBAC_Action, forTCP, useAuthn bool) {
	t.Helper()
	m, err := authzmodel.New(types.NamespacedName{Namespace: "ns", Name: "pol"}, rule)
	if err != nil {
		fmt.Printf("=== %s ===\nMODEL ERROR: %v\n\n", label, err)
		return
	}
	pol, err := m.Generate(forTCP, useAuthn, action)
	if err != nil {
		fmt.Printf("=== %s ===\nGENERATE ERROR: %v\n\n", label, err)
		return
	}
	y, err := protomarshal.ToYAML(pol)
	if err != nil {
		t.Fatalf("yaml: %v", err)
	}
	fmt.Printf("=== %s (action=%v forTCP=%v useAuthn=%v) ===\n%s\n", label, action, forTCP, useAuthn, y)
}

func cond(key string, vals, notVals []string) *authzpb.Condition {
	return &authzpb.Condition{Key: key, Values: vals, NotValues: notVals}
}

func TestDumpMatchers(t *testing.T) {
	// ---- PATH cases ----
	dump(t, "path-exact", &authzpb.Rule{To: []*authzpb.Rule_To{{Operation: &authzpb.Operation{Paths: []string{"/admin"}}}}}, rbacpb.RBAC_ALLOW, false, true)
	dump(t, "path-prefix-star", &authzpb.Rule{To: []*authzpb.Rule_To{{Operation: &authzpb.Operation{Paths: []string{"/admin/*"}}}}}, rbacpb.RBAC_ALLOW, false, true)
	dump(t, "path-mid-star", &authzpb.Rule{To: []*authzpb.Rule_To{{Operation: &authzpb.Operation{Paths: []string{"/api/*/admin"}}}}}, rbacpb.RBAC_ALLOW, false, true)
	dump(t, "path-template-one", &authzpb.Rule{To: []*authzpb.Rule_To{{Operation: &authzpb.Operation{Paths: []string{"/api/{*}/admin"}}}}}, rbacpb.RBAC_ALLOW, false, true)
	dump(t, "path-template-any", &authzpb.Rule{To: []*authzpb.Rule_To{{Operation: &authzpb.Operation{Paths: []string{"/api/{**}"}}}}}, rbacpb.RBAC_ALLOW, false, true)
	dump(t, "notpath-deny", &authzpb.Rule{To: []*authzpb.Rule_To{{Operation: &authzpb.Operation{NotPaths: []string{"/health"}}}}}, rbacpb.RBAC_DENY, false, true)

	// ---- HOST ----
	dump(t, "host-exact", &authzpb.Rule{To: []*authzpb.Rule_To{{Operation: &authzpb.Operation{Hosts: []string{"example.com"}}}}}, rbacpb.RBAC_ALLOW, false, true)
	dump(t, "host-prefix", &authzpb.Rule{To: []*authzpb.Rule_To{{Operation: &authzpb.Operation{Hosts: []string{"*.example.com"}}}}}, rbacpb.RBAC_ALLOW, false, true)

	// ---- METHOD ----
	dump(t, "method-get", &authzpb.Rule{To: []*authzpb.Rule_To{{Operation: &authzpb.Operation{Methods: []string{"GET"}}}}}, rbacpb.RBAC_ALLOW, false, true)
	dump(t, "notmethod-deny", &authzpb.Rule{To: []*authzpb.Rule_To{{Operation: &authzpb.Operation{NotMethods: []string{"GET"}}}}}, rbacpb.RBAC_DENY, false, true)

	// ---- PORTS ----
	dump(t, "port", &authzpb.Rule{To: []*authzpb.Rule_To{{Operation: &authzpb.Operation{Ports: []string{"8080"}}}}}, rbacpb.RBAC_ALLOW, false, true)

	// ---- PRINCIPALS ----
	dump(t, "principal-exact", &authzpb.Rule{From: []*authzpb.Rule_From{{Source: &authzpb.Source{Principals: []string{"cluster.local/ns/foo/sa/bar"}}}}}, rbacpb.RBAC_ALLOW, false, true)
	dump(t, "principal-star", &authzpb.Rule{From: []*authzpb.Rule_From{{Source: &authzpb.Source{Principals: []string{"*"}}}}}, rbacpb.RBAC_ALLOW, false, true)
	dump(t, "principal-prefix", &authzpb.Rule{From: []*authzpb.Rule_From{{Source: &authzpb.Source{Principals: []string{"cluster.local/ns/foo/sa/*"}}}}}, rbacpb.RBAC_ALLOW, false, true)
	dump(t, "principal-suffixstar", &authzpb.Rule{From: []*authzpb.Rule_From{{Source: &authzpb.Source{Principals: []string{"*/ns/foo/sa/bar"}}}}}, rbacpb.RBAC_ALLOW, false, true)
	dump(t, "notprincipal-deny", &authzpb.Rule{From: []*authzpb.Rule_From{{Source: &authzpb.Source{NotPrincipals: []string{"cluster.local/ns/foo/sa/bar"}}}}}, rbacpb.RBAC_DENY, false, true)

	// ---- NAMESPACES ----
	dump(t, "namespace", &authzpb.Rule{From: []*authzpb.Rule_From{{Source: &authzpb.Source{Namespaces: []string{"foo"}}}}}, rbacpb.RBAC_ALLOW, false, true)
	dump(t, "namespace-star", &authzpb.Rule{From: []*authzpb.Rule_From{{Source: &authzpb.Source{Namespaces: []string{"foo*"}}}}}, rbacpb.RBAC_ALLOW, false, true)

	// ---- SERVICE ACCOUNTS ----
	dump(t, "sa", &authzpb.Rule{From: []*authzpb.Rule_From{{Source: &authzpb.Source{ServiceAccounts: []string{"foo/bar"}}}}}, rbacpb.RBAC_ALLOW, false, true)

	// ---- TRUST DOMAIN ----
	dump(t, "td-exact", &authzpb.Rule{From: []*authzpb.Rule_From{{Source: &authzpb.Source{TrustDomains: []string{"cluster.local"}}}}}, rbacpb.RBAC_ALLOW, false, true)

	// ---- IP ----
	dump(t, "srcip", &authzpb.Rule{From: []*authzpb.Rule_From{{Source: &authzpb.Source{IpBlocks: []string{"10.0.0.0/8"}}}}}, rbacpb.RBAC_ALLOW, false, true)
	dump(t, "remoteip", &authzpb.Rule{From: []*authzpb.Rule_From{{Source: &authzpb.Source{RemoteIpBlocks: []string{"1.2.3.4"}}}}}, rbacpb.RBAC_ALLOW, false, true)

	// ---- JWT request principal ----
	dump(t, "reqprincipal", &authzpb.Rule{From: []*authzpb.Rule_From{{Source: &authzpb.Source{RequestPrincipals: []string{"iss.example.com/subject"}}}}}, rbacpb.RBAC_ALLOW, false, true)
	dump(t, "reqprincipal-notvals-deny", &authzpb.Rule{From: []*authzpb.Rule_From{{Source: &authzpb.Source{NotRequestPrincipals: []string{"iss.example.com/subject"}}}}}, rbacpb.RBAC_DENY, false, true)

	// ---- WHEN conditions ----
	dump(t, "when-header", &authzpb.Rule{When: []*authzpb.Condition{cond("request.headers[x-foo]", []string{"bar"}, nil)}}, rbacpb.RBAC_ALLOW, false, true)
	dump(t, "when-claim", &authzpb.Rule{When: []*authzpb.Condition{cond("request.auth.claims[groups]", []string{"admin"}, nil)}}, rbacpb.RBAC_ALLOW, false, true)
	dump(t, "when-notclaim-deny", &authzpb.Rule{When: []*authzpb.Condition{cond("request.auth.claims[groups]", nil, []string{"admin"})}}, rbacpb.RBAC_DENY, false, true)

	// ---- useAuthn=false (filter state) ----
	dump(t, "principal-exact-filterstate", &authzpb.Rule{From: []*authzpb.Rule_From{{Source: &authzpb.Source{Principals: []string{"cluster.local/ns/foo/sa/bar"}}}}}, rbacpb.RBAC_ALLOW, false, false)
}
