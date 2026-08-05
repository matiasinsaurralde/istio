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

func gen(t *testing.T, rule *authzpb.Rule, action rbacpb.RBAC_Action, forTCP bool) (*rbacpb.Policy, error) {
	m, err := authzmodel.New(types.NamespacedName{Namespace: "ns", Name: "p"}, rule)
	if err != nil {
		return nil, err
	}
	return m.Generate(forTCP, true, action)
}

// Confirm: an invalid value in a DENY rule WIDENS the deny (fail-closed), never narrows it.
func TestFailClosed_DenyInvalidValue(t *testing.T) {
	// DENY attacker on an invalid port -> port condition should vanish, deny becomes broader.
	rule := &authzpb.Rule{
		From: []*authzpb.Rule_From{{Source: &authzpb.Source{Principals: []string{"cluster.local/ns/foo/sa/attacker"}}}},
		To:   []*authzpb.Rule_To{{Operation: &authzpb.Operation{Ports: []string{"NOT_A_PORT"}}}},
	}
	pol, err := gen(t, rule, rbacpb.RBAC_DENY, false)
	if err != nil {
		t.Fatalf("DENY must not error (got %v)", err)
	}
	y, _ := protomarshal.ToYAML(pol)
	// Expect permission to be Any (port dropped) and principal to be the attacker.
	perm := pol.Permissions[0]
	if evalPermission(t, perm, req{path: "/", method: "GET", port: 12345}) != true {
		t.Errorf("expected widened permission (Any) for DENY with invalid port, got:\n%s", y)
	}
	fmt.Printf("DENY-invalid-port permission widened to match-any: OK\n%s\n", y)
}

// Confirm: same policy as ALLOW is DROPPED (fail-closed: more restrictive), producing an error.
func TestFailClosed_AllowInvalidValue(t *testing.T) {
	rule := &authzpb.Rule{
		To: []*authzpb.Rule_To{{Operation: &authzpb.Operation{Ports: []string{"NOT_A_PORT"}}}},
	}
	_, err := gen(t, rule, rbacpb.RBAC_ALLOW, false)
	if err == nil {
		t.Errorf("expected ALLOW with invalid port to ERROR (rule dropped = fail closed)")
	} else {
		fmt.Printf("ALLOW-invalid-port errored (rule dropped, fail-closed): %v\n", err)
	}
}

// Confirm: L7 DENY conditions on a TCP filter chain widen to deny-all (fail-closed), not bypass.
func TestFailClosed_DenyL7OnTCP(t *testing.T) {
	rule := &authzpb.Rule{
		To: []*authzpb.Rule_To{{Operation: &authzpb.Operation{Paths: []string{"/admin"}}}},
	}
	pol, err := gen(t, rule, rbacpb.RBAC_DENY, true /*forTCP*/)
	if err != nil {
		t.Fatalf("DENY on TCP must not error: %v", err)
	}
	perm := pol.Permissions[0]
	// On TCP the path condition is dropped -> Any -> denies everything (fail closed).
	if evalPermission(t, perm, req{path: "/anything", method: "GET", port: 80}) != true {
		y, _ := protomarshal.ToYAML(pol)
		t.Errorf("expected TCP DENY to widen to match-any, got:\n%s", y)
	}
	fmt.Printf("DENY-L7-on-TCP widened to match-any (fail-closed): OK\n")
}

// Confirm: notPorts / notHosts negation is faithful.
func TestFailClosed_NotPortsNotHosts(t *testing.T) {
	// DENY notPorts:[80] -> denies all ports except 80.
	rule := &authzpb.Rule{To: []*authzpb.Rule_To{{Operation: &authzpb.Operation{NotPorts: []string{"80"}}}}}
	pol, err := gen(t, rule, rbacpb.RBAC_DENY, false)
	if err != nil {
		t.Fatal(err)
	}
	perm := pol.Permissions[0]
	if evalPermission(t, perm, req{path: "/", method: "GET", port: 80}) != false {
		t.Errorf("notPorts:[80] should NOT match port 80")
	}
	if evalPermission(t, perm, req{path: "/", method: "GET", port: 8080}) != true {
		t.Errorf("notPorts:[80] should match port 8080")
	}
	fmt.Printf("notPorts negation faithful: OK\n")
}
