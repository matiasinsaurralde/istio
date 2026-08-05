package authzrepro

import (
	"math/rand"
	"strings"
	"testing"

	rbacpb "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	"k8s.io/apimachinery/pkg/types"

	authzpb "istio.io/api/security/v1beta1"
	authzmodel "istio.io/istio/pilot/pkg/security/authz/model"
)

// evalPrincipalIdentity evaluates a principal tree against a peer identity string
// (only the identity-string principals used here: authenticated/filterstate/and/or/not/any).
func evalPrincipalIdentity(t *testing.T, pr *rbacpb.Principal, id string) bool {
	t.Helper()
	switch p := pr.GetIdentifier().(type) {
	case *rbacpb.Principal_Any:
		return p.Any
	case *rbacpb.Principal_AndIds:
		for _, x := range p.AndIds.GetIds() {
			if !evalPrincipalIdentity(t, x, id) {
				return false
			}
		}
		return true
	case *rbacpb.Principal_OrIds:
		for _, x := range p.OrIds.GetIds() {
			if evalPrincipalIdentity(t, x, id) {
				return true
			}
		}
		return false
	case *rbacpb.Principal_NotId:
		return !evalPrincipalIdentity(t, p.NotId, id)
	case *rbacpb.Principal_Authenticated_:
		return simEnvoyStringMatch(t, p.Authenticated.GetPrincipalName(), id)
	case *rbacpb.Principal_FilterState:
		return simEnvoyStringMatch(t, p.FilterState.GetStringMatch(), id)
	default:
		t.Fatalf("unhandled principal id kind: %T", p)
		return false
	}
}

// policyMatches: Envoy RBAC policy matches iff (any permission) AND (any principal).
func policyMatches(t *testing.T, pol *rbacpb.Policy, r req, id string) bool {
	permOK := false
	for _, p := range pol.Permissions {
		if evalPermission(t, p, r) {
			permOK = true
			break
		}
	}
	if !permOK {
		return false
	}
	prinOK := false
	for _, p := range pol.Principals {
		if evalPrincipalIdentity(t, p, id) {
			prinOK = true
			break
		}
	}
	return prinOK
}

var (
	nsPool  = []string{"foo", "bar", "foo*"}
	saNames = []string{"bar", "baz"}
)

func TestFuzzDiff_Combined(t *testing.T) {
	r := rand.New(rand.NewSource(99))
	idPool := []string{
		"spiffe://cluster.local/ns/foo/sa/bar",
		"spiffe://cluster.local/ns/foo/sa/baz",
		"spiffe://cluster.local/ns/bar/sa/bar",
		"spiffe://cluster.local/ns/foobar/sa/bar",
		"spiffe://td2/ns/foo/sa/bar",
	}
	reqPool := []req{
		{path: "/admin", method: "GET", port: 80},
		{path: "/admin/x", method: "POST", port: 80},
		{path: "/pub", method: "GET", port: 8080},
		{path: "/health", method: "GET", port: 80},
	}

	fails := 0
	for iter := 0; iter < 8000; iter++ {
		// Build 1-2 from blocks
		var froms []*authzpb.Rule_From
		type refFrom struct {
			principals, notPrincipals []string
			namespaces                []string
		}
		var rfroms []refFrom
		nf := 1 + r.Intn(2)
		for i := 0; i < nf; i++ {
			src := &authzpb.Source{}
			rf := refFrom{}
			if r.Intn(2) == 0 {
				p := "cluster.local/ns/" + nsPool[r.Intn(len(nsPool))] + "/sa/" + saNames[r.Intn(len(saNames))]
				// avoid wildcard ns in principal (principals are literal-ish); keep simple
				p = strings.ReplaceAll(p, "*", "")
				src.Principals = []string{p}
				rf.principals = []string{p}
			} else {
				ns := nsPool[r.Intn(len(nsPool))]
				src.Namespaces = []string{ns}
				rf.namespaces = []string{ns}
			}
			froms = append(froms, &authzpb.Rule_From{Source: src})
			rfroms = append(rfroms, rf)
		}

		// Build 1-2 to blocks
		var tos []*authzpb.Rule_To
		type refTo struct {
			paths, notPaths, methods []string
		}
		var rtos []refTo
		nt := 1 + r.Intn(2)
		for i := 0; i < nt; i++ {
			op := &authzpb.Operation{}
			rt := refTo{}
			if r.Intn(2) == 0 {
				op.Paths = pick(r, pathPool)
				rt.paths = op.Paths
			}
			if r.Intn(2) == 0 {
				op.NotPaths = []string{"/health"}
				rt.notPaths = op.NotPaths
			}
			if r.Intn(2) == 0 {
				op.Methods = []string{"GET"}
				rt.methods = op.Methods
			}
			tos = append(tos, &authzpb.Rule_To{Operation: op})
			rtos = append(rtos, rt)
		}

		rule := &authzpb.Rule{From: froms, To: tos}
		m, err := authzmodel.New(types.NamespacedName{Namespace: "polns", Name: "p"}, rule)
		if err != nil {
			continue
		}
		pol, err := m.Generate(false, true, rbacpb.RBAC_ALLOW)
		if err != nil {
			continue
		}

		for _, id := range idPool {
			for _, rq := range reqPool {
				got := policyMatches(t, pol, rq, id)

				// reference: (any refTo matches rq) AND (any refFrom matches id)
				permRef := false
				for _, rt := range rtos {
					ok := true
					if len(rt.paths) > 0 {
						ok = ok && refField(rt.paths, nil, rq.path, false, true)
					}
					if len(rt.notPaths) > 0 {
						ok = ok && refField(nil, rt.notPaths, rq.path, false, true)
					}
					if len(rt.methods) > 0 {
						ok = ok && refField(rt.methods, nil, rq.method, false, true)
					}
					if ok {
						permRef = true
						break
					}
				}
				prinRef := false
				for _, rf := range rfroms {
					ok := true
					if len(rf.principals) > 0 {
						ok = ok && principalRef(rf.principals[0], id)
					}
					if len(rf.namespaces) > 0 {
						seg, has := nsSegment(id)
						ok = ok && has && refStringMatch(rf.namespaces[0], seg, false)
					}
					if ok {
						prinRef = true
						break
					}
				}
				want := permRef && prinRef

				if got != want {
					fails++
					if fails <= 15 {
						t.Errorf("COMBINED DIVERGENCE iter=%d id=%q req=%+v\n rule=%s\n got=%v want=%v",
							iter, id, rq, ruleStr(rule), got, want)
					}
				}
			}
		}
	}
	if fails > 0 {
		t.Errorf("total combined divergences: %d", fails)
	}
}

func ruleStr(r *authzpb.Rule) string {
	var b strings.Builder
	for _, f := range r.From {
		b.WriteString("FROM{")
		b.WriteString("principals=")
		b.WriteString(strings.Join(f.Source.Principals, ","))
		b.WriteString(" ns=")
		b.WriteString(strings.Join(f.Source.Namespaces, ","))
		b.WriteString("} ")
	}
	for _, tt := range r.To {
		b.WriteString("TO{paths=")
		b.WriteString(strings.Join(tt.Operation.Paths, ","))
		b.WriteString(" notPaths=")
		b.WriteString(strings.Join(tt.Operation.NotPaths, ","))
		b.WriteString(" methods=")
		b.WriteString(strings.Join(tt.Operation.Methods, ","))
		b.WriteString("} ")
	}
	return b.String()
}
