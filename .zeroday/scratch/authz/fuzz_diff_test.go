package authzrepro

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	rbacpb "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	"k8s.io/apimachinery/pkg/types"

	authzpb "istio.io/api/security/v1beta1"
	authzmodel "istio.io/istio/pilot/pkg/security/authz/model"
)

// ---- Reference model of Istio's INTENDED semantics ----

// refStringMatch encodes Istio's documented wildcard rule: only a single leading
// or trailing '*' is a wildcard; '*' alone means "present/any non-empty"; anything
// else (including interior '*') is a literal exact match.
func refStringMatch(pattern, s string, ignoreCase bool) bool {
	if ignoreCase {
		pattern = strings.ToLower(pattern)
		s = strings.ToLower(s)
	}
	switch {
	case pattern == "*":
		return s != "" // present
	case strings.HasPrefix(pattern, "*"):
		return strings.HasSuffix(s, pattern[1:])
	case strings.HasSuffix(pattern, "*"):
		return strings.HasPrefix(s, pattern[:len(pattern)-1])
	default:
		return s == pattern
	}
}

// refField: does the request value match ANY of values and NONE of notValues?
func refField(values, notValues []string, reqVal string, ignoreCase bool, present bool) bool {
	if len(values) > 0 {
		any := false
		for _, v := range values {
			if refStringMatch(v, reqVal, ignoreCase) {
				any = true
				break
			}
		}
		if !any {
			return false
		}
	}
	for _, nv := range notValues {
		if refStringMatch(nv, reqVal, ignoreCase) {
			return false
		}
	}
	return true
}

// pools of candidate literals/wildcards
var (
	pathPool   = []string{"/admin", "/admin/*", "*/admin", "/", "/a/b", "/health", "*"}
	methodPool = []string{"GET", "POST", "PUT", "GET*", "*"}
	hostPool   = []string{"example.com", "*.example.com", "api.*", "*"}
	portPool   = []string{"80", "8080", "443"}
)

func pick(r *rand.Rand, pool []string) []string {
	n := r.Intn(2) // 0,1
	if n == 0 {
		return nil
	}
	// choose 1..2 distinct
	k := 1 + r.Intn(2)
	seen := map[string]bool{}
	var out []string
	for len(out) < k {
		v := pool[r.Intn(len(pool))]
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
		if len(seen) == len(pool) {
			break
		}
	}
	return out
}

// request candidates
var (
	reqPaths   = []string{"/admin", "/admin/", "/admin/x", "/x/admin", "/", "/a/b", "/health", "/Admin"}
	reqMethods = []string{"GET", "POST", "PUT", "GETX", "get"}
	reqHosts   = []string{"example.com", "a.example.com", "API.foo", "api.foo", "evil.com", "a.example.com:8080"}
	reqPorts   = []uint32{80, 8080, 443}
)

func TestFuzzDiff_Permissions(t *testing.T) {
	r := rand.New(rand.NewSource(1234))
	fails := 0
	for iter := 0; iter < 20000; iter++ {
		paths := pick(r, pathPool)
		notPaths := pick(r, pathPool)
		methods := pick(r, methodPool)
		notMethods := pick(r, methodPool)
		hosts := pick(r, hostPool)
		ports := pick(r, portPool)

		op := &authzpb.Operation{
			Paths: paths, NotPaths: notPaths,
			Methods: methods, NotMethods: notMethods,
			Hosts: hosts, Ports: ports,
		}
		// must have at least one field to be meaningful
		rule := &authzpb.Rule{To: []*authzpb.Rule_To{{Operation: op}}}
		m, err := authzmodel.New(types.NamespacedName{Namespace: "ns", Name: "p"}, rule)
		if err != nil {
			continue
		}
		pol, err := m.Generate(false, true, rbacpb.RBAC_ALLOW)
		if err != nil {
			continue
		}
		perm := pol.Permissions[0]

		for _, rp := range reqPaths {
			for _, rm := range reqMethods {
				for _, rh := range reqHosts {
					for _, rport := range reqPorts {
						rq := req{path: rp, method: rm, host: rh, port: rport}
						got := evalPermission(t, perm, rq)

						// reference: AND across fields; each field matches if req matches values & not notValues
						want := true
						want = want && refField(paths, notPaths, strings.Split(rp, "?")[0], false, true)
						want = want && refField(methods, notMethods, rm, false, true)
						if len(hosts) > 0 {
							want = want && refField(hosts, nil, rh, true, true)
						}
						if len(ports) > 0 {
							want = want && refFieldPort(ports, rport)
						}

						if got != want {
							fails++
							if fails <= 20 {
								t.Errorf("DIVERGENCE iter=%d\n op=%s\n req path=%q method=%q host=%q port=%d\n got=%v want=%v",
									iter, opString(op), rp, rm, rh, rport, got, want)
							}
						}
					}
				}
			}
		}
	}
	if fails > 0 {
		t.Errorf("total divergences: %d", fails)
	}
}

func refFieldPort(ports []string, p uint32) bool {
	for _, ps := range ports {
		if fmt.Sprintf("%d", p) == ps {
			return true
		}
	}
	return false
}

func opString(op *authzpb.Operation) string {
	return fmt.Sprintf("paths=%v notPaths=%v methods=%v notMethods=%v hosts=%v ports=%v",
		op.Paths, op.NotPaths, op.Methods, op.NotMethods, op.Hosts, op.Ports)
}
