# Istio Zero-Day Discovery — Findings

Repo: matiasinsaurralde/istio @ 35fae141 (VERSION 1.31)
Method: first-principles reading + probes. No git diff/blame, no CVE lookup.

## Attack surface inventory (remote-reachable Go)
- **istiod/pilot-discovery**: XDS/ADS gRPC (`pilot/pkg/xds`, `pkg/xds`), config parse, debug endpoints
- **CA server** (`security/pkg/server/ca`): CSR signing; authenticators (cert/oidc/xfcc/kube-jwt); node_auth → **priv-esc surface** (cert for arbitrary SPIFFE id)
- **Injection webhook** (`pkg/kube/inject`): AdmissionReview parse, template render → possible RCE
- **Validation webhook** (`pkg/webhooks/validation`)
- **istio-agent**: SDS, xds_proxy, DNS proxy (`pkg/dns`), HBONE (`pkg/hbone`)
- **spiffe** (`pkg/spiffe`): trust-domain/identity parse
- **jwt** (`pkg/jwt`), **authn/authz** (`pilot/pkg/security`)
- **CNI** (`cni/`), **ztunnel api** (`pkg/zdsapi`)

## Approach families (registry)
| # | Family | Mechanism hypothesis | Status |
|---|--------|----------------------|--------|
| A | CA authenticators | XFCC/oidc/kube-jwt/cert identity extraction bug → cert for arbitrary id | OPEN |
| B | spiffe identity/trustdomain | trust-domain confusion / parse bug → impersonation | OPEN |
| C | authz policy matching | path/header normalization mismatch → authz bypass | OPEN |
| D | DNS proxy parser | malformed query → crash | OPEN |
| E | HBONE / h2 handling | request smuggling / auth bypass | OPEN |
| F | injection webhook | template/param injection → RCE or SSRF | OPEN |
| G | JWT validation | signature/aud/iss bypass | OPEN |
| H | XDS authz (node/proxy) | one proxy reads another's secrets/config | OPEN |

## Leads (orchestrator hand-read, not yet confirmed)
- **L1 (HIGH): Debug-endpoint namespace authorization is CUSTOM code** (`pilot/pkg/xds/debug.go`, `debuggen.go`). `ENABLE_DEBUG_ENDPOINT_AUTH` default **true**. Two entry points to debug handlers: (1) HTTP `allowAuthenticatedOrLocalhost`; (2) XDS `DebugType` via `DebugGen.Generate`->`processDebugRequest` dispatching through **internalMux (UNAUTHENTICATED)**. Non-system callers limited to `activeNamespaceDebuggers={config_dump,ndsz,edsz}`, all routed to `ConfigDump`, gated by `getDebugConnection` (requires `?proxyID=`, enforces `con.proxy.ConfigNamespace==callerNamespace`). **config_dump INCLUDES SDS secret private keys** (connectionConfigDump SecretsConfigDump) => any bypass of the namespace check = cross-tenant private-key theft / impersonation. On careful reading the check looks correct; needs an adversarial reproducer through the real DebugGen XDS path. Sub-questions: (a) URL-parse mismatch between `parseAndValidateDebugRequest` (u.Path of resourceName) and ServeMux path-clean dispatch; (b) any handler in allowlist not requiring proxyID; (c) `callerNamespace==""` reachable on an authenticated path; (d) systemNamespace value passed to NewDebugGen (discovery.go). Found: reading.
- **O1**: `xfcc_authenticator.go:93` `netip.MustParseAddr(ip).IsLoopback()` — panics if peer IP unpar?eable; reachable only after trusted-CIDR loop misses. Likely benign (SplitHostPort yields valid IP) — verify. Found: rule (MustParse sweep).
- **O2**: `pkg/wasm/httpfetcher.go:57` InsecureSkipVerify gated by `allowInsecure(host)` — check gating source. Found: rule.
- **O3**: `pkg/istio-agent/health/health_probers.go:262` exec of `Config.Command` — trace who sets it (pod annotation?). Assigned to remote-config agent.
- **O4**: `pilot.go:106` `DebugEndpointAuthAllowedNamespaces = sets.New(strings.Split(v, ",")...)` — default v="" => set `{""}`. Neutralized by `namespace==""` early-deny in AuthorizeDebugRequest, but a real smell; if any consumer skips the empty-guard it's an allow-all. Found: reading.

## Confirmed findings
(none yet)

## Dead ends
(none yet)

## Coverage statement
(pending)
