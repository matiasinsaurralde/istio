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
| D | DNS proxy parser | malformed query → crash | BLOCKED (11.3M fuzz execs, no crash; miekg guards) |
| E | HBONE / h2 handling | request smuggling / auth bypass | OPEN |
| F | injection webhook | template/param injection → RCE or SSRF | OPEN |
| G | JWT validation | signature/aud/iss bypass | OPEN |
| H | XDS authz (node/proxy) | one proxy reads another's secrets/config | OPEN |

## Leads (orchestrator hand-read, not yet confirmed)
- **L1 (HIGH): Debug-endpoint namespace authorization is CUSTOM code** (`pilot/pkg/xds/debug.go`, `debuggen.go`). `ENABLE_DEBUG_ENDPOINT_AUTH` default **true**. Two entry points to debug handlers: (1) HTTP `allowAuthenticatedOrLocalhost`; (2) XDS `DebugType` via `DebugGen.Generate`->`processDebugRequest` dispatching through **internalMux (UNAUTHENTICATED)**. Non-system callers limited to `activeNamespaceDebuggers={config_dump,ndsz,edsz}`, all routed to `ConfigDump`, gated by `getDebugConnection` (requires `?proxyID=`, enforces `con.proxy.ConfigNamespace==callerNamespace`). **config_dump INCLUDES SDS secret private keys** (connectionConfigDump SecretsConfigDump) => any bypass of the namespace check = cross-tenant private-key theft / impersonation. On careful reading the check looks correct; needs an adversarial reproducer through the real DebugGen XDS path. Sub-questions: (a) URL-parse mismatch between `parseAndValidateDebugRequest` (u.Path of resourceName) and ServeMux path-clean dispatch; (b) any handler in allowlist not requiring proxyID; (c) `callerNamespace==""` reachable on an authenticated path; (d) systemNamespace value passed to NewDebugGen (discovery.go). Found: reading.
- **O1**: `xfcc_authenticator.go:93` `netip.MustParseAddr(ip).IsLoopback()` — panics if peer IP unpar?eable; reachable only after trusted-CIDR loop misses. Likely benign (SplitHostPort yields valid IP) — verify. Found: rule (MustParse sweep).
- **O2**: `pkg/wasm/httpfetcher.go:57` InsecureSkipVerify gated by `allowInsecure(host)` — check gating source. Found: rule.
- **L1 UPDATE (leaning SOUND):** orchestrator re-reasoned the debug-auth control. Allowlist is an EXACT map lookup on `u.Path`/`TrimPrefix(URL.Path,"/debug/")`, so path tricks change the key and fail; all 3 allowed endpoints route through `ConfigDump`→`getDebugConnection` namespace check. Only skip is `callerNamespace==""`, which needs an empty-namespace mesh cert the CA won't issue (checkConnectionIdentity ties VerifiedIdentity to a real cert). No bypass found by reading; downgraded — still worth one adversarial reproducer agent, but likely a correct control (foil).
- **VERIFIED (orchestrator re-ran):** F3 OIDC `sub` panic and O1 XFCC `MustParseAddr` panic both reproduce against REAL authenticators (`go test ./.zeroday/scratch/ca-identity/`). F1 confirmed via real in-package `wasm` test.
- **O3**: `pkg/istio-agent/health/health_probers.go:262` exec of `Config.Command` — trace who sets it (pod annotation?). Assigned to remote-config agent.
- **O4**: `pilot.go:106` `DebugEndpointAuthAllowedNamespaces = sets.New(strings.Split(v, ",")...)` — default v="" => set `{""}`. Neutralized by `namespace==""` early-deny in AuthorizeDebugRequest, but a real smell; if any consumer skips the empty-guard it's an allow-all. Found: reading.

## Confirmed / strong candidates
- **F1 (SSRF, custom control bypass) — `pkg/wasm/imagefetcher.go:69-156` `ssrfProtectionTransport` / `validateRealmURL`.** CUSTOM SSRF filter over the OCI `WWW-Authenticate` bearer realm. Bypasses (all confirmed by probe `.zeroday/scratch/remote-config/ssrf_repro/main.go`):
  - case-sensitive exact matches: `host=="localhost"`, `host=="metadata.google.internal"` → `LOCALHOST`, `Metadata.Google.Internal` pass;
  - trailing-dot FQDN `metadata.google.internal.` passes;
  - `0.0.0.0` (and IPv6 `[::]`) not classified private/loopback/link-local → passes, routes to loopback on Linux;
  - **DNS-name bypass (general)**: filter only inspects *literal* IPs (`net.ParseIP`); any hostname that A-resolves to 169.254.169.254 / 127.0.0.1 / RFC1918 passes and is resolved at dial time.
  Exploit: attacker-controlled OCI registry (referenced by a WasmPlugin) returns 401 with `realm="http://169.254.169.254/…"`; fetcher authenticates against it and forwards the internal response as `Authorization: Bearer` to the attacker's registry ⇒ cloud metadata / IAM credential exfiltration from the fetcher's network position.
  REACHABILITY (confirmed by remote-config agent): `cache.Get`←`MaybeConvertWasmExtensionConfig` runs in **istio-agent** (`xds_proxy.go:537`), fetching a `WasmPlugin` whose `url`/`sha256` a **namespace-scoped user** sets. OCI branch → `NewImageFetcher`/`PrepareFetch` does the registry handshake gated by the broken filter. Boundary: namespace RBAC / external registry → node network position + cloud metadata (→ node cloud creds). Blind SSRF; response consumed as bearer token (credential exfil to attacker registry).
  - **F1b (direct SSRF, no guard at all):** the plain `http(s)` primary-fetch path `pkg/wasm/httpfetcher.go:72-89` applies NO `ssrfProtectionTransport`; `WasmPlugin url: http://169.254.169.254/...` is a direct blind SSRF from the agent. 
  - **F1c (parser-differential, unverified):** `validateAllRealms` only finds the literal substring `realm="`; an unquoted realm (`Bearer realm=http://169.254.169.254/`) yields "no realms" → passes the gate while go-containerregistry may still parse it.
  STATUS: **CONFIRMED via REAL code path** — `pkg/wasm/ssrf_bypass_zeroday_test.go` (`go test -tags zeroday_repro -run TestZeroDay ./pkg/wasm/`) calls the actual `validateAllRealms`/`ssrfProtectionTransport.RoundTrip`; all 8 bypasses ALLOWED, end-to-end loopback reach confirmed. Found: reading + probe (remote-config agent) + orchestrator real-path test.
- **F3 (control-plane DoS, panic) — OIDC authenticator `sub` parsing — `security/pkg/server/ca/authenticate/oidc.go:104-109`.** `if !strings.HasPrefix(sa.Sub, "system:serviceaccount")` (note: NO trailing colon) then `parts := strings.Split(sa.Sub, ":"); ns := parts[2]; ksa := parts[3]` with no length check ⇒ `sub="system:serviceaccount"` or `"system:serviceaccountX"` → index-out-of-range panic. **No grpc/istiod panic-recovery interceptor** ⇒ istiod process crash. Panic is reached BEFORE the audience check (line 110), so any token merely signed by the trusted issuer (any audience) with a crafted `sub` triggers it. Sibling KubeJWT path guards this (`k8s/tokenreview/k8sauthn.go:103` `len(subStrings)!=4`) — the inconsistency is the tell. Wired into BOTH CA and XDS authenticators when `JWT_RULE`/OIDC issuer configured, or external-CA mode; NOT default in-cluster. CONFIRMED via real authenticator reproducer (ca-identity agent, `.zeroday/scratch/ca-identity/`). Sev: Medium/High (conditional). Found: reading (oidc vs tokenreview inconsistency) + repro.
- **F4 (DoS, panic) — OIDC nil meshHolder — `pilot/pkg/bootstrap/istio_ca.go:183` + `oidc.go:115`.** `RunCA` constructs `NewJwtAuthenticator(&jwtRule, nil)`; on a *valid* token, `j.meshHolder.Mesh()` nil-derefs. External/standalone CA mode only. CONFIRMED via real reproducer. Sev: Medium (conditional). Found: reading + repro.
- **O1 CONFIRMED latent — XFCC `netip.MustParseAddr` panic — `xfcc_authenticator.go:93,103`.** Panics if peer host is non-IP (empty/hostname). Needs `TRUSTED_GATEWAY_CIDR` set (XFCC off by default) AND a non-IP peer; no standard transport yields that ⇒ latent robustness bug, not a confirmed remote trigger. Found: rule + probe.
- **DEAD (test-only) — HBONE unauth open CONNECT proxy — `pkg/hbone/server.go:138-171`.** Real unauth SSRF/open-relay, but `hbone.NewServer()` is wired ONLY into the test echo server; no shipping binary imports it. Blast radius = echo test workloads, not core Istio. Recorded, not headlined. (Also: implicit 200 before dial masks 503; UDS `chmod 0o666` smell at `pkg/uds/uds.go:49`.) Found: reading + repro (hbone agent).
- **F2 (SSRF, control-plane) — istiod JWKS resolver `pilot/pkg/model/jwks_resolver.go`.** Custom `BLOCKED_CIDRS_IN_JWKS_URIS` control. Dialer `blockedCIDRDialContext` (line 604) uses `net.Dialer.Control` on the **resolved** IP — architecturally CORRECT vs DNS rebinding; CIDR parse (pilot.go:364) looks correct. BUT default is empty ⇒ **no protection at all by default**, so istiod fetches any attacker `jwksUri`/`issuer` from a namespaced RequestAuthentication (openid discovery + jwks fetch) — control-plane blind SSRF unless operator opts in. Likely matches upstream (opt-in hardening), so NOT a code bug — marking the dialer REVIEWED-correct; keeping default-off SSRF as a documented risk, not a planted-bug claim. Found: reading (orchestrator).

## Dead ends (refuted — do not re-tread)
- CSR-SAN impersonation via CA: SAN built only from authenticated identity; CSR contributes only pubkey (`GenCertFromCSR`/`genCertTemplateFromCSR`). REFUTED.
- KubeJWT `sub` panic: guarded by `len(subStrings)!=4`. REFUTED.
- Node impersonation bypass (`node_auth.go`): requires CA_TRUSTED_NODE_ACCOUNTS + pod UID/SA/node match. REFUTED.
- ClientCert/ExtractIDs extra identities: from CA-verified chain SANs the CA itself set. REFUTED.
- WASM checksum path traversal (`getModulePath`): sink traversable in isolation but unreachable — path built from COMPUTED sha256 hex, not user `opts.Checksum`. REFUTED.
- secretcache symlink traversal: resolved target only feeds fsnotify watchers, not served cert bytes. REFUTED.
- ExecProber `Config.Command`: sourced from pod's own ProxyConfig/readiness spec (pod owner already runs code in pod). No trust-boundary crossing. REFUTED.
- xds_proxy cross-workload secret leak: downstream bound to per-container UDS; upstream uses agent's OWN creds; Envoy metadata not propagated. REFUTED (defaults).
- HBONE crash/panic DoS: real server survives malformed CONNECT/h2 + reset storm under -race; x/net/http2 caps streams at 250. REFUTED.
- h2c "unsafe wrapper": `pkg/h2c` doesn't exist here; no prod code uses raw h2c; istiod h2c hardened + non-default. DEAD END.
- JWKS `blockedCIDRDialContext`: uses `Dialer.Control` on RESOLVED IP — correct vs DNS rebinding; CIDR parse correct. REVIEWED-correct (default-off = opt-in hardening, matches upstream). Not a code bug.
- **DNS proxy crash/DoS (whole family): BLOCKED.** istio-agent DNS proxy (`pkg/dns/client/`) fuzzed via real handler (`FuzzServeDNSRaw` 7.2M, `FuzzServeDNSStructured` 2.9M, `FuzzLookupHost` 1M+, `FuzzBuildDNSAnswers` 589K) + 2007-payload raw-socket blast against real `LocalDNSServer`; ZERO panics/hangs/OOM. 8 candidates refuted (O(n²) wildcard bounded by miekg 255-octet budget; CNAME assertion invariant; roundRobin index math; Question[0] guarded; EDNS Truncate shrink-only; compression-pointer cap). Only minor: `queryUpstreamParallel` blocks forever if resolv.conf empty (not query-triggerable). Harnesses in `pkg/dns/client/zz_zeroday_*_test.go`.

## Coverage statement
(pending)
