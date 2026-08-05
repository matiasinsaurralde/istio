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

## Confirmed findings
(none yet)

## Dead ends
(none yet)

## Coverage statement
(pending)
