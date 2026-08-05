// Reproducer against the REAL config-validation webhook handler
// (pkg/webhooks/validation/server). Confirms whether the /validate admit path
// FAILS OPEN or CLOSED on: invalid config, unknown type, undecodable object,
// field smuggling, and a null AdmissionRequest.
//
// Run: go run /home/user/istio/.zeroday/scratch/webhook/repro_validation.go
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"

	v1beta1 "k8s.io/api/admission/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	"istio.io/istio/pkg/config/schema/collections"
	testconfig "istio.io/istio/pkg/test/config"
	valserver "istio.io/istio/pkg/webhooks/validation/server"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func buildServer() (*httptest.Server, func()) {
	mux := http.NewServeMux()
	_, err := valserver.New(valserver.Options{
		Port:         0,
		DomainSuffix: "cluster.local",
		Schemas:      collections.Mocks,
		Mux:          mux,
	})
	must(err)
	srv := httptest.NewServer(mux)
	return srv, func() { srv.Close() }
}

func mockRaw(key string, extraKey bool) []byte {
	r := collections.Mock
	var un unstructured.Unstructured
	un.SetGroupVersionKind(r.GroupVersionKind().Kubernetes())
	un.SetName("mock-config")
	un.Object["spec"] = &testconfig.MockConfig{
		Key:   key,
		Pairs: []*testconfig.ConfigPair{{Key: key, Value: "1"}},
	}
	raw, err := json.Marshal(&un)
	must(err)
	if extraKey {
		trial := map[string]any{}
		must(json.Unmarshal(raw, &trial))
		trial["unexpected_key"] = "x"
		raw, err = json.Marshal(&trial)
		must(err)
	}
	return raw
}

func reviewRaw(kind string, raw []byte) []byte {
	review := v1beta1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{Kind: "AdmissionReview", APIVersion: "admission.k8s.io/v1beta1"},
		Request: &v1beta1.AdmissionRequest{
			Kind:      metav1.GroupVersionKind{Group: "test.istio.io", Version: "v1", Kind: kind},
			Object:    runtime.RawExtension{Raw: raw},
			Operation: v1beta1.Create,
			Namespace: "default",
		},
	}
	b, err := json.Marshal(review)
	must(err)
	return b
}

func post(srv *httptest.Server, body []byte, ct string) (int, *v1beta1.AdmissionResponse, string) {
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/validate", bytes.NewReader(body))
	must(err)
	req.Header.Set("Content-Type", ct)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return -1, nil, "transport error (server panic recovered / conn reset): " + err.Error()
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return resp.StatusCode, nil, string(rb)
	}
	var out v1beta1.AdmissionReview
	if err := json.Unmarshal(rb, &out); err != nil {
		return resp.StatusCode, nil, "non-AdmissionReview body: " + string(rb)
	}
	msg := ""
	if out.Response != nil && out.Response.Result != nil {
		msg = out.Response.Result.Message
	}
	return resp.StatusCode, out.Response, msg
}

func show(name string, st int, r *v1beta1.AdmissionResponse, msg string) {
	allowed := "n/a"
	if r != nil {
		allowed = fmt.Sprintf("%v", r.Allowed)
	}
	fmt.Printf("%-28s HTTP=%d allowed=%s msg=%q\n", name, st, allowed, msg)
}

func main() {
	srv, cleanup := buildServer()
	defer cleanup()

	// 1. Valid config -> allowed true
	st, r, m := post(srv, reviewRaw(collections.Mock.Kind(), mockRaw("key", false)), "application/json")
	show("valid-config", st, r, m)

	// 2. Invalid config (empty Key) -> expect allowed false (fail-closed)
	st, r, m = post(srv, reviewRaw(collections.Mock.Kind(), mockRaw("", false)), "application/json")
	show("invalid-config", st, r, m)

	// 3. Unknown type -> expect allowed false (fail-closed)
	st, r, m = post(srv, reviewRaw("TotallyUnknownKind", mockRaw("key", false)), "application/json")
	show("unknown-type", st, r, m)

	// 4. Undecodable object (Object.Raw is not JSON object) -> expect allowed false
	st, r, m = post(srv, reviewRaw(collections.Mock.Kind(), []byte(`"not-an-object"`)), "application/json")
	show("undecodable-object", st, r, m)

	// 5. Field smuggling (extra top-level key) -> expect allowed false (checkFields)
	st, r, m = post(srv, reviewRaw(collections.Mock.Kind(), mockRaw("key", true)), "application/json")
	show("extra-top-level-field", st, r, m)

	// 6. Wrong content-type -> expect 415
	st, r, m = post(srv, reviewRaw(collections.Mock.Kind(), mockRaw("key", false)), "text/plain")
	show("wrong-content-type", st, r, m)

	// 7. Body that is not an AdmissionReview at all -> decode path
	st, r, m = post(srv, []byte(`{"foo":"bar"}`), "application/json")
	show("not-an-admissionreview", st, r, m)

	// 8. AdmissionReview with request:null -> nil ar.Request deref (server.go:197)
	st, r, m = post(srv, []byte(`{"kind":"AdmissionReview","apiVersion":"admission.k8s.io/v1beta1","request":null}`), "application/json")
	show("request-null", st, r, m)
}
