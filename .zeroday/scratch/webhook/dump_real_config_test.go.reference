package inject

import (
	"os"
	"testing"

	"sigs.k8s.io/yaml"

	"istio.io/istio/pkg/config/mesh"
)

// Throwaway: dump the REAL rendered injector config (full default template),
// values, and mesh config to scratch so a standalone reproducer can load them.
func TestZZDumpRealConfig(t *testing.T) {
	cfg, values, mc := getInjectionSettings(t, nil, "")
	dir := "/home/user/istio/.zeroday/scratch/webhook"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfgBytes, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/real-inject-config.yaml", cfgBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/real-values.yaml", []byte(values.raw), 0o644); err != nil {
		t.Fatal(err)
	}
	if mc == nil {
		mc = mesh.DefaultMeshConfig()
	}
	mcBytes, err := yaml.Marshal(mc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/real-mesh.yaml", mcBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("dumped config(%d) values(%d) mesh(%d)", len(cfgBytes), len(values.raw), len(mcBytes))
}
