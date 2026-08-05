package authzattach

import (
	"math/rand"
	"testing"

	"istio.io/istio/pkg/config/labels"
)

// independent definition: sel is a subset of wl iff every key in sel is in wl with equal value.
func refSubset(sel, wl map[string]string) bool {
	for k, v := range sel {
		if wl[k] != v || func() bool { _, ok := wl[k]; return !ok }() {
			return false
		}
	}
	return true
}

// TestSubsetOf independently fuzzes labels.Instance.SubsetOf (the core selector primitive
// used by isSelected / FilterSelects / PeerAuthentication attach).
func TestSubsetOf(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	keys := []string{"a", "b", "c", "gateway.networking.k8s.io/gateway-name", "app"}
	vals := []string{"1", "2", "", "web", "x"}
	mk := func() map[string]string {
		m := map[string]string{}
		for i := 0; i < rng.Intn(4); i++ {
			m[keys[rng.Intn(len(keys))]] = vals[rng.Intn(len(vals))]
		}
		return m
	}
	diverged := 0
	for i := 0; i < 2_000_000; i++ {
		sel := mk()
		wl := mk()
		got := labels.Instance(sel).SubsetOf(labels.Instance(wl))
		want := refSubset(sel, wl)
		if got != want {
			diverged++
			if diverged <= 10 {
				t.Errorf("SubsetOf diverge: sel=%v wl=%v got=%v want=%v", sel, wl, got, want)
			}
		}
	}
	if diverged > 0 {
		t.Fatalf("SubsetOf diverged %d times", diverged)
	}
}
