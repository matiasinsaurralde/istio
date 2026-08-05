package main

// Refutation probe for lead #1 (WasmPlugin sha256 -> path traversal on write).
// getModulePath copied VERBATIM from pkg/wasm/cache.go:188-196 (stdlib only).

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type moduleKey struct{ name, checksum string }

// ===== verbatim copy: pkg/wasm/cache.go:188-196 =====
func getModulePath(baseDir string, mkey moduleKey) (string, error) {
	sha := sha256.Sum256([]byte(mkey.name))
	hashedName := hex.EncodeToString(sha[:])
	moduleDir := filepath.Join(baseDir, hashedName)
	if err := os.Mkdir(moduleDir, 0o755); err != nil && !os.IsExist(err) {
		return "", err
	}
	return filepath.Join(moduleDir, fmt.Sprintf("%s.wasm", mkey.checksum)), nil
}
// ===== end verbatim =====

func main() {
	cdir, _ := os.MkdirTemp("", "cdir") // stands in for LocalFileCache.dir
	defer os.RemoveAll(cdir)

	// (1) attacker-controlled checksum reaching the sink WOULD escape c.dir:
	evil := moduleKey{name: "oci://reg/x:latest", checksum: "../../../../../../tmp/PWNED"}
	p, _ := getModulePath(cdir, evil)
	cleaned := filepath.Clean(p)
	fmt.Printf("attacker checksum  -> %s\n", cleaned)
	fmt.Printf("   escapes c.dir(%s)? %v\n", cdir, !strings.HasPrefix(cleaned, cdir+"/"))

	// (2) value actually passed by cache.go (computed sha256 hex) is inert:
	d := sha256.Sum256([]byte("\x00asm\x01\x00\x00\x00"))
	good := moduleKey{name: "oci://reg/x:latest", checksum: hex.EncodeToString(d[:])}
	p2, _ := getModulePath(cdir, good)
	fmt.Printf("computed dChecksum -> %s\n", filepath.Clean(p2))
	fmt.Printf("   escapes c.dir? %v\n", !strings.HasPrefix(filepath.Clean(p2), cdir+"/"))
}
