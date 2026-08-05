#!/usr/bin/env bash
# Reproducers for the fork's custom debug-endpoint namespace-authz audit.
# The *_test.go files must live in the package dir to access unexported code;
# runnable copies are kept at pilot/pkg/xds/zeroday_*_test.go (archived here too).
set -euo pipefail
cd /home/user/istio
echo "== SOUND: cross-namespace read is denied; empty-ns/system-ns only via mis-issued cert =="
go test ./pilot/pkg/xds/ -run '^(TestCore_getDebugConnection|TestXDSPath_DebugGen)$' -v -count=1 2>&1 | grep -v '^2026-\|unable to resolve'
echo
echo "== REFUTED: no allowlist-vs-dispatch divergence bypass =="
go test ./pilot/pkg/xds/ -run '^TestAllowlistVsDispatch$' -count=1 2>&1 | grep -v '^2026-\|unable to resolve' | tail -2
echo
echo "== CONFIRMED DoS: malformed XDS debug resourceName crashes istiod (nil-deref, no recover) =="
go test ./pilot/pkg/xds/ -run '^(TestRealParseAndValidatePanic|TestZeroDayADSCrash_Parent)$' -v -count=1 2>&1 | grep -v '^2026-\|unable to resolve'
