package caidentity

// Reproducer: RunCA() (pilot/pkg/bootstrap/istio_ca.go:183) constructs the OIDC
// authenticator as NewJwtAuthenticator(&jwtRule, nil) -- meshHolder is nil --
// on the out-of-cluster path (KUBERNETES_SERVICE_HOST unset). On a SUCCESSFUL
// authentication of a *valid, well-formed* token the code executes:
//     spiffe.MustGenSpiffeURI(j.meshHolder.Mesh(), ns, ksa)
// which calls .Mesh() on a nil mesh.Holder interface -> nil pointer panic.
//
// This exercises the real NewJwtAuthenticator + Authenticate with nil meshHolder,
// exactly as RunCA wires it.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"google.golang.org/grpc/metadata"

	"istio.io/api/security/v1beta1"
	"istio.io/istio/pkg/security"
	"istio.io/istio/security/pkg/server/ca/authenticate"
)

func TestOIDCNilMeshHolderPanicOnValidToken(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	key := jose.JSONWebKey{Algorithm: string(jose.RS256), Key: rsaKey}
	keySet := jose.JSONWebKeySet{}
	keySet.Keys = append(keySet.Keys, key.Public())
	server := httptest.NewServer(&jwksServer{key: keySet})
	defer server.Close()

	jwtRuleStr := `{"issuer": "` + server.URL + `", "jwks_uri": "` + server.URL + `", "audiences": ["istio-ca"]}`
	jwtRule := v1beta1.JWTRule{}
	if err := json.Unmarshal([]byte(jwtRuleStr), &jwtRule); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// EXACTLY as RunCA does it: nil meshHolder.
	authr, err := authenticate.NewJwtAuthenticator(&jwtRule, nil)
	if err != nil {
		t.Fatalf("NewJwtAuthenticator: %v", err)
	}

	// A perfectly valid, well-formed service-account token.
	expStr := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	claims := fmt.Sprintf(`{"iss": %q, "aud": ["istio-ca"], "sub": "system:serviceaccount:foo:bar", "exp": %s}`, server.URL, expStr)
	token, err := signJWT(&key, []byte(claims))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("authorization", "Bearer "+token))

	var panicked any
	func() {
		defer func() { panicked = recover() }()
		_, _ = authr.Authenticate(security.AuthContext{GrpcContext: ctx})
	}()
	if panicked == nil {
		t.Errorf("expected nil-meshHolder panic on valid token, got none")
		return
	}
	t.Logf("CONFIRMED nil-meshHolder panic on a VALID token: %v", panicked)
}
