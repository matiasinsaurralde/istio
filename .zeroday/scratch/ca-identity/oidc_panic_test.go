package caidentity

// Reproducer: JwtAuthenticator (security/pkg/server/ca/authenticate/oidc.go) panics
// with "index out of range" when a VERIFIED token has a `sub` that begins with
// "system:serviceaccount" but has fewer than 4 colon-separated parts.
//
// This exercises the REAL authenticator: it builds a real JwtAuthenticator via
// NewJwtAuthenticator against a local JWKS server, signs a real token with that
// key, and calls the real Authenticate() entrypoint (gRPC bearer-token path).
//
// oidc.go:
//   if !strings.HasPrefix(sa.Sub, "system:serviceaccount") { return err }
//   parts := strings.Split(sa.Sub, ":")
//   ns := parts[2]     // <-- panics if len(parts) < 3
//   ksa := parts[3]    // <-- panics if len(parts) < 4
//
// Compare tokenreview.go (the Kube path) which DOES guard: len(subStrings) != 4.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"google.golang.org/grpc/metadata"

	meshconfig "istio.io/api/mesh/v1alpha1"
	"istio.io/api/security/v1beta1"
	"istio.io/istio/pkg/config/mesh/meshwatcher"
	"istio.io/istio/pkg/security"
	"istio.io/istio/security/pkg/server/ca/authenticate"
)

type jwksServer struct {
	key jose.JSONWebKeySet
}

func (k *jwksServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_ = json.NewEncoder(w).Encode(k.key)
}

func signJWT(key *jose.JSONWebKey, claims []byte) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(key.Algorithm),
		Key:       key,
	}, nil)
	if err != nil {
		return "", err
	}
	sig, err := signer.Sign(claims)
	if err != nil {
		return "", err
	}
	return sig.CompactSerialize()
}

func buildAuthenticator(t *testing.T) (*authenticate.JwtAuthenticator, *jose.JSONWebKey, string) {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	key := jose.JSONWebKey{Algorithm: string(jose.RS256), Key: rsaKey}
	keySet := jose.JSONWebKeySet{}
	keySet.Keys = append(keySet.Keys, key.Public())
	server := httptest.NewServer(&jwksServer{key: keySet})
	t.Cleanup(server.Close)

	jwtRuleStr := `{"issuer": "` + server.URL + `", "jwks_uri": "` + server.URL + `", "audiences": ["istio-ca"]}`
	jwtRule := v1beta1.JWTRule{}
	if err := json.Unmarshal([]byte(jwtRuleStr), &jwtRule); err != nil {
		t.Fatalf("unmarshal rule: %v", err)
	}
	authr, err := authenticate.NewJwtAuthenticator(&jwtRule,
		meshwatcher.NewTestWatcher(&meshconfig.MeshConfig{TrustDomain: "cluster.local"}))
	if err != nil {
		t.Fatalf("NewJwtAuthenticator: %v", err)
	}
	return authr, &key, server.URL
}

func callAuthenticate(t *testing.T, authr *authenticate.JwtAuthenticator, key *jose.JSONWebKey, issuer, sub string) (caller *security.Caller, err error, panicked any) {
	t.Helper()
	expStr := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	claims := fmt.Sprintf(`{"iss": %q, "aud": ["istio-ca"], "sub": %q, "exp": %s}`, issuer, sub, expStr)
	token, err := signJWT(key, []byte(claims))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	ctx := context.Background()
	md := metadata.MD{}
	md.Append("authorization", "Bearer "+token)
	ctx = metadata.NewIncomingContext(ctx, md)

	defer func() {
		if r := recover(); r != nil {
			panicked = r
		}
	}()
	caller, err = authr.Authenticate(security.AuthContext{GrpcContext: ctx})
	return
}

func TestOIDCMalformedSubPanic(t *testing.T) {
	authr, key, issuer := buildAuthenticator(t)

	// These all pass HasPrefix("system:serviceaccount") but split into <4 parts.
	malformed := []string{
		"system:serviceaccount",       // 2 parts -> parts[2] panics
		"system:serviceaccount:onlyns", // 3 parts -> parts[3] panics
		"system:serviceaccountXYZ",    // 2 parts (no 2nd colon) -> parts[2] panics
	}
	for _, sub := range malformed {
		t.Run(sub, func(t *testing.T) {
			caller, err, panicked := callAuthenticate(t, authr, key, issuer, sub)
			if panicked != nil {
				t.Logf("CONFIRMED PANIC for sub=%q: %v", sub, panicked)
				return
			}
			t.Errorf("NO PANIC for sub=%q (caller=%v err=%v) -- bug not reproduced", sub, caller, err)
		})
	}
}

func TestOIDCWellFormedSubImpersonation(t *testing.T) {
	// Control: a well-formed sub yields whatever ns/sa are embedded -> becomes the cert SAN.
	authr, key, issuer := buildAuthenticator(t)
	caller, err, panicked := callAuthenticate(t, authr, key, issuer, "system:serviceaccount:kube-system:istiod")
	if panicked != nil {
		t.Fatalf("unexpected panic: %v", panicked)
	}
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	t.Logf("well-formed sub -> identities: %v (these become the issued cert SANs)", caller.Identities)
}
