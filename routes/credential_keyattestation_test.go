// SPDX-License-Identifier: EUPL-1.2

package routes

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-quicktest/qt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/valyala/fasthttp"
)

// bareJWKProofJWT returns a minimal ES256-signed proof JWT with the holder key
// in the jwk header field (no key_attestation).
func bareJWKProofJWT(t *testing.T) string {
	t.Helper()

	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))

	x := base64.RawURLEncoding.EncodeToString(holderKey.PublicKey.X.FillBytes(make([]byte, 32)))
	y := base64.RawURLEncoding.EncodeToString(holderKey.PublicKey.Y.FillBytes(make([]byte, 32)))

	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{})
	tok.Header["alg"] = "ES256"
	tok.Header["jwk"] = map[string]any{"kty": "EC", "crv": "P-256", "x": x, "y": y}

	s, err := tok.SignedString(holderKey)
	qt.Assert(t, qt.IsNil(err))

	return s
}

// attestedProofJWT returns a minimal ES256-signed proof JWT whose header contains
// a key_attestation JWT with key_storage="iso_18045_high" and the holder key in
// attested_keys. The attestation is signed by an unrelated issuer key — issuer-go
// does not verify the attestation signature (trust is delegated upstream).
func attestedProofJWT(t *testing.T) string {
	t.Helper()

	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))

	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))

	x := base64.RawURLEncoding.EncodeToString(holderKey.PublicKey.X.FillBytes(make([]byte, 32)))
	y := base64.RawURLEncoding.EncodeToString(holderKey.PublicKey.Y.FillBytes(make([]byte, 32)))

	kaTok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"key_storage": []string{"iso_18045_high"},
		"attested_keys": []map[string]any{
			{"kty": "EC", "crv": "P-256", "x": x, "y": y},
		},
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	kaTok.Header["typ"] = "keyattestation+jwt"

	ka, err := kaTok.SignedString(issuerKey)
	qt.Assert(t, qt.IsNil(err))

	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{})
	tok.Header["alg"] = "ES256"
	tok.Header["key_attestation"] = ka

	s, err := tok.SignedString(holderKey)
	qt.Assert(t, qt.IsNil(err))

	return s
}

func postCredential(t *testing.T, srv *httptest.Server, proofJWT string) *fasthttp.Response {
	t.Helper()

	app := dpopTestApp(t, srv.URL)
	app.Start(t)
	t.Cleanup(app.Stop)

	client := app.TestClient()

	resp, err := client.PostJSON("/credential", map[string]any{
		"credential_configuration_id": "eu.europa.ec.eudi.pid_digimaks_pid_mdoc",
		"proofs": map[string]any{
			"jwt": []string{proofJWT},
		},
	}, client.WithHeader("Authorization", "Bearer test-token"))
	qt.Assert(t, qt.IsNil(err))

	return resp
}

func TestCredential_IDAuthPath_RejectsBareJWKWhenAttestationRequired(t *testing.T) {
	srv := fakeIDAuth(t, map[string]any{
		"active":     true,
		"sub":        "subject-1",
		"token_type": "Bearer",
	})

	resp := postCredential(t, srv, bareJWKProofJWT(t))

	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))

	body, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))

	var problem map[string]any
	qt.Assert(t, qt.IsNil(json.Unmarshal(body, &problem)))
	qt.Check(t, qt.Equals(problem["code"], "err:credential:keyAttestationRequired"))
}

func TestCredential_IDAuthPath_EnforcedRejectsInvalidWUA(t *testing.T) {
	// attestedProofJWT's key-attestation JWT carries no x5c header, so
	// ValidateWUA always fails it (Phase 3). With enforcement on, that
	// failure must reject the request instead of being logged only.
	t.Setenv("ISSUER_WUA_VERIFICATION_ENFORCED", "true")

	srv := fakeIDAuth(t, map[string]any{
		"active":     true,
		"sub":        "subject-1",
		"token_type": "Bearer",
	})

	resp := postCredential(t, srv, attestedProofJWT(t))

	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))

	body, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))

	var problem map[string]any
	qt.Assert(t, qt.IsNil(json.Unmarshal(body, &problem)))
	qt.Check(t, qt.Equals(problem["code"], "err:credential:keyAttestationInvalid"))
}

func TestCredential_IDAuthPath_AcceptsAttestedProofWhenRequired(t *testing.T) {
	srv := fakeIDAuth(t, map[string]any{
		"active":     true,
		"sub":        "subject-1",
		"token_type": "Bearer",
	})

	resp := postCredential(t, srv, attestedProofJWT(t))

	// Must NOT be rejected for missing attestation — status depends on how
	// far issuance proceeds in this test's minimal fixture (signing cert
	// etc. may not be configured), but it must not be the 400 attestation
	// rejection specifically.
	if resp.StatusCode() == fasthttp.StatusBadRequest {
		body, _ := resp.BodyUncompressed()

		var problem map[string]any
		_ = json.Unmarshal(body, &problem)
		qt.Check(t, qt.Not(qt.Equals(problem["code"], "err:credential:keyAttestationRequired")))
	}
}
