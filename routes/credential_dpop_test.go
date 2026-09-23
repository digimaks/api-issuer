// SPDX-License-Identifier: EUPL-1.2

package routes

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	issuer "github.com/digimaks/api-issuer"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/valyala/fasthttp"
)

func fakeIDAuth(t *testing.T, introspection map[string]any) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/introspection" {
			w.WriteHeader(http.StatusNotFound)

			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(introspection)
	}))
	t.Cleanup(srv.Close)

	return srv
}

func dpopTestApp(t *testing.T, idauthURL string) *azugo.TestApp {
	t.Helper()

	app := issuer.TestAppWithIDAuth(t, idauthURL)
	qt.Assert(t, qt.IsNil(Init(app)))

	return azugo.NewTestApp(app.App)
}

// credentialProof returns a DPoP proof bound to the TestApp public URL
// (https://issuer.example.com/credential) and the given access token, plus
// the key's jkt thumbprint.
func credentialProof(t *testing.T, accessToken string) (string, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))

	x := base64.RawURLEncoding.EncodeToString(key.PublicKey.X.FillBytes(make([]byte, 32)))
	y := base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.FillBytes(make([]byte, 32)))

	tpJSON := `{"crv":"P-256","kty":"EC","x":"` + x + `","y":"` + y + `"}`
	tpSum := sha256.Sum256([]byte(tpJSON))
	jkt := base64.RawURLEncoding.EncodeToString(tpSum[:])

	athSum := sha256.Sum256([]byte(accessToken))

	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"htm": "POST",
		"htu": "https://issuer.example.com/credential",
		"iat": time.Now().Unix(),
		"jti": "jti-" + t.Name(),
		"ath": base64.RawURLEncoding.EncodeToString(athSum[:]),
	})
	tok.Header["typ"] = "dpop+jwt"
	tok.Header["jwk"] = map[string]any{"kty": "EC", "crv": "P-256", "x": x, "y": y}

	proof, err := tok.SignedString(key)
	qt.Assert(t, qt.IsNil(err))

	return proof, jkt
}

func TestCredential_DPoPBoundToken_MissingProofRejected(t *testing.T) {
	_, jkt := credentialProof(t, "the-token")

	srv := fakeIDAuth(t, map[string]any{
		"active":     true,
		"sub":        "subject-1",
		"token_type": "DPoP",
		"cnf":        map[string]string{"jkt": jkt},
	})

	app := dpopTestApp(t, srv.URL)
	app.Start(t)
	defer app.Stop()

	client := app.TestClient()
	resp, err := client.PostJSON("/credential", map[string]any{},
		client.WithHeader("Authorization", "DPoP the-token"))
	qt.Assert(t, qt.IsNil(err))

	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnauthorized))
	qt.Check(t, qt.StringContains(string(resp.Header.Peek("WWW-Authenticate")), "DPoP"))
}

func TestCredential_DPoPBoundToken_WrongKeyRejected(t *testing.T) {
	proof, _ := credentialProof(t, "the-token")

	srv := fakeIDAuth(t, map[string]any{
		"active":     true,
		"sub":        "subject-1",
		"token_type": "DPoP",
		"cnf":        map[string]string{"jkt": "someone-elses-thumbprint"},
	})

	app := dpopTestApp(t, srv.URL)
	app.Start(t)
	defer app.Stop()

	client := app.TestClient()
	resp, err := client.PostJSON("/credential", map[string]any{},
		client.WithHeader("Authorization", "DPoP the-token"),
		client.WithHeader("DPoP", proof))
	qt.Assert(t, qt.IsNil(err))

	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnauthorized))
}

func TestCredential_DPoPBoundToken_ValidProofPassesMiddleware(t *testing.T) {
	proof, jkt := credentialProof(t, "the-token")

	srv := fakeIDAuth(t, map[string]any{
		"active":     true,
		"sub":        "subject-1",
		"token_type": "DPoP",
		"cnf":        map[string]string{"jkt": jkt},
	})

	app := dpopTestApp(t, srv.URL)
	app.Start(t)
	defer app.Stop()

	client := app.TestClient()
	resp, err := client.PostJSON("/credential", map[string]any{},
		client.WithHeader("Authorization", "DPoP the-token"),
		client.WithHeader("DPoP", proof))
	qt.Assert(t, qt.IsNil(err))

	// Middleware must NOT reject; the empty body then fails in the handler
	// with a non-401 status.
	qt.Check(t, qt.Not(qt.Equals(resp.StatusCode(), fasthttp.StatusUnauthorized)))
}

func TestCredential_DPoPBoundToken_BearerSchemeRejected(t *testing.T) {
	proof, jkt := credentialProof(t, "the-token")

	srv := fakeIDAuth(t, map[string]any{
		"active":     true,
		"sub":        "subject-1",
		"token_type": "DPoP",
		"cnf":        map[string]string{"jkt": jkt},
	})

	app := dpopTestApp(t, srv.URL)
	app.Start(t)
	defer app.Stop()

	// RFC 9449 section 7.2: a DPoP-bound token presented with the Bearer
	// scheme must be rejected even when a valid proof accompanies it.
	client := app.TestClient()
	resp, err := client.PostJSON("/credential", map[string]any{},
		client.WithHeader("Authorization", "Bearer the-token"),
		client.WithHeader("DPoP", proof))
	qt.Assert(t, qt.IsNil(err))

	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnauthorized))
	qt.Check(t, qt.StringContains(string(resp.Header.Peek("WWW-Authenticate")), "DPoP"))
}

func TestCredential_UnknownAuthSchemeRejected(t *testing.T) {
	srv := fakeIDAuth(t, map[string]any{
		"active": true,
		"sub":    "subject-1",
	})

	app := dpopTestApp(t, srv.URL)
	app.Start(t)
	defer app.Stop()

	client := app.TestClient()
	resp, err := client.PostJSON("/credential", map[string]any{},
		client.WithHeader("Authorization", "Basic dXNlcjpwYXNz"))
	qt.Assert(t, qt.IsNil(err))

	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnauthorized))
}

func TestCredential_BearerTokenUnaffected(t *testing.T) {
	srv := fakeIDAuth(t, map[string]any{
		"active": true,
		"sub":    "subject-1",
	})

	app := dpopTestApp(t, srv.URL)
	app.Start(t)
	defer app.Stop()

	client := app.TestClient()
	resp, err := client.PostJSON("/credential", map[string]any{},
		client.WithHeader("Authorization", "Bearer the-token"))
	qt.Assert(t, qt.IsNil(err))

	qt.Check(t, qt.Not(qt.Equals(resp.StatusCode(), fasthttp.StatusUnauthorized)))
}
