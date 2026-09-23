// SPDX-License-Identifier: EUPL-1.2

package routes

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	issuer "github.com/digimaks/api-issuer"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// fakeIDAuthWithPreauth creates a test HTTP server that handles both
// /introspection and /preauth_generate endpoints.
func fakeIDAuthWithPreauth(t *testing.T) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/preauth_generate":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"preauth_code": "test-preauth-code",
				"tx_code":      12345,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	return srv
}

func offerTestApp(t *testing.T, idauthURL string) *azugo.TestApp {
	t.Helper()

	app := issuer.TestAppWithIDAuth(t, idauthURL)
	qt.Assert(t, qt.IsNil(Init(app)))

	return azugo.NewTestApp(app.App)
}

func offerRequestBody(grantTypes []string) map[string]any {
	return map[string]any{
		"credentialIds": []string{"eu.europa.ec.eudi.pid_digimaks_vc_sd_jwt"},
		"grantTypes":    grantTypes,
		"form":          map[string]any{},
	}
}

// decodeOfferGrants extracts the grants object from the haip-vci:// deep link.
func decodeOfferGrants(t *testing.T, urlData string) map[string]any {
	t.Helper()

	idx := strings.Index(urlData, "credential_offer=")
	qt.Assert(t, qt.IsTrue(idx >= 0))

	raw, err := url.QueryUnescape(urlData[idx+len("credential_offer="):])
	qt.Assert(t, qt.IsNil(err))

	offer := map[string]any{}
	qt.Assert(t, qt.IsNil(json.Unmarshal([]byte(raw), &offer)))

	grants, ok := offer["grants"].(map[string]any)
	qt.Assert(t, qt.IsTrue(ok))

	return grants
}

func TestGenerateOffer_AuthorizationCodeGrantOnly(t *testing.T) {
	// authorization_code-only must NOT hit IDAuth at all — use a server that
	// returns 500 for any request to prove it's never called.
	idauthSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(idauthSrv.Close)

	app := offerTestApp(t, idauthSrv.URL)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().PostJSON("/generate_credential_offer",
		offerRequestBody([]string{"authorization_code"}))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))

	buf, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))

	body := map[string]any{}
	qt.Assert(t, qt.IsNil(json.Unmarshal(buf, &body)))

	grants := decodeOfferGrants(t, body["urlData"].(string))

	authCode, ok := grants["authorization_code"].(map[string]any)
	qt.Assert(t, qt.IsTrue(ok))

	issuerState, _ := authCode["issuer_state"].(string)
	qt.Check(t, qt.Not(qt.Equals(issuerState, "")))

	_, hasPreAuth := grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
	qt.Check(t, qt.IsFalse(hasPreAuth))
}

func TestGenerateOffer_DefaultRemainsPreAuthorizedOnly(t *testing.T) {
	srv := fakeIDAuthWithPreauth(t)
	app := offerTestApp(t, srv.URL)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().PostJSON("/generate_credential_offer",
		offerRequestBody(nil))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))

	buf, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))

	body := map[string]any{}
	qt.Assert(t, qt.IsNil(json.Unmarshal(buf, &body)))

	grants := decodeOfferGrants(t, body["urlData"].(string))

	_, hasPreAuth := grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
	qt.Check(t, qt.IsTrue(hasPreAuth))

	_, hasAuthCode := grants["authorization_code"]
	qt.Check(t, qt.IsFalse(hasAuthCode))
}

func TestGenerateOffer_RejectsUnknownGrantType(t *testing.T) {
	srv := fakeIDAuthWithPreauth(t)
	app := offerTestApp(t, srv.URL)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().PostJSON("/generate_credential_offer",
		offerRequestBody([]string{"implicit"}))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnprocessableEntity))
}
