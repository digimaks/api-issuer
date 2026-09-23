// SPDX-License-Identifier: EUPL-1.2

package routes

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	issuer "github.com/digimaks/api-issuer"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// fakeIDAuthEchoSession serves /preauth_generate returning sessionID —
// generated (like idauth does) when the caller sent none, echoed otherwise.
func fakeIDAuthEchoSession(t *testing.T, generated string) (*httptest.Server, *string) {
	t.Helper()

	var lastSessionID string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/preauth_generate" {
			w.WriteHeader(http.StatusNotFound)

			return
		}

		_ = r.ParseForm()

		lastSessionID = r.Form.Get("session_id")
		if lastSessionID == "" {
			lastSessionID = generated
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"preauth_code": "test-preauth-code",
			"session_id":   lastSessionID,
			"tx_code":      12345,
		})
	}))
	t.Cleanup(srv.Close)

	return srv, &lastSessionID
}

// offerFormTestApp registers the normal routes plus a test-only endpoint
// exposing the offer form cache, since GetFormData needs a request context.
func offerFormTestApp(t *testing.T, idauthURL string) *azugo.TestApp {
	t.Helper()

	app := issuer.TestAppWithIDAuth(t, idauthURL)
	qt.Assert(t, qt.IsNil(Init(app)))

	app.Get("/test/form-data/{sid}", func(ctx *azugo.Context) {
		data, ok := app.OpenID4VCI().GetFormData(ctx, ctx.Params.String("sid"))
		if !ok {
			ctx.StatusCode(fasthttp.StatusNotFound)

			return
		}

		ctx.JSON(data)
	})

	return azugo.NewTestApp(app.App)
}

func TestGenerateOffer_FormCachedUnderIDAuthGeneratedSession(t *testing.T) {
	srv, _ := fakeIDAuthEchoSession(t, "GEN123")
	app := offerFormTestApp(t, srv.URL)
	app.Start(t)
	defer app.Stop()

	body := map[string]any{
		"credentialIds": []string{"eu.europa.ec.eudi.pid_digimaks_vc_sd_jwt"},
		// no sessionId, no personal_administrative_number — idauth generates
		"form": map[string]any{"name": "Anna", "employee_id": "EMP-DE-00789"},
	}

	resp, err := app.TestClient().PostJSON("/generate_credential_offer", body)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))

	formResp, err := app.TestClient().Get("/test/form-data/GEN123")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(formResp.StatusCode(), fasthttp.StatusOK))

	buf, err := formResp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))

	cached := map[string]any{}
	qt.Assert(t, qt.IsNil(json.Unmarshal(buf, &cached)))
	qt.Check(t, qt.Equals(cached["name"].(string), "Anna"))
	qt.Check(t, qt.Equals(cached["employee_id"].(string), "EMP-DE-00789"))
}

func TestGenerateOffer_FormCachedUnderCallerSession(t *testing.T) {
	srv, _ := fakeIDAuthEchoSession(t, "UNUSED")
	app := offerFormTestApp(t, srv.URL)
	app.Start(t)
	defer app.Stop()

	body := map[string]any{
		"credentialIds": []string{"eu.europa.ec.eudi.pid_digimaks_vc_sd_jwt"},
		"form":          map[string]any{"personal_administrative_number": "PAN-42", "given_name": "Anna"},
	}

	resp, err := app.TestClient().PostJSON("/generate_credential_offer", body)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))

	// idauth echoed the PAN back — cache key identical to the legacy flow.
	formResp, err := app.TestClient().Get("/test/form-data/PAN-42")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(formResp.StatusCode(), fasthttp.StatusOK))
}
