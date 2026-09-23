// SPDX-License-Identifier: EUPL-1.2

package routes

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

func TestGenerateOffer_TXCodeDisabled(t *testing.T) {
	var gotNoTXCode string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/preauth_generate" {
			w.WriteHeader(http.StatusNotFound)

			return
		}

		_ = r.ParseForm()
		gotNoTXCode = r.Form.Get("no_tx_code")

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"preauth_code": "test-preauth-code",
		})
	}))
	t.Cleanup(srv.Close)

	t.Setenv("ISSUER_TX_CODE_DISABLED", "true")

	app := offerTestApp(t, srv.URL)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().PostJSON("/generate_credential_offer", offerRequestBody(nil))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))

	qt.Check(t, qt.Equals(gotNoTXCode, "true"))

	buf, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))

	body := map[string]any{}
	qt.Assert(t, qt.IsNil(json.Unmarshal(buf, &body)))

	_, hasTXCode := body["tx_code"]
	qt.Check(t, qt.IsFalse(hasTXCode))

	grants := decodeOfferGrants(t, body["urlData"].(string))

	preauth, ok := grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"].(map[string]any)
	qt.Assert(t, qt.IsTrue(ok))

	_, hasGrantTXCode := preauth["tx_code"]
	qt.Check(t, qt.IsFalse(hasGrantTXCode))
	qt.Check(t, qt.Equals(preauth["pre-authorized_code"].(string), "test-preauth-code"))
}

func TestGenerateOffer_TXCodeEnabledByDefault(t *testing.T) {
	srv := fakeIDAuthWithPreauth(t)
	app := offerTestApp(t, srv.URL)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().PostJSON("/generate_credential_offer", offerRequestBody(nil))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))

	buf, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))

	body := map[string]any{}
	qt.Assert(t, qt.IsNil(json.Unmarshal(buf, &body)))
	qt.Check(t, qt.Equals(body["tx_code"].(float64), float64(12345)))

	grants := decodeOfferGrants(t, body["urlData"].(string))

	preauth, ok := grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"].(map[string]any)
	qt.Assert(t, qt.IsTrue(ok))

	_, hasGrantTXCode := preauth["tx_code"]
	qt.Check(t, qt.IsTrue(hasGrantTXCode))
}
