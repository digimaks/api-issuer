// SPDX-License-Identifier: EUPL-1.2

package routes

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	issuer "github.com/digimaks/api-issuer"
	"github.com/digimaks/api-issuer/credential"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// fakeStatusList spins up an httptest.Server that answers POST /take with a
// valid {"status_list":{"uri":...,"idx":...}} response, letting credential
// issuance succeed end-to-end in tests without a real status-list service.
func fakeStatusList(t *testing.T) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/take" {
			w.WriteHeader(http.StatusNotFound)

			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status_list": map[string]any{"uri": "https://statuslist.example.com/list/1", "idx": 1},
		})
	}))
	t.Cleanup(srv.Close)

	return srv
}

// issuanceTestApp wires a router against a test App with fake IDAuth and
// status-list servers and the given store, so POST /credential can be
// exercised end-to-end including credential issuance and DB tracking.
func issuanceTestApp(t *testing.T, introspection map[string]any, store *fakeStore) *azugo.TestApp {
	t.Helper()

	idauthSrv := fakeIDAuth(t, introspection)
	statusListSrv := fakeStatusList(t)

	app := issuer.TestAppWithIDAuthAndStatusList(t, idauthSrv.URL, statusListSrv.URL)
	if store != nil {
		app.SetStore(store)
	}

	qt.Assert(t, qt.IsNil(Init(app)))

	return azugo.NewTestApp(app.App)
}

func TestCredential_IDAuthPath_RecordsIssuanceAndReturnsCredentialID(t *testing.T) {
	store := &fakeStore{resultJSON: `{"id":"tracked-cred-id"}`}

	app := issuanceTestApp(t, map[string]any{
		"active":     true,
		"sub":        "subject-1",
		"token_type": "Bearer",
		"claims": map[string]any{
			"given_name":                     "John",
			"family_name":                    "Doe",
			"personal_administrative_number": "PNOLV-32001011234",
			"birth_date":                     "1990-01-01",
			"issuing_country":                "LV",
		},
	}, store)
	app.Start(t)
	defer app.Stop()

	client := app.TestClient()
	resp, err := client.PostJSON("/credential", map[string]any{
		"credential_configuration_id": credential.PIDSDJTVCID,
		"proofs": map[string]any{
			"jwt": []string{attestedProofJWT(t)},
		},
	}, client.WithHeader("Authorization", "Bearer test-token"))
	qt.Assert(t, qt.IsNil(err))

	body, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK), qt.Commentf("body: %s", body))

	var parsed struct {
		CredentialID string `json:"credential_id"`
		Credentials  []struct {
			CredentialID string `json:"credential_id"`
		} `json:"credentials"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal(body, &parsed)))

	qt.Check(t, qt.Equals(parsed.CredentialID, "tracked-cred-id"))
	qt.Assert(t, qt.Equals(len(parsed.Credentials), 1))
	qt.Check(t, qt.Equals(parsed.Credentials[0].CredentialID, "tracked-cred-id"))
	qt.Check(t, qt.Equals(string(resp.Header.Peek("Credential-ID")), "tracked-cred-id"))

	qt.Assert(t, qt.Equals(len(store.calls), 1))
	qt.Check(t, qt.Equals(store.calls[0], "attestation_provider.record_credential_issuance"))
}

func TestCredential_IDAuthPath_DBFailureIsNonFatal(t *testing.T) {
	store := &fakeStore{execErr: fasthttp.ErrConnectionClosed}

	app := issuanceTestApp(t, map[string]any{
		"active":     true,
		"sub":        "subject-1",
		"token_type": "Bearer",
		"claims": map[string]any{
			"given_name":                     "John",
			"family_name":                    "Doe",
			"personal_administrative_number": "PNOLV-32001011234",
			"birth_date":                     "1990-01-01",
			"issuing_country":                "LV",
		},
	}, store)
	app.Start(t)
	defer app.Stop()

	client := app.TestClient()
	resp, err := client.PostJSON("/credential", map[string]any{
		"credential_configuration_id": credential.PIDSDJTVCID,
		"proofs": map[string]any{
			"jwt": []string{attestedProofJWT(t)},
		},
	}, client.WithHeader("Authorization", "Bearer test-token"))
	qt.Assert(t, qt.IsNil(err))

	body, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	// Issuance must still succeed even though tracking failed.
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK), qt.Commentf("body: %s", body))

	var parsed struct {
		CredentialID string `json:"credential_id"`
		Credentials  []struct {
			Credential   string `json:"credential"`
			CredentialID string `json:"credential_id"`
		} `json:"credentials"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal(body, &parsed)))

	qt.Check(t, qt.Equals(parsed.CredentialID, ""))
	qt.Assert(t, qt.Equals(len(parsed.Credentials), 1))
	qt.Check(t, qt.Not(qt.Equals(parsed.Credentials[0].Credential, "")))
	qt.Check(t, qt.Equals(parsed.Credentials[0].CredentialID, ""))
	qt.Check(t, qt.Equals(string(resp.Header.Peek("Credential-ID")), ""))
}
