// SPDX-License-Identifier: EUPL-1.2

package routes

import (
	"testing"

	issuer "github.com/digimaks/api-issuer"
	"github.com/digimaks/api-issuer/idauth"
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

func testCredentialApp(t testing.TB) (*azugo.TestApp, *router) {
	t.Helper()

	app := issuer.TestApp(t)
	r := &router{App: app}

	app.Post("/__test_credential_no_introspection", func(ctx *azugo.Context) {
		ctx.SetUserValue("bearer_token", "test-token")
		r.credential(ctx)
	})

	app.Post("/__test_credential", func(ctx *azugo.Context) {
		ctx.SetUserValue("bearer_token", "test-token")
		ctx.SetUserValue("introspection", &idauth.IntrospectionResponse{Sub: "test-holder"})
		r.credential(ctx)
	})

	return azugo.NewTestApp(app.App), r
}

func TestCredential_ProblemJSON_InvalidRequestBody(t *testing.T) {
	app, _ := testCredentialApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Post("/__test_credential", []byte("{not-json"),
		app.TestClient().WithHeader("Content-Type", "application/json"))
	qt.Assert(t, qt.IsNil(err))

	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))
	qt.Check(t, qt.Equals(string(resp.Header.ContentType()), pkerrors.ContentTypeProblemJSON))

	body, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.StringContains(string(body), `"code":"err:credential:invalidRequestBody"`))
}

func TestCredential_ProblemJSON_ProofTypeUnsupported(t *testing.T) {
	app, _ := testCredentialApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().PostJSON("/__test_credential", map[string]any{
		"credential_configuration_id": "unknown-config-id",
	})
	qt.Assert(t, qt.IsNil(err))

	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))

	body, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.StringContains(string(body), `"code":"err:credential:proofTypeUnsupported"`))
}

func TestCredential_ProblemJSON_TokenExpiredOrNotFound(t *testing.T) {
	app, _ := testCredentialApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().PostJSON("/__test_credential_no_introspection", map[string]any{
		"credential_configuration_id": "unknown-config-id",
		"proof":                       map[string]any{"proof_type": "jwt", "jwt": "placeholder"},
	})
	qt.Assert(t, qt.IsNil(err))

	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnauthorized))

	body, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.StringContains(string(body), `"code":"err:credential:tokenExpiredOrNotFound"`))
}

func TestCredential_ProblemJSON_ConfigurationUnsupported(t *testing.T) {
	app, _ := testCredentialApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().PostJSON("/__test_credential", map[string]any{
		"credential_configuration_id": "unknown-config-id",
		"proof":                       map[string]any{"proof_type": "jwt", "jwt": "placeholder"},
	})
	qt.Assert(t, qt.IsNil(err))

	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))

	body, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.StringContains(string(body), `"code":"err:credential:configurationUnsupported"`))
}
