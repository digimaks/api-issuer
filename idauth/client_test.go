// SPDX-License-Identifier: EUPL-1.2

package idauth

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
)

// withTestContext builds a real *azugo.Context by driving a minimal test
// app through an actual request, mirroring the pattern used by azugo's own
// http_client_test.go (a real *fasthttp.RequestCtx is required — a nil one,
// as produced by MockContext, panics on UserValue/correlation lookups).
func withTestContext(t *testing.T, fn func(ctx *azugo.Context)) {
	t.Helper()

	app := azugo.NewTestApp()
	app.Get("/", func(ctx *azugo.Context) {
		fn(ctx)
	})
	app.Start(t)
	defer app.Stop()

	_, err := app.TestClient().Get("/")
	qt.Assert(t, qt.IsNil(err))
}

func TestIntrospect_SendsBasicAuth(t *testing.T) {
	var gotAuth string

	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"active":false}`))
	}))
	defer fake.Close()

	client, err := NewClient(&Configuration{
		URL:          fake.URL,
		ClientID:     "digimaks.api-wallet",
		ClientSecret: "test-secret",
	})
	qt.Assert(t, qt.IsNil(err))

	var introspectErr error

	withTestContext(t, func(ctx *azugo.Context) {
		_, introspectErr = client.Introspect(ctx, "some-token")
	})

	qt.Assert(t, qt.IsNil(introspectErr))

	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("digimaks.api-wallet:test-secret"))
	qt.Check(t, qt.Equals(gotAuth, wantAuth))
}

func TestGeneratePreauth_UsesBearerAuth(t *testing.T) {
	var gotAuth string

	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"session_id":"s","preauth_code":"c","tx_code":1}`))
	}))
	defer fake.Close()

	client, err := NewClient(&Configuration{
		URL:          fake.URL,
		ClientID:     "digimaks.api-wallet",
		ClientSecret: "test-secret",
	})
	qt.Assert(t, qt.IsNil(err))

	var preauthErr error

	withTestContext(t, func(ctx *azugo.Context) {
		_, preauthErr = client.GeneratePreauth(ctx, PreauthRequest{Scope: "pid", SessionID: "s"})
	})

	qt.Assert(t, qt.IsNil(preauthErr))
	qt.Check(t, qt.Equals(gotAuth, "Bearer test-secret"))
}
