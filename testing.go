// SPDX-License-Identifier: EUPL-1.2

package issuer

import (
	"testing"

	"github.com/go-quicktest/qt"
)

// TestApp creates a fully wired App for use in unit tests.
func TestApp(tb testing.TB) *App {
	return TestAppWithIDAuth(tb, "http://idauth.example.com")
}

// TestAppWithIDAuth creates a test App whose IDAuth client points at
// idauthURL (e.g. a local httptest server).
func TestAppWithIDAuth(tb testing.TB, idauthURL string) *App {
	tb.Helper()

	return TestAppWithIDAuthAndStatusList(tb, idauthURL, "http://statuslist.example.com")
}

// TestAppWithIDAuthAndStatusList creates a test App whose IDAuth and status
// list clients point at idauthURL/statusListURL (e.g. local httptest
// servers). Use this over TestAppWithIDAuth when a test needs credential
// issuance to actually succeed (StatusList().Take() must reach a server that
// returns a valid {"status_list":{"uri":...,"idx":...}} response).
func TestAppWithIDAuthAndStatusList(tb testing.TB, idauthURL, statusListURL string) *App {
	tb.Helper()

	tb.Setenv("METRICS_ENABLED", "false")

	tb.Setenv("POSTGRES_HOST", "localhost")
	tb.Setenv("POSTGRES_PORT", "5432")
	tb.Setenv("POSTGRES_USER", "test")
	tb.Setenv("POSTGRES_PASSWORD", "test")
	tb.Setenv("POSTGRES_DB", "test")

	tb.Setenv("ISSUER_PUBLIC_URL", "https://issuer.example.com")

	// Postgres stubs — no real database is contacted in unit tests since
	// Store().Start() is only invoked from App.Start(), not New().
	tb.Setenv("POSTGRES_HOST", "localhost")
	tb.Setenv("POSTGRES_PORT", "5432")
	tb.Setenv("POSTGRES_USER", "test")
	tb.Setenv("POSTGRES_PASSWORD", "test")
	tb.Setenv("POSTGRES_DB", "test")

	// IDAuth stubs
	tb.Setenv("IDAUTH_URL", idauthURL)
	tb.Setenv("IDAUTH_CLIENT_ID", "issuer-go")
	tb.Setenv("IDAUTH_CLIENT_SECRET", "test-secret")

	// OpenID4VCI - PASETO nonce key (32 random bytes, base64-encoded)
	tb.Setenv("ISSUER_NONCE_SHARED_SECRET", "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=")

	// Signing certificate - self-signed P-256 for tests; base64-encoded PEM
	// Real deployments load this via ISSUER_CERTIFICATE env var (secret).
	tb.Setenv("ISSUER_CERTIFICATE", testSigningCertPEM)

	// Status list client stubs
	tb.Setenv("STATUS_LIST_API_URL", statusListURL)
	tb.Setenv("STATUS_LIST_API_KEY", "test-status-list-key")
	tb.Setenv("STATUS_LIST_COUNTRY_CODE", "LV")

	app, err := New(nil, "1.0.0-test")
	qt.Assert(tb, qt.IsNil(err))

	return app
}

// testSigningCertPEM is a minimal PEM bundle (cert + key) for testing.
// Generated with: openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650
//
//nolint:gosec
const testSigningCertPEM = `-----BEGIN CERTIFICATE-----
MIIBdzCCAR2gAwIBAgIUV/cfs+eG7hildSroBZqHobGlM3wwCgYIKoZIzj0EAwIw
ETEPMA0GA1UEAwwGdGVzdENBMB4XDTI2MDcxNTEzMDcyMFoXDTM2MDcxMjEzMDcy
MFowETEPMA0GA1UEAwwGdGVzdENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
UekcFnFOTsd7pTcR4d6YiWGZcTCvPhFtSp3a4o1bWUwBH6WSyvrteTt9vEr8n3DT
tr1O44O7TGOdizNhYTvcV6NTMFEwHQYDVR0OBBYEFBz6Rs1rTduv4T0G+erinTpV
2NvXMB8GA1UdIwQYMBaAFBz6Rs1rTduv4T0G+erinTpV2NvXMA8GA1UdEwEB/wQF
MAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgdsCYBx9d9K99MdO3etVVFvq1CDFwAF3K
wIiDQIlp5YYCIQC5EECDxAyfeMgSBhdUVrxM8D22UQ2i2zL0u6K280GvoA==
-----END CERTIFICATE-----
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg3a9Eq/p6OOfsLH+8
TXgDd3Xklj/jLY2ZAvqdcLffp6ehRANCAARR6RwWcU5Ox3ulNxHh3piJYZlxMK8+
EW1KndrijVtZTAEfpZLK+u15O328SvyfcNO2vU7jg7tMY52LM2FhO9xX
-----END PRIVATE KEY-----`
