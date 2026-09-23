// SPDX-License-Identifier: EUPL-1.2

package openid4vci

import (
	"bytes"
	"compress/zlib"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/golang-jwt/jwt/v5"
)

// newWUATestApp creates a bare azugo TestApp suitable for ValidateWUA's
// MockContext-based tests (no real HTTP server, no full issuer.App wiring).
func newWUATestApp(t *testing.T) *azugo.TestApp {
	t.Helper()

	return azugo.NewTestApp(azugo.New())
}

// newWUATestService builds a minimal Service whose TrustedWalletProviderRoots
// trusts roots (DER-encoded certificates, typically the test leaf/CA itself).
func newWUATestService(_ *testing.T, app *azugo.TestApp, roots ...[]byte) *Service {
	var pemBuf bytes.Buffer

	for _, der := range roots {
		_ = pem.Encode(&pemBuf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}

	return &Service{
		app:    app.App,
		config: &Configuration{TrustedWalletProviderRoots: pemBuf.String()},
	}
}

// selfSignedCert generates a self-signed ECDSA certificate, returning the
// private key and DER-encoded certificate. Used as its own trust anchor in
// tests — a self-signed cert added to the Roots pool verifies itself.
func selfSignedCert(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-wallet-provider"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	qt.Assert(t, qt.IsNil(err))

	return key, der
}

// signKA signs claims as a Key Attestation JWT (typ "keyattestation+jwt"),
// embedding der as the sole x5c leaf (standard base64, per RFC 7515 §4.1.6).
func signKA(t *testing.T, key *ecdsa.PrivateKey, der []byte, claims jwt.MapClaims) string {
	t.Helper()

	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["typ"] = "keyattestation+jwt"
	tok.Header["x5c"] = []string{base64.StdEncoding.EncodeToString(der)}

	s, err := tok.SignedString(key)
	qt.Assert(t, qt.IsNil(err))

	return s
}

func TestValidateWUA_UntrustedProvider_RejectedWithoutHTTPCall(t *testing.T) {
	app := newWUATestApp(t)

	_, trustedDER := selfSignedCert(t)
	svc := newWUATestService(t, app, trustedDER)

	key, evilDER := selfSignedCert(t)

	jwtStr := signKA(t, key, evilDER, jwt.MapClaims{
		"exp":         time.Now().Add(time.Hour).Unix(),
		"key_storage": []string{"iso_18045_high"},
	})

	var validateErr error

	app.MockContext(func(ctx *azugo.Context) {
		validateErr = svc.ValidateWUA(ctx, jwtStr)
	})

	qt.Assert(t, qt.ErrorIs(validateErr, ErrWalletProviderNotTrusted))
}

func TestValidateWUA_Success(t *testing.T) {
	key, der := selfSignedCert(t)

	app := newWUATestApp(t)
	svc := newWUATestService(t, app, der)

	jwtStr := signKA(t, key, der, jwt.MapClaims{
		"exp":         time.Now().Add(time.Hour).Unix(),
		"key_storage": []string{"iso_18045_high"},
	})

	var validateErr error

	app.MockContext(func(ctx *azugo.Context) {
		validateErr = svc.ValidateWUA(ctx, jwtStr)
	})

	qt.Assert(t, qt.IsNil(validateErr))
}

func TestValidateWUA_WrongKeyStorage_Rejected(t *testing.T) {
	key, der := selfSignedCert(t)

	app := newWUATestApp(t)
	svc := newWUATestService(t, app, der)

	jwtStr := signKA(t, key, der, jwt.MapClaims{
		"exp":         time.Now().Add(time.Hour).Unix(),
		"key_storage": []string{"normal"},
	})

	var validateErr error

	app.MockContext(func(ctx *azugo.Context) {
		validateErr = svc.ValidateWUA(ctx, jwtStr)
	})

	qt.Assert(t, qt.IsNotNil(validateErr))
}

func TestValidateWUA_ExpiredAssertion_Rejected(t *testing.T) {
	key, der := selfSignedCert(t)

	app := newWUATestApp(t)
	svc := newWUATestService(t, app, der)

	jwtStr := signKA(t, key, der, jwt.MapClaims{
		"exp":         time.Now().Add(-time.Hour).Unix(),
		"key_storage": []string{"iso_18045_high"},
	})

	var validateErr error

	app.MockContext(func(ctx *azugo.Context) {
		validateErr = svc.ValidateWUA(ctx, jwtStr)
	})

	qt.Assert(t, qt.ErrorIs(validateErr, jwt.ErrTokenExpired))
}

func TestValidateWUA_TamperedSignature_Rejected(t *testing.T) {
	// der certifies a different key's public key than the one the token is
	// signed with — verification against the x5c leaf must fail.
	_, der := selfSignedCert(t)

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))

	app := newWUATestApp(t)
	svc := newWUATestService(t, app, der)

	jwtStr := signKA(t, otherKey, der, jwt.MapClaims{
		"exp":         time.Now().Add(time.Hour).Unix(),
		"key_storage": []string{"iso_18045_high"},
	})

	var validateErr error

	app.MockContext(func(ctx *azugo.Context) {
		validateErr = svc.ValidateWUA(ctx, jwtStr)
	})

	qt.Assert(t, qt.ErrorIs(validateErr, jwt.ErrTokenSignatureInvalid))
}

func TestValidateWUA_MissingX5C_Rejected(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))

	app := newWUATestApp(t)
	svc := newWUATestService(t, app)

	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"exp":         time.Now().Add(time.Hour).Unix(),
		"key_storage": []string{"iso_18045_high"},
	})
	tok.Header["typ"] = "keyattestation+jwt"

	jwtStr, err := tok.SignedString(key)
	qt.Assert(t, qt.IsNil(err))

	var validateErr error

	app.MockContext(func(ctx *azugo.Context) {
		validateErr = svc.ValidateWUA(ctx, jwtStr)
	})

	qt.Assert(t, qt.IsNotNil(validateErr))
}

func TestValidateWUA_WrongTyp_Rejected(t *testing.T) {
	key, der := selfSignedCert(t)

	app := newWUATestApp(t)
	svc := newWUATestService(t, app, der)

	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"exp":         time.Now().Add(time.Hour).Unix(),
		"key_storage": []string{"iso_18045_high"},
	})
	tok.Header["typ"] = "oauth-client-attestation+jwt"
	tok.Header["x5c"] = []string{base64.StdEncoding.EncodeToString(der)}

	jwtStr, err := tok.SignedString(key)
	qt.Assert(t, qt.IsNil(err))

	var validateErr error

	app.MockContext(func(ctx *azugo.Context) {
		validateErr = svc.ValidateWUA(ctx, jwtStr)
	})

	qt.Assert(t, qt.IsNotNil(validateErr))
}

// TestValidateWUA_LegacyHyphenatedTyp_Accepted covers api-wallet-digimaks's
// IssueWalletUnitAttestation, which still emits the pre-TS3-v1.5
// "key-attestation+jwt" typ (see keyAttestationTyps' TODO).
func TestValidateWUA_LegacyHyphenatedTyp_Accepted(t *testing.T) {
	key, der := selfSignedCert(t)

	app := newWUATestApp(t)
	svc := newWUATestService(t, app, der)

	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"exp":         time.Now().Add(time.Hour).Unix(),
		"key_storage": []string{"iso_18045_high"},
	})
	tok.Header["typ"] = "key-attestation+jwt"
	tok.Header["x5c"] = []string{base64.StdEncoding.EncodeToString(der)}

	jwtStr, err := tok.SignedString(key)
	qt.Assert(t, qt.IsNil(err))

	var validateErr error

	app.MockContext(func(ctx *azugo.Context) {
		validateErr = svc.ValidateWUA(ctx, jwtStr)
	})

	qt.Assert(t, qt.IsNil(validateErr))
}

// signingCert generates a self-signed ECDSA certificate for signing a status
// list JWT, returning the private key and the DER-encoded certificate.
func signingCert(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()

	return selfSignedCert(t)
}

// statusListJWT builds a minimal IETF Token Status List JWT with a single bit
// per entry, setting the bit at revokedIdx (if >= 0).
func statusListJWT(t *testing.T, key *ecdsa.PrivateKey, der []byte, sub string, revokedIdx int) string {
	t.Helper()

	bitset := make([]byte, 2)

	if revokedIdx >= 0 {
		bitset[revokedIdx/8] |= 1 << (revokedIdx % 8)
	}

	var buf bytes.Buffer

	zw := zlib.NewWriter(&buf)
	_, err := zw.Write(bitset)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(zw.Close()))

	claims := jwt.MapClaims{
		"sub": sub,
		"iat": time.Now().Unix(),
		"status_list": map[string]any{
			"bits": 1,
			"lst":  base64.RawURLEncoding.EncodeToString(buf.Bytes()),
		},
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["typ"] = "statuslist+jwt"
	tok.Header["x5c"] = []string{base64.StdEncoding.EncodeToString(der)}

	s, err := tok.SignedString(key)
	qt.Assert(t, qt.IsNil(err))

	return s
}

func TestValidateWUA_RevokedStatusList_Rejected(t *testing.T) {
	key, der := selfSignedCert(t)

	statusKey, statusCert := signingCert(t)

	mux := http.NewServeMux()

	var statusListURL string

	mux.HandleFunc("/status-list", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, statusListJWT(t, statusKey, statusCert, statusListURL, 5))
	})

	statusSrv := httptest.NewServer(mux)
	t.Cleanup(statusSrv.Close)
	statusListURL = statusSrv.URL + "/status-list"

	app := newWUATestApp(t)
	svc := newWUATestService(t, app, der)

	jwtStr := signKA(t, key, der, jwt.MapClaims{
		"exp":         time.Now().Add(time.Hour).Unix(),
		"key_storage": []string{"iso_18045_high"},
		"key_storage_status": map[string]any{
			"status": map[string]any{
				"status_list": map[string]any{
					"idx": 5,
					"uri": statusListURL,
				},
			},
		},
	})

	// validateStatusList needs a real fasthttp request context (for
	// correlation ID propagation on the outbound status list fetch) —
	// MockContext leaves that unset and panics, so drive this through a
	// real request instead.
	var validateErr error

	app.Get("/", func(ctx *azugo.Context) {
		validateErr = svc.ValidateWUA(ctx, jwtStr)
	})

	app.Start(t)
	defer app.Stop()

	_, err := app.TestClient().Get("/")
	qt.Assert(t, qt.IsNil(err))

	qt.Assert(t, qt.IsNotNil(validateErr))
}

func TestValidateWUA_ValidStatusList_NotRevoked(t *testing.T) {
	key, der := selfSignedCert(t)

	statusKey, statusCert := signingCert(t)

	mux := http.NewServeMux()

	var statusListURL string

	mux.HandleFunc("/status-list", func(w http.ResponseWriter, _ *http.Request) {
		// No index revoked (-1).
		fmt.Fprint(w, statusListJWT(t, statusKey, statusCert, statusListURL, -1))
	})

	statusSrv := httptest.NewServer(mux)
	t.Cleanup(statusSrv.Close)
	statusListURL = statusSrv.URL + "/status-list"

	app := newWUATestApp(t)
	svc := newWUATestService(t, app, der)

	jwtStr := signKA(t, key, der, jwt.MapClaims{
		"exp":         time.Now().Add(time.Hour).Unix(),
		"key_storage": []string{"iso_18045_high"},
		"key_storage_status": map[string]any{
			"status": map[string]any{
				"status_list": map[string]any{
					"idx": 5,
					"uri": statusListURL,
				},
			},
		},
	})

	// Same reason as TestValidateWUA_RevokedStatusList_Rejected: needs a
	// real request context for outbound correlation ID propagation.
	var validateErr error

	app.Get("/", func(ctx *azugo.Context) {
		validateErr = svc.ValidateWUA(ctx, jwtStr)
	})

	app.Start(t)
	defer app.Stop()

	_, err := app.TestClient().Get("/")
	qt.Assert(t, qt.IsNil(err))

	qt.Assert(t, qt.IsNil(validateErr))
}

func TestHasKeyStorageLevel(t *testing.T) {
	qt.Check(t, qt.IsTrue(hasKeyStorageLevel([]any{"iso_18045_high"}, "iso_18045_high")))
	qt.Check(t, qt.IsTrue(hasKeyStorageLevel([]any{"normal", "iso_18045_high"}, "iso_18045_high")))
	qt.Check(t, qt.IsFalse(hasKeyStorageLevel([]any{"normal"}, "iso_18045_high")))
	qt.Check(t, qt.IsFalse(hasKeyStorageLevel("iso_18045_high", "iso_18045_high")))
	qt.Check(t, qt.IsFalse(hasKeyStorageLevel(nil, "iso_18045_high")))
}

func TestIsIndexListed(t *testing.T) {
	// Single bit per entry: bit 5 set.
	bitset := []byte{0b0010_0000}

	listed, err := isIndexListed(bitset, 5, 1)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(listed))

	listed, err = isIndexListed(bitset, 0, 1)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsFalse(listed))

	// Beyond available data -> treated as not listed.
	listed, err = isIndexListed(bitset, 1000, 1)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsFalse(listed))

	_, err = isIndexListed(bitset, -1, 1)
	qt.Check(t, qt.IsNotNil(err))

	_, err = isIndexListed(bitset, 0, 0)
	qt.Check(t, qt.IsNotNil(err))
}
