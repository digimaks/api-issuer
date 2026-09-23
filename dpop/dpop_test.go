// SPDX-License-Identifier: EUPL-1.2

package dpop

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/go-quicktest/qt"
	"github.com/golang-jwt/jwt/v5"
)

const testHTU = "https://issuer.example.com/credential"

func signProof(t *testing.T, key *ecdsa.PrivateKey, raw map[string]any, mutate func(header map[string]any, claims jwt.MapClaims)) string {
	t.Helper()

	claims := jwt.MapClaims{
		"htm": "POST",
		"htu": testHTU,
		"iat": time.Now().Unix(),
		"jti": "jti-" + t.Name(),
	}
	header := map[string]any{"typ": "dpop+jwt", "jwk": raw}

	if mutate != nil {
		mutate(header, claims)
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	for k, v := range header {
		tok.Header[k] = v
	}

	s, err := tok.SignedString(key)
	qt.Assert(t, qt.IsNil(err))

	return s
}

func mapReplayChecker() ReplayChecker {
	seen := map[string]bool{}

	return func(_ context.Context, jti string) (bool, error) {
		if seen[jti] {
			return true, nil
		}

		seen[jti] = true

		return false, nil
	}
}

func testValidator() *Validator {
	return NewValidator(Config{
		AcceptedHTUs: []string{testHTU},
		IATWindow:    time.Minute,
		ReplayCheck:  mapReplayChecker(),
	})
}

func TestValidate_ValidProofWithATH(t *testing.T) {
	key, raw := testJWK(t)
	v := testValidator()

	sum := sha256.Sum256([]byte("the-access-token"))
	ath := base64.RawURLEncoding.EncodeToString(sum[:])

	proof := signProof(t, key, raw, func(_ map[string]any, c jwt.MapClaims) { c["ath"] = ath })

	jkt, err := v.Validate(context.Background(), proof, "POST", "the-access-token", "/credential", "/credential")
	qt.Assert(t, qt.IsNil(err))

	_, wantJKT, err := parseECJWK(raw)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(jkt, wantJKT))
}

func TestValidate_RejectsMissingATH(t *testing.T) {
	key, raw := testJWK(t)
	v := testValidator()

	_, err := v.Validate(context.Background(), signProof(t, key, raw, nil), "POST", "the-access-token", "/credential", "/credential")
	qt.Check(t, qt.ErrorIs(err, ErrInvalidProof))
}

func TestValidate_RejectsWrongATH(t *testing.T) {
	key, raw := testJWK(t)
	v := testValidator()

	proof := signProof(t, key, raw, func(_ map[string]any, c jwt.MapClaims) { c["ath"] = "bogus" })

	_, err := v.Validate(context.Background(), proof, "POST", "the-access-token", "/credential", "/credential")
	qt.Check(t, qt.ErrorIs(err, ErrInvalidProof))
}

func TestValidate_RejectsWrongTyp(t *testing.T) {
	key, raw := testJWK(t)
	v := testValidator()

	proof := signProof(t, key, raw, func(h map[string]any, _ jwt.MapClaims) { h["typ"] = "JWT" })

	_, err := v.Validate(context.Background(), proof, "POST", "", "/credential", "/credential")
	qt.Check(t, qt.ErrorIs(err, ErrInvalidProof))
}

func TestValidate_RejectsStaleIAT(t *testing.T) {
	key, raw := testJWK(t)
	v := testValidator()

	proof := signProof(t, key, raw, func(_ map[string]any, c jwt.MapClaims) {
		c["iat"] = time.Now().Add(-5 * time.Minute).Unix()
	})

	_, err := v.Validate(context.Background(), proof, "POST", "", "/credential", "/credential")
	qt.Check(t, qt.ErrorIs(err, ErrInvalidProof))
}

func TestValidate_RejectsUnknownHTU(t *testing.T) {
	key, raw := testJWK(t)
	v := testValidator()

	proof := signProof(t, key, raw, func(_ map[string]any, c jwt.MapClaims) {
		c["htu"] = "https://evil.example.com/credential"
	})

	_, err := v.Validate(context.Background(), proof, "POST", "", "/credential", "/credential")
	qt.Check(t, qt.ErrorIs(err, ErrInvalidProof))
}

func TestValidate_RejectsReplayedJTI(t *testing.T) {
	key, raw := testJWK(t)
	v := testValidator()
	proof := signProof(t, key, raw, nil)

	_, err := v.Validate(context.Background(), proof, "POST", "", "/credential", "/credential")
	qt.Assert(t, qt.IsNil(err))

	_, err = v.Validate(context.Background(), proof, "POST", "", "/credential", "/credential")
	qt.Check(t, qt.ErrorIs(err, ErrReplay))
}

func TestValidate_RejectsHTUFromDifferentEndpoint(t *testing.T) {
	key, raw := testJWK(t)
	v := NewValidator(Config{
		AcceptedHTUs: []string{testHTU, "https://issuer.example.com/revoke"},
		IATWindow:    time.Minute,
		ReplayCheck:  mapReplayChecker(),
	})

	proof := signProof(t, key, raw, nil) // htu = testHTU = ".../credential"

	_, err := v.Validate(context.Background(), proof, "POST", "", "/revoke", "/revoke")
	qt.Check(t, qt.ErrorIs(err, ErrInvalidProof))
}

func TestValidate_DynamicHTURoute_Accepted(t *testing.T) {
	key, raw := testJWK(t)
	v := NewValidator(Config{
		DynamicHTURoutes: []string{"/credential/{id}/acknowledge"},
		PublicURL:        "https://issuer.example.com",
		IATWindow:        time.Minute,
		ReplayCheck:      mapReplayChecker(),
	})

	proof := signProof(t, key, raw, func(_ map[string]any, c jwt.MapClaims) {
		c["htu"] = "https://issuer.example.com/credential/abc123/acknowledge"
	})

	_, err := v.Validate(context.Background(), proof, "POST", "", "/credential/{id}/acknowledge", "/credential/abc123/acknowledge")
	qt.Assert(t, qt.IsNil(err))
}

func TestValidate_DynamicHTURoute_RejectsMismatchedID(t *testing.T) {
	key, raw := testJWK(t)
	v := NewValidator(Config{
		DynamicHTURoutes: []string{"/credential/{id}/acknowledge"},
		PublicURL:        "https://issuer.example.com",
		IATWindow:        time.Minute,
		ReplayCheck:      mapReplayChecker(),
	})

	// Proof bound to a different credential ID than the one being requested.
	proof := signProof(t, key, raw, func(_ map[string]any, c jwt.MapClaims) {
		c["htu"] = "https://issuer.example.com/credential/other-id/acknowledge"
	})

	_, err := v.Validate(context.Background(), proof, "POST", "", "/credential/{id}/acknowledge", "/credential/abc123/acknowledge")
	qt.Check(t, qt.ErrorIs(err, ErrInvalidProof))
}

func TestValidate_RejectsNoneAlg(t *testing.T) {
	_, raw := testJWK(t)
	v := testValidator()

	header := map[string]any{"typ": "dpop+jwt", "alg": "none", "jwk": raw}
	claims := map[string]any{
		"htm": "POST",
		"htu": testHTU,
		"iat": time.Now().Unix(),
		"jti": "jti-" + t.Name(),
	}

	headerJSON, err := json.Marshal(header)
	qt.Assert(t, qt.IsNil(err))
	claimsJSON, err := json.Marshal(claims)
	qt.Assert(t, qt.IsNil(err))

	proof := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON) + "."

	_, err = v.Validate(context.Background(), proof, "POST", "", "/credential", "/credential")
	qt.Check(t, qt.ErrorIs(err, ErrInvalidProof))
}

func TestValidate_RejectsRS256Alg(t *testing.T) {
	_, raw := testJWK(t)
	v := testValidator()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	qt.Assert(t, qt.IsNil(err))

	claims := jwt.MapClaims{
		"htm": "POST",
		"htu": testHTU,
		"iat": time.Now().Unix(),
		"jti": "jti-" + t.Name(),
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["typ"] = "dpop+jwt"
	tok.Header["jwk"] = raw

	proof, err := tok.SignedString(rsaKey)
	qt.Assert(t, qt.IsNil(err))

	_, err = v.Validate(context.Background(), proof, "POST", "", "/credential", "/credential")
	qt.Check(t, qt.ErrorIs(err, ErrInvalidProof))
}
