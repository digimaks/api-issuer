// SPDX-License-Identifier: EUPL-1.2

package credential

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/go-quicktest/qt"
	"github.com/golang-jwt/jwt/v5"
)

// signES256 signs header+claims with key using ES256, returning the compact JWT.
func signES256(t *testing.T, key *ecdsa.PrivateKey, header map[string]any, claims jwt.MapClaims) string {
	t.Helper()

	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	for k, v := range header {
		tok.Header[k] = v
	}

	s, err := tok.SignedString(key)
	qt.Assert(t, qt.IsNil(err))

	return s
}

func jwkHeaderFor(key *ecdsa.PrivateKey) map[string]any {
	return map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(key.PublicKey.X.FillBytes(make([]byte, 32))),
		"y":   base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.FillBytes(make([]byte, 32))),
	}
}

// signKeyAttestationJWT builds a minimal key_attestation JWT (WUA shape) with
// one attested EC P-256 key, signed by an unrelated issuer key (issuer-go's
// VerifyProofSignature does not verify this signature — trust is delegated
// to api-wallet-digimaks upstream, per extractKeyFromAttestation's doc comment).
func signKeyAttestationJWT(t *testing.T, attestedKey *ecdsa.PrivateKey, keyStorage string, exp time.Time) string {
	t.Helper()

	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))

	claims := jwt.MapClaims{
		"key_storage": []string{keyStorage},
		"attested_keys": []map[string]any{
			{
				"kty": "EC",
				"crv": "P-256",
				"x":   base64.RawURLEncoding.EncodeToString(attestedKey.PublicKey.X.FillBytes(make([]byte, 32))),
				"y":   base64.RawURLEncoding.EncodeToString(attestedKey.PublicKey.Y.FillBytes(make([]byte, 32))),
			},
		},
	}

	if !exp.IsZero() {
		claims["exp"] = exp.Unix()
	}

	return signES256(t, issuerKey, map[string]any{"typ": "keyattestation+jwt"}, claims)
}

func TestVerifyProofSignature_BareJWK_NotAttested(t *testing.T) {
	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))

	proof := signES256(t, holderKey, map[string]any{
		"alg": "ES256",
		"jwk": jwkHeaderFor(holderKey),
	}, jwt.MapClaims{})

	result, err := VerifyProofSignature(proof)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsFalse(result.KeyAttestationVerified))
}

func TestVerifyProofSignature_KeyAttestationHeader_Attested(t *testing.T) {
	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))

	ka := signKeyAttestationJWT(t, holderKey, "iso_18045_high", time.Now().Add(time.Hour))

	proof := signES256(t, holderKey, map[string]any{
		"alg":             "ES256",
		"key_attestation": ka,
	}, jwt.MapClaims{})

	result, err := VerifyProofSignature(proof)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(result.KeyAttestationVerified))
}

func TestVerifyProofSignature_KeyAttestationProofType_Attested(t *testing.T) {
	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))

	ka := signKeyAttestationJWT(t, holderKey, "iso_18045_high", time.Now().Add(time.Hour))

	result, err := VerifyProofSignature(ka)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(result.KeyAttestationVerified))
}

func TestVerifyProofSignatureAll_BatchAttestedKeys_AllMarkedVerified(t *testing.T) {
	holderKey1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))
	holderKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))

	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))

	claims := jwt.MapClaims{
		"key_storage": []string{"iso_18045_high"},
		"attested_keys": []map[string]any{
			{
				"kty": "EC", "crv": "P-256",
				"x": base64.RawURLEncoding.EncodeToString(holderKey1.PublicKey.X.FillBytes(make([]byte, 32))),
				"y": base64.RawURLEncoding.EncodeToString(holderKey1.PublicKey.Y.FillBytes(make([]byte, 32))),
			},
			{
				"kty": "EC", "crv": "P-256",
				"x": base64.RawURLEncoding.EncodeToString(holderKey2.PublicKey.X.FillBytes(make([]byte, 32))),
				"y": base64.RawURLEncoding.EncodeToString(holderKey2.PublicKey.Y.FillBytes(make([]byte, 32))),
			},
		},
	}
	ka := signES256(t, issuerKey, map[string]any{"typ": "keyattestation+jwt"}, claims)

	proof := signES256(t, holderKey1, map[string]any{
		"alg":             "ES256",
		"key_attestation": ka,
	}, jwt.MapClaims{})

	results, err := VerifyProofSignatureAll(proof)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(results, 2))
	qt.Check(t, qt.IsTrue(results[0].KeyAttestationVerified))
	qt.Check(t, qt.IsTrue(results[1].KeyAttestationVerified))
}

func TestVerifyProofSignature_ExpiredKeyAttestation_Rejected(t *testing.T) {
	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))

	ka := signKeyAttestationJWT(t, holderKey, "iso_18045_high", time.Now().Add(-time.Hour))

	proof := signES256(t, holderKey, map[string]any{
		"alg":             "ES256",
		"key_attestation": ka,
	}, jwt.MapClaims{})

	_, err = VerifyProofSignature(proof)
	qt.Assert(t, qt.Not(qt.IsNil(err)))
}

func TestExtractKeyAttestation_HeaderField(t *testing.T) {
	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))

	ka := signKeyAttestationJWT(t, holderKey, "iso_18045_high", time.Now().Add(time.Hour))

	proof := signES256(t, holderKey, map[string]any{
		"alg":             "ES256",
		"key_attestation": ka,
	}, jwt.MapClaims{})

	got, err := ExtractKeyAttestation(proof)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(got, ka))
}

func TestExtractKeyAttestation_WholeJWTIsAttestation(t *testing.T) {
	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))

	ka := signKeyAttestationJWT(t, holderKey, "iso_18045_high", time.Now().Add(time.Hour))

	got, err := ExtractKeyAttestation(ka)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(got, ka))
}

func TestExtractKeyAttestation_AbsentReturnsEmpty(t *testing.T) {
	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))

	proof := signES256(t, holderKey, jwkHeaderFor(holderKey), jwt.MapClaims{})

	got, err := ExtractKeyAttestation(proof)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(got, ""))
}

func TestExtractKeyAttestation_MalformedJWT(t *testing.T) {
	_, err := ExtractKeyAttestation("not-a-jwt")
	qt.Assert(t, qt.Not(qt.IsNil(err)))
}
