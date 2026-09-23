// SPDX-License-Identifier: EUPL-1.2

package dpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/go-quicktest/qt"
)

func testJWK(t *testing.T) (*ecdsa.PrivateKey, map[string]any) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))

	return key, map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(key.PublicKey.X.FillBytes(make([]byte, 32))),
		"y":   base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.FillBytes(make([]byte, 32))),
	}
}

func TestParseECJWK_Valid(t *testing.T) {
	key, raw := testJWK(t)

	pub, jkt, err := parseECJWK(raw)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(pub.Equal(&key.PublicKey)))
	qt.Check(t, qt.Not(qt.Equals(jkt, "")))
}

func TestParseECJWK_RejectsPrivateKeyMaterial(t *testing.T) {
	_, raw := testJWK(t)
	raw["d"] = "AAAA"

	_, _, err := parseECJWK(raw)
	qt.Check(t, qt.ErrorIs(err, ErrInvalidJWK))
}

func TestParseECJWK_RejectsWrongKeyType(t *testing.T) {
	_, raw := testJWK(t)
	raw["kty"] = "RSA"

	_, _, err := parseECJWK(raw)
	qt.Check(t, qt.ErrorIs(err, ErrInvalidJWK))
}

func TestParseECJWK_RejectsPointOffCurve(t *testing.T) {
	_, raw := testJWK(t)
	raw["y"] = base64.RawURLEncoding.EncodeToString(make([]byte, 32))

	_, _, err := parseECJWK(raw)
	qt.Check(t, qt.ErrorIs(err, ErrInvalidJWK))
}
