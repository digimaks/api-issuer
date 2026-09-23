// SPDX-License-Identifier: EUPL-1.2

package dpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

var ErrInvalidJWK = errors.New("dpop: invalid jwk")

func parseECJWK(raw map[string]any) (*ecdsa.PublicKey, string, error) {
	kty, _ := raw["kty"].(string)
	crv, _ := raw["crv"].(string)
	x, _ := raw["x"].(string)
	y, _ := raw["y"].(string)

	if kty != "EC" || crv != "P-256" || x == "" || y == "" {
		return nil, "", fmt.Errorf("%w: expected EC P-256 public key", ErrInvalidJWK)
	}

	if _, ok := raw["d"]; ok {
		return nil, "", fmt.Errorf("%w: private key material not allowed", ErrInvalidJWK)
	}

	xb, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %w", ErrInvalidJWK, err)
	}

	yb, err := base64.RawURLEncoding.DecodeString(y)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %w", ErrInvalidJWK, err)
	}

	// Uncompressed form: 04 || X || Y.
	uncompressed := make([]byte, 1+len(xb)+len(yb))
	uncompressed[0] = 0x04
	copy(uncompressed[1:], xb)
	copy(uncompressed[1+len(xb):], yb)

	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), uncompressed)
	if err != nil {
		return nil, "", fmt.Errorf("%w: point not on curve", ErrInvalidJWK)
	}

	// RFC 7638 thumbprint: SHA-256 over the required members in lexicographic
	// order; json.Marshal of a map emits keys sorted, which matches exactly.
	tp, err := json.Marshal(map[string]string{"crv": crv, "kty": kty, "x": x, "y": y})
	if err != nil {
		return nil, "", err
	}

	sum := sha256.Sum256(tp)

	return pub, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}
