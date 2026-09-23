// SPDX-License-Identifier: EUPL-1.2

package credential

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/digimaks/api-issuer/openid4vci"
)

// MintSDJWT creates and signs an SD-JWT-VC credential.
//
// Selectively-disclosable claims are listed by name; the function creates
// a disclosure per claim (random salt + claim name + claim value),
// hashes each with SHA-256, and embeds the hashes in the JWT payload.
//
// The returned string is the standard "issuer-jwt~disc1~disc2~…~" serialization.
func MintSDJWT(vct string, claims map[string]any, result *ProofResult, ctx *IssuanceContext, expiry time.Duration) (string, error) {
	privKey, kid, err := ctx.SigningKeyFunc()
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrSigningKeyLoadFailed, err)
	}

	ecKey, ok := privKey.(*ecdsa.PrivateKey)
	if !ok {
		return "", ErrSigningKeyInvalidType
	}

	now := time.Now()

	var (
		disclosures []string
		sdHashes    []string
	)

	for name, value := range claims {
		d := createDisclosure(name, value)
		disclosures = append(disclosures, d)
		sdHashes = append(sdHashes, hashDisclosure(d))
	}

	// Build confirmation key (cnf) from holder JWK
	cnfJWK := map[string]string{
		"kty": result.HolderJWK["kty"],
		"crv": result.HolderJWK["crv"],
		"x":   result.HolderJWK["x"],
		"y":   result.HolderJWK["y"],
	}

	payload := map[string]any{
		"iss":     ctx.PublicURL,
		"sub":     result.HolderKeyID,
		"iat":     now.Unix(),
		"nbf":     now.Unix(),
		"exp":     now.Add(expiry).Unix(),
		"vct":     vct,
		"cnf":     map[string]any{"jwk": cnfJWK},
		"_sd":     sdHashes,
		"_sd_alg": "sha-256",
	}

	// Embed status list reference when available
	if ctx.StatusListURI != "" {
		payload["status"] = map[string]any{
			"status_list": map[string]any{
				"idx": ctx.StatusListIdx,
				"uri": ctx.StatusListURI,
			},
		}
	}

	header := map[string]any{
		"alg": "ES256",
		"typ": "dc+sd-jwt",
		"kid": kid,
	}

	if len(ctx.X5C) > 0 {
		header["x5c"] = ctx.X5C
	}

	issuerJWT, err := signJWT(ecKey, header, payload)
	if err != nil {
		return "", err
	}

	parts := []string{issuerJWT}
	parts = append(parts, disclosures...)

	return strings.Join(parts, "~") + "~", nil
}

// createDisclosure returns a base64url-encoded [salt, name, value] array.
func createDisclosure(name string, value any) string {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)

	arr := []any{base64.RawURLEncoding.EncodeToString(salt), name, value}
	jsonBytes, _ := json.Marshal(arr)

	return base64.RawURLEncoding.EncodeToString(jsonBytes)
}

// hashDisclosure returns the base64url-encoded SHA-256 of a disclosure string.
func hashDisclosure(disclosure string) string {
	h := sha256.Sum256([]byte(disclosure))

	return base64.RawURLEncoding.EncodeToString(h[:])
}

// signJWT produces a compact JWS (ES256) for the given header and payload maps.
func signJWT(key *ecdsa.PrivateKey, header, payload map[string]any) (string, error) {
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrJWTPartMarshalFailed, err)
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrJWTPartMarshalFailed, err)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signingInput := headerB64 + "." + payloadB64
	h := sha256.Sum256([]byte(signingInput))

	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrSignatureComputationFailed, err)
	}

	sig := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)

	return headerB64 + "." + payloadB64 + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// JWK4SDJWTMeta returns a CredentialConfiguration entry for an SD-JWT-VC type.
func JWK4SDJWTMeta(vct, displayName, description string, claims map[string]any) openid4vci.CredentialConfiguration {
	return openid4vci.CredentialConfiguration{
		Format:                               "dc+sd-jwt",
		VCT:                                  vct,
		CryptographicBindingMethodsSupported: []string{"jwk"},
		CredentialSigningAlgValuesSupported:  []string{"ES256"},
		ProofTypesSupported: map[string]openid4vci.ProofTypeSupport{
			"jwt": {
				ProofSigningAlgValuesSupported: []string{"ES256"},
				KeyAttestationsRequired: map[string][]string{
					"key_storage": {"iso_18045_high"},
				},
			},
		},
		Claims: claims,
		Display: []openid4vci.CredentialDisplay{
			{Name: displayName, Description: description, Locale: "en"},
		},
	}
}
