// SPDX-License-Identifier: EUPL-1.2

package openid4vci

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

// SignedMetadataContentType is the media type used to request and serve
// Credential Issuer metadata as a signed JWT (OID4VCI §12.2.3).
const SignedMetadataContentType = "openidvci-issuer-metadata+jwt"

// SignedMetadataTTL is the validity period of the signed metadata JWT's exp claim.
const SignedMetadataTTL = 24 * time.Hour

// SignedIssuerMeta returns the Credential Issuer metadata as a compact JWT,
// signed with the issuer's credential signing key (OID4VCI §12.2.3).
func (s *Service) SignedIssuerMeta(meta *IssuerMetadata) (string, error) {
	cert, err := s.config.SigningCertificate()
	if err != nil {
		return "", err
	}

	ecKey, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return "", errors.New("signing key is not ECDSA")
	}

	kid, err := s.SigningCertificateKID()
	if err != nil {
		return "", err
	}

	x5c, err := s.SigningCertificateX5C()
	if err != nil {
		return "", err
	}

	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return "", err
	}

	payload := map[string]any{}
	if err := json.Unmarshal(metaJSON, &payload); err != nil {
		return "", err
	}

	now := time.Now()
	payload["iss"] = meta.CredentialIssuer
	payload["sub"] = meta.CredentialIssuer
	payload["iat"] = now.Unix()
	payload["exp"] = now.Add(SignedMetadataTTL).Unix()

	header := map[string]any{
		"alg": "ES256",
		"typ": SignedMetadataContentType,
		"kid": kid,
		"x5c": x5c,
	}

	return signJWT(ecKey, header, payload)
}

// signJWT signs an ES256 JWT from the given header and payload maps.
func signJWT(key *ecdsa.PrivateKey, header, payload map[string]any) (string, error) {
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signingInput := headerB64 + "." + payloadB64
	h := sha256.Sum256([]byte(signingInput))

	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		return "", err
	}

	sig := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
