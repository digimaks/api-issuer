// SPDX-License-Identifier: EUPL-1.2

package credential

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"
)

// VerifyProof validates an OpenID4VCI proof JWT and returns the holder context.
//
// The proof JWT header must contain:
//   - alg: "ES256"
//   - typ: "openid4vci-proof+jwt"
//   - jwk: EC P-256 public key {"kty","crv","x","y"}
//
// The payload must contain:
//   - aud: issuer URL (or DID)
//   - nonce: the c_nonce issued by the server
//   - iat: issued-at must not be older than maxAge
func VerifyProof(proofJWT, expectedNonce, issuerURL string, maxAge time.Duration) (*ProofResult, error) {
	parts := strings.Split(proofJWT, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT format")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("invalid header encoding")
	}

	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		JWK struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"jwk"`
	}

	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("invalid header JSON: %w", err)
	}

	if header.Alg != "ES256" {
		return nil, fmt.Errorf("unsupported algorithm: %s (must be ES256)", header.Alg)
	}

	if header.Typ != "openid4vci-proof+jwt" {
		return nil, fmt.Errorf("invalid typ: %s", header.Typ)
	}

	if header.JWK.Kty != "EC" || header.JWK.Crv != "P-256" || header.JWK.X == "" || header.JWK.Y == "" {
		return nil, errors.New("invalid or missing JWK in header")
	}

	// Decode holder public key
	xBytes, err := base64.RawURLEncoding.DecodeString(header.JWK.X)
	if err != nil {
		return nil, errors.New("invalid JWK x coordinate")
	}

	yBytes, err := base64.RawURLEncoding.DecodeString(header.JWK.Y)
	if err != nil {
		return nil, errors.New("invalid JWK y coordinate")
	}

	point := make([]byte, 65)
	point[0] = 0x04
	copy(point[1:33], xBytes)
	copy(point[33:65], yBytes)

	holderKey, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		return nil, errors.New("JWK point is not on P-256 curve")
	}

	// Verify signature
	signingInput := parts[0] + "." + parts[1]
	h := sha256.Sum256([]byte(signingInput))

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sigBytes) != 64 {
		return nil, errors.New("invalid signature encoding")
	}

	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])

	if !ecdsa.Verify(holderKey, h[:], r, s) {
		return nil, errors.New("proof JWT signature verification failed")
	}

	// Validate payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("invalid payload encoding")
	}

	var payload struct {
		Aud   any     `json:"aud"`
		Nonce string  `json:"nonce"`
		IAT   float64 `json:"iat"`
	}

	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("invalid payload JSON: %w", err)
	}

	// Validate aud (may be a string or []string)
	validAud := false

	switch v := payload.Aud.(type) {
	case string:
		validAud = v == issuerURL
	case []any:
		for _, a := range v {
			if s, ok := a.(string); ok && s == issuerURL {
				validAud = true
				break
			}
		}
	}

	if !validAud {
		return nil, fmt.Errorf("proof JWT audience mismatch: expected %s", issuerURL)
	}

	if payload.Nonce != expectedNonce {
		return nil, errors.New("proof JWT nonce mismatch")
	}

	iat := time.Unix(int64(payload.IAT), 0)
	if time.Since(iat) > maxAge {
		return nil, errors.New("proof JWT is too old (iat)")
	}

	// Derive holder key ID: SHA-256 of uncompressed point (0x04 || X || Y)
	uncompressed := make([]byte, 65)
	uncompressed[0] = 0x04
	copy(uncompressed[1:33], xBytes)
	copy(uncompressed[33:65], yBytes)
	keyHash := sha256.Sum256(uncompressed)
	holderKeyID := fmt.Sprintf("%x", keyHash[:])

	holderJWK := map[string]string{
		"kty": "EC",
		"crv": "P-256",
		"x":   header.JWK.X,
		"y":   header.JWK.Y,
	}

	return &ProofResult{
		HolderKeyID: holderKeyID,
		HolderJWK:   holderJWK,
	}, nil
}

// ExtractJWTExp decodes the payload of any JWT and returns its exp claim as a
// time.Time. Returns zero time if exp is absent or the JWT is malformed.
func ExtractJWTExp(jwtStr string) time.Time {
	parts := strings.Split(jwtStr, ".")
	if len(parts) != 3 {
		return time.Time{}
	}

	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}
	}

	var claims struct {
		Exp float64 `json:"exp"`
	}
	if err := json.Unmarshal(b, &claims); err != nil || claims.Exp == 0 {
		return time.Time{}
	}

	return time.Unix(int64(claims.Exp), 0)
}

// ExtractJWTIssuer decodes the payload of any JWT and returns its iss claim,
// without verifying the signature. Used to read the wallet provider identity
// from a WUA assertion JWT (trust already established when the WUA session
// was created). Returns "" if iss is absent or the JWT is malformed.
func ExtractJWTIssuer(jwtStr string) string {
	parts := strings.Split(jwtStr, ".")
	if len(parts) != 3 {
		return ""
	}

	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}

	var claims struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(b, &claims); err != nil {
		return ""
	}

	return claims.Iss
}

// keyAttestationTyps are the JOSE "typ" values recognized as a Key
// Attestation (KA) JWT. "keyattestation+jwt" (no hyphen) is the current TS3
// (Wallet Unit Attestation spec, v1.5+) value. "key-attestation+jwt"
// (hyphenated) is a pre-v1.5 draft value still emitted by
// api-wallet-digimaks's IssueWalletUnitAttestation (openid4vci/attestation_endpoints.go).
//
// TODO(TS3 alignment): drop "key-attestation+jwt" once api-wallet-digimaks
// emits the spec-correct "keyattestation+jwt" — see
// api-wallet-digimaks/openid4vci/attestation_endpoints.go.
var keyAttestationTyps = []string{"keyattestation+jwt", "key-attestation+jwt"}

// ExtractKeyAttestation returns the Key Attestation (KA) JWT embedded in a
// proof JWT, without verifying any signature. Two forms are recognized:
//   - header.key_attestation holds a separate KA JWT (holder-signed proof,
//     KA-bound key).
//   - the proof JWT's own typ is one of keyAttestationTyps: the whole JWT IS
//     the key attestation, signed by the wallet provider rather than the
//     holder (OID4VCI attestation proof type).
//
// Returns "" with a nil error when the proof carries no key attestation at
// all — a valid, non-attested proof is not an error at this layer.
func ExtractKeyAttestation(proofJWT string) (string, error) {
	parts := strings.Split(proofJWT, ".")
	if len(parts) != 3 {
		return "", errors.New("invalid JWT format")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", errors.New("invalid header encoding")
	}

	var header struct {
		Typ            string `json:"typ"`
		KeyAttestation string `json:"key_attestation"`
	}

	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return "", fmt.Errorf("invalid header JSON: %w", err)
	}

	if slices.Contains(keyAttestationTyps, header.Typ) {
		return proofJWT, nil
	}

	return header.KeyAttestation, nil
}

// ExtractProofNonce parses a proof JWT (without signature verification) and returns
// the "nonce" claim from the payload. Used when the nonce is validated separately
// via PASETO before VerifyProof is called.
func ExtractProofNonce(proofJWT string) (string, error) {
	parts := strings.Split(proofJWT, ".")
	if len(parts) != 3 {
		return "", errors.New("invalid JWT format")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("invalid payload encoding")
	}

	var payload struct {
		Nonce string `json:"nonce"`
	}

	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return "", fmt.Errorf("invalid payload JSON: %w", err)
	}

	if payload.Nonce == "" {
		return "", errors.New("missing nonce in proof JWT payload")
	}

	return payload.Nonce, nil
}

type attestedKeyEntry struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// parseAttestedKeys returns all attested EC P-256 keys from a WUA JWT payload.
// ARF §6.6.2.3.3: rejects the attestation if its exp claim has passed.
func parseAttestedKeys(attestationJWT string) ([]attestedKeyEntry, error) {
	attParts := strings.Split(attestationJWT, ".")
	if len(attParts) != 3 {
		return nil, errors.New("invalid attestation JWT format")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(attParts[1])
	if err != nil {
		return nil, errors.New("invalid attestation payload encoding")
	}

	var payload struct {
		Exp          float64            `json:"exp"`
		KeyStorage   any                `json:"key_storage"`
		AttestedKeys []attestedKeyEntry `json:"attested_keys"`
	}

	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("invalid attestation payload JSON: %w", err)
	}

	if payload.Exp != 0 && !time.Now().Before(time.Unix(int64(payload.Exp), 0)) {
		return nil, errors.New("key_attestation has expired")
	}

	// ARF §6.6.2.3.3: key must be WSCD-level protected. TS3 (Wallet Unit
	// Attestation spec, v1.5+) models key_storage as an array of
	// attack-resistance levels.
	levels, ok := payload.KeyStorage.([]any)
	if !ok || !slices.ContainsFunc(levels, func(l any) bool {
		s, ok := l.(string)

		return ok && s == "iso_18045_high"
	}) {
		return nil, errors.New("invalid_proof")
	}

	if len(payload.AttestedKeys) == 0 {
		return nil, errors.New("no attested_keys in key_attestation")
	}

	return payload.AttestedKeys, nil
}

// extractKeyFromAttestation parses a key-attestation JWT (WUA JWT) and returns
// the x/y coordinates of the first attested EC P-256 public key.
// The attestation signature is NOT verified here; callers (routes/credential.go's
// validateProofKeyAttestation) run openid4vci.ValidateWUA against the same JWT
// before this extraction, so signature verification happens upstream of this call,
// not at the wallet-api boundary as before Phase 3 (see issuance-separation-plan.md).
func extractKeyFromAttestation(attestationJWT string) (x, y string, err error) {
	keys, err := parseAttestedKeys(attestationJWT)
	if err != nil {
		return "", "", err
	}

	key := keys[0]
	if key.Kty != "EC" || key.Crv != "P-256" || key.X == "" || key.Y == "" {
		return "", "", errors.New("attested key is not a valid EC P-256 key")
	}

	return key.X, key.Y, nil
}

// extractHardwareKeyTag reads the hardware_key_tag claim from a key
// attestation JWT's payload, without verifying its signature (trust is
// already established by the caller — either this issuer's own
// parseAttestedKeys validation or the upstream api-wallet service). Returns
// "" on any failure (malformed JWT, absent claim) since issuance tracking
// must never fail because device-linking metadata is missing.
func extractHardwareKeyTag(attestationJWT string) string {
	if attestationJWT == "" {
		return ""
	}

	parts := strings.Split(attestationJWT, ".")
	if len(parts) != 3 {
		return ""
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}

	var claims struct {
		HardwareKeyTag string `json:"hardware_key_tag"`
	}

	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return ""
	}

	return claims.HardwareKeyTag
}

// proofResultForKey builds a ProofResult for a key that came from a verified
// key_attestation (all current callers pass attested keys — see call sites
// in VerifyProofSignatureAll and VerifyProofSignature's key-attestation+jwt case).
// hardwareKeyTag is the device-binding tag extracted from the same attestation
// JWT the key was taken from (see extractHardwareKeyTag).
func proofResultForKey(xStr, yStr, hardwareKeyTag string) (*ProofResult, error) {
	xBytes, err := base64.RawURLEncoding.DecodeString(xStr)
	if err != nil {
		return nil, errors.New("invalid JWK x coordinate")
	}

	yBytes, err := base64.RawURLEncoding.DecodeString(yStr)
	if err != nil {
		return nil, errors.New("invalid JWK y coordinate")
	}

	uncompressed := make([]byte, 65)
	uncompressed[0] = 0x04
	copy(uncompressed[1:33], xBytes)
	copy(uncompressed[33:65], yBytes)
	keyHash := sha256.Sum256(uncompressed)

	return &ProofResult{
		HolderKeyID: fmt.Sprintf("%x", keyHash[:]),
		HolderJWK: map[string]string{
			"kty": "EC",
			"crv": "P-256",
			"x":   xStr,
			"y":   yStr,
		},
		KeyAttestationVerified: true,
		HardwareKeyTag:         hardwareKeyTag,
	}, nil
}

// VerifyProofSignatureAll verifies a WUA-bound proof JWT and returns one
// ProofResult per attested key in the WUA. For non-WUA proofs (plain JWK
// header) it returns a single-element slice identical to VerifyProofSignature.
//
// This supports the Android batch-issuance flow where the wallet sends one
// proof signed by attested_keys[0] but expects N credentials - one per
// attested key in the WUA.
func VerifyProofSignatureAll(proofJWT string) ([]*ProofResult, error) {
	// Run normal single verification first (validates alg, sig, key format).
	first, err := VerifyProofSignature(proofJWT)
	if err != nil {
		return nil, err
	}

	// Check whether the proof carries multiple attested keys (batch flow).
	parts := strings.Split(proofJWT, ".")
	headerBytes, _ := base64.RawURLEncoding.DecodeString(parts[0])

	var header struct {
		Typ            string `json:"typ"`
		KeyAttestation string `json:"key_attestation"`
	}

	_ = json.Unmarshal(headerBytes, &header)

	// Determine which JWT holds the attested_keys list.
	attestationJWT := header.KeyAttestation
	if slices.Contains(keyAttestationTyps, header.Typ) {
		attestationJWT = proofJWT
	}

	if attestationJWT == "" {
		return []*ProofResult{first}, nil
	}

	keys, err := parseAttestedKeys(attestationJWT)
	if err != nil || len(keys) <= 1 {
		return []*ProofResult{first}, nil
	}

	hardwareKeyTag := extractHardwareKeyTag(attestationJWT)

	results := make([]*ProofResult, 0, len(keys))
	for _, k := range keys {
		if k.Kty != "EC" || k.Crv != "P-256" || k.X == "" || k.Y == "" {
			continue
		}

		pr, err := proofResultForKey(k.X, k.Y, hardwareKeyTag)
		if err != nil {
			continue
		}

		results = append(results, pr)
	}

	if len(results) == 0 {
		return []*ProofResult{first}, nil
	}

	return results, nil
}

// VerifyProofSignature verifies only the ES256 signature and holder key of a
// proof JWT, without checking the audience or nonce claims. Used in the
// IDAuth-authenticated forwarded path where nonce/audience were already
// validated by the upstream api-wallet service.
//
// Supports two proof key formats:
//   - Standard: header.jwk contains the EC P-256 public key directly
//   - WUA-bound: header.key_attestation is a WUA JWT; the holder key is taken
//     from its attested_keys[0] claim
func VerifyProofSignature(proofJWT string) (*ProofResult, error) {
	parts := strings.Split(proofJWT, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT format")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("invalid header encoding")
	}

	var header struct {
		Alg            string `json:"alg"`
		Typ            string `json:"typ"`
		KeyAttestation string `json:"key_attestation"`
		JWK            struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"jwk"`
	}

	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("invalid header JSON: %w", err)
	}

	if header.Alg != "ES256" {
		return nil, fmt.Errorf("unsupported algorithm: %s (must be ES256)", header.Alg)
	}

	var xStr, yStr string

	var attested bool

	var hardwareKeyTag string

	switch {
	case slices.Contains(keyAttestationTyps, header.Typ):
		// OID4VCI attestation proof type: the JWT itself is the WUA/key-attestation,
		// signed by the issuer's key (not the holder's). Signature was already validated
		// upstream by api-wallet. Just extract the holder key from attested_keys[0].
		xStr, yStr, err = extractKeyFromAttestation(proofJWT)
		if err != nil {
			return nil, fmt.Errorf("invalid key-attestation proof: %w", err)
		}

		return proofResultForKey(xStr, yStr, extractHardwareKeyTag(proofJWT))
	case header.KeyAttestation != "":
		// WUA-bound proof: extract holder key from key_attestation JWT in header
		xStr, yStr, err = extractKeyFromAttestation(header.KeyAttestation)
		if err != nil {
			return nil, fmt.Errorf("invalid key_attestation: %w", err)
		}

		attested = true
		hardwareKeyTag = extractHardwareKeyTag(header.KeyAttestation)
	case header.JWK.Kty == "EC" && header.JWK.Crv == "P-256" && header.JWK.X != "" && header.JWK.Y != "":
		xStr = header.JWK.X
		yStr = header.JWK.Y
	default:
		return nil, errors.New("invalid or missing JWK in header")
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(xStr)
	if err != nil {
		return nil, errors.New("invalid JWK x coordinate")
	}

	yBytes, err := base64.RawURLEncoding.DecodeString(yStr)
	if err != nil {
		return nil, errors.New("invalid JWK y coordinate")
	}

	uncompressed := make([]byte, 65)
	uncompressed[0] = 0x04
	copy(uncompressed[1:33], xBytes)
	copy(uncompressed[33:65], yBytes)

	holderKey, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), uncompressed)
	if err != nil {
		return nil, errors.New("JWK point is not on P-256 curve")
	}

	signingInput := parts[0] + "." + parts[1]
	h := sha256.Sum256([]byte(signingInput))

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sigBytes) != 64 {
		return nil, errors.New("invalid signature encoding")
	}

	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])

	if !ecdsa.Verify(holderKey, h[:], r, s) {
		return nil, errors.New("proof JWT signature verification failed")
	}

	keyHash := sha256.Sum256(uncompressed)

	return &ProofResult{
		HolderKeyID: fmt.Sprintf("%x", keyHash[:]),
		HolderJWK: map[string]string{
			"kty": "EC",
			"crv": "P-256",
			"x":   xStr,
			"y":   yStr,
		},
		KeyAttestationVerified: attested,
		HardwareKeyTag:         hardwareKeyTag,
	}, nil
}
