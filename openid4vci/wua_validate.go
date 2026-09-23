// SPDX-License-Identifier: EUPL-1.2

package openid4vci

import (
	"bytes"
	"compress/zlib"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"azugo.io/azugo"
	"github.com/gmb-lib/go-platform-kit/httpclient"
	"github.com/golang-jwt/jwt/v5"
)

// ErrWalletProviderNotTrusted is returned when a Key Attestation's x5c chain
// does not verify against Configuration.TrustedWalletProviderRoots.
var ErrWalletProviderNotTrusted = errors.New("wallet provider certificate chain not trusted")

// keyAttestationTyps are the JOSE "typ" values accepted for a Key Attestation
// (KA) JWT. "keyattestation+jwt" (no hyphen) is the current TS3 (Wallet Unit
// Attestation spec, v1.5+) value. "key-attestation+jwt" (hyphenated) is a
// pre-v1.5 draft value still emitted by api-wallet-digimaks's
// IssueWalletUnitAttestation (openid4vci/attestation_endpoints.go).
//
// TODO(TS3 alignment): drop "key-attestation+jwt" once api-wallet-digimaks
// emits the spec-correct "keyattestation+jwt" — see
// api-wallet-digimaks/openid4vci/attestation_endpoints.go.
var keyAttestationTyps = []string{"keyattestation+jwt", "key-attestation+jwt"}

// ValidateWUA cryptographically verifies a Key Attestation (KA) JWT — TS3
// (Wallet Unit Attestation spec, v1.5+) dropped the `iss` claim entirely, so
// the Wallet Provider's identity and trust derive solely from the `x5c`
// header: the leaf certificate's public key verifies the JWT signature, and
// the leaf must chain (via any intermediates also carried in `x5c`) to a
// root in Configuration.TrustedWalletProviderRoots.
//
// It also:
//   - requires typ in keyAttestationTyps and an ES256/ES384/ES512 signature,
//   - enforces key_storage containing "iso_18045_high" (ARF §6.6.2.3.3 WSCD
//     level; TS3 v1.5+ models key_storage as an array of levels),
//   - and, when the KA carries a key_storage_status claim, checks the
//     wallet unit has not been revoked on its issuer's status list.
func (s *Service) ValidateWUA(ctx *azugo.Context, jwtStr string) error {
	parts := strings.Split(jwtStr, ".")
	if len(parts) != 3 {
		return errors.New("invalid jwt format")
	}

	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("failed to decode header: %w", err)
	}

	var header struct {
		Typ string   `json:"typ"`
		X5C []string `json:"x5c"`
	}
	if err := json.Unmarshal(hb, &header); err != nil {
		return fmt.Errorf("failed to parse header: %w", err)
	}

	if !slices.Contains(keyAttestationTyps, header.Typ) {
		return fmt.Errorf("unexpected typ %q, want one of %v", header.Typ, keyAttestationTyps)
	}

	if len(header.X5C) == 0 {
		return errors.New("missing x5c in JWT header")
	}

	chain := make([]*x509.Certificate, 0, len(header.X5C))

	for i, entry := range header.X5C {
		der, err := base64.StdEncoding.DecodeString(entry)
		if err != nil {
			return fmt.Errorf("invalid x5c[%d]: %w", i, err)
		}

		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("cannot parse x5c[%d] cert: %w", i, err)
		}

		chain = append(chain, cert)
	}

	leaf := chain[0]

	roots, err := s.config.TrustedWalletProviderCertPool()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrWalletProviderNotTrusted, err)
	}

	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}

	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return fmt.Errorf("%w: %w", ErrWalletProviderNotTrusted, err)
	}

	token, err := jwt.Parse(
		jwtStr,
		func(t *jwt.Token) (any, error) {
			return leaf.PublicKey, nil
		},
		jwt.WithValidMethods([]string{"ES256", "ES384", "ES512"}),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		if isJWTError(err) {
			return err
		}

		return fmt.Errorf("key attestation signature verification failed: %w", err)
	}

	if !token.Valid {
		return errors.New("invalid key attestation signature")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return errors.New("invalid key attestation claims")
	}

	if !hasKeyStorageLevel(claims["key_storage"], "iso_18045_high") {
		return errors.New("insufficient key storage level")
	}

	if kss, ok := claims["key_storage_status"].(map[string]any); ok {
		if st, ok := kss["status"].(map[string]any); ok {
			if sl, ok := st["status_list"].(map[string]any); ok {
				idx, ok := sl["idx"].(float64)
				if !ok {
					return errors.New("status list missing idx")
				}

				uri, ok := sl["uri"].(string)
				if !ok || strings.TrimSpace(uri) == "" {
					return errors.New("status list missing uri")
				}

				if err := validateStatusList(ctx, uri, idx); err != nil {
					return fmt.Errorf("failed to validate wallet unit status: %w", err)
				}
			}
		}
	}

	return nil
}

// hasKeyStorageLevel reports whether the key_storage claim — a TS3 v1.5+
// array of attack-resistance levels — contains want.
func hasKeyStorageLevel(v any, want string) bool {
	levels, ok := v.([]any)
	if !ok {
		return false
	}

	return slices.ContainsFunc(levels, func(l any) bool {
		s, ok := l.(string)

		return ok && s == want
	})
}

// validateStatusList fetches the IETF Token Status List JWT at uri and
// verifies the entry at idx is not marked revoked. Requires an x5c header
// (leaf certificate public key) — no other trust model is supported.
func validateStatusList(ctx *azugo.Context, uri string, idx float64) error {
	client := ctx.HTTPClient()

	resp, err := client.Get(uri, httpclient.CorrelationOptions(ctx)...)
	if err != nil {
		return fmt.Errorf("failed to fetch status list: %w", err)
	}

	jws := string(resp)

	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return errors.New("status list is not a compact JWS")
	}

	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("failed to decode header: %w", err)
	}

	var hdr struct {
		Typ string   `json:"typ"`
		Alg string   `json:"alg"`
		X5C []string `json:"x5c"`
	}
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return fmt.Errorf("failed to parse header: %w", err)
	}

	if hdr.Typ != "statuslist+jwt" {
		return errors.New("unexpected typ")
	}

	if hdr.Alg == "" {
		return errors.New("missing alg")
	}

	if len(hdr.X5C) == 0 {
		return errors.New("missing x5c header")
	}

	der, err := base64.StdEncoding.DecodeString(hdr.X5C[0])
	if err != nil {
		return fmt.Errorf("invalid x5c leaf: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("cannot parse x5c leaf cert: %w", err)
	}

	tok, err := jwt.Parse(jws, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != hdr.Alg {
			return nil, errors.New("alg mismatch")
		}

		return cert.PublicKey, nil
	}, jwt.WithValidMethods([]string{hdr.Alg}))
	if err != nil {
		if isJWTError(err) {
			return err
		}

		return fmt.Errorf("invalid signature: %w", err)
	}

	if !tok.Valid {
		return errors.New("invalid signature")
	}

	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return errors.New("invalid claims")
	}

	if sub, _ := claims["sub"].(string); strings.TrimSpace(sub) != strings.TrimSpace(uri) {
		return errors.New("sub mismatch")
	}

	iatF, ok := claims["iat"].(float64)
	if !ok {
		return errors.New("missing iat")
	}

	if time.Unix(int64(iatF), 0).After(time.Now().Add(2 * time.Minute)) {
		return errors.New("iat is in the future")
	}

	statusList, ok := claims["status_list"].(map[string]any)
	if !ok {
		return errors.New("missing status_list")
	}

	bitsF, ok := statusList["bits"].(float64)
	if !ok || bitsF <= 0 {
		return errors.New("missing or invalid bits")
	}

	lstStr, ok := statusList["lst"].(string)
	if !ok || strings.TrimSpace(lstStr) == "" {
		return errors.New("missing lst")
	}

	raw, err := base64.RawURLEncoding.DecodeString(lstStr)
	if err != nil {
		return fmt.Errorf("invalid lst encoding: %w", err)
	}

	dec, err := zlib.NewReader(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("zlib init failed: %w", err)
	}

	defer func() { _ = dec.Close() }()

	buf := new(bytes.Buffer)

	const maxDecompressedSize = 10 * 1024 * 1024

	if _, err := io.Copy(buf, io.LimitReader(dec, maxDecompressedSize)); err != nil {
		return fmt.Errorf("zlib decompress failed: %w", err)
	}

	if buf.Len() >= maxDecompressedSize {
		return errors.New("decompressed data exceeds size limit")
	}

	listed, err := isIndexListed(buf.Bytes(), int(idx), int(bitsF))
	if err != nil {
		return err
	}

	if listed {
		return fmt.Errorf("entry at idx=%d is listed (revoked)", int(idx))
	}

	return nil
}

// isIndexListed returns true if the entry at index is set in the bitset
// (LSB-first bit ordering per IETF Token Status List draft §8.1).
func isIndexListed(bitset []byte, index, bitsPerEntry int) (bool, error) {
	if index < 0 {
		return false, errors.New("invalid idx")
	}

	if bitsPerEntry <= 0 {
		return false, errors.New("invalid bits per entry")
	}

	totalBits := len(bitset) * 8
	maxIndex := (totalBits / bitsPerEntry) - 1

	if index > maxIndex {
		// Beyond available data — treat as not listed (valid/not revoked).
		return false, nil
	}

	offset := index * bitsPerEntry

	if bitsPerEntry == 1 {
		bytePos := offset / 8
		if bytePos >= len(bitset) {
			return false, nil
		}

		bitPos := offset % 8

		return bitset[bytePos]&(1<<bitPos) != 0, nil
	}

	val := 0

	for i := range bitsPerEntry {
		curOffset := offset + i
		bp := curOffset / 8

		if bp >= len(bitset) {
			break
		}

		ip := curOffset % 8
		bit := (bitset[bp] >> ip) & 0x01
		val |= int(bit) << i
	}

	return val != 0, nil
}

// isJWTError reports whether err originates from jwt.Parse's own validation
// (bad signature, expired, malformed) as opposed to a transport/programming
// error, so callers can decide how to classify the failure.
func isJWTError(err error) bool {
	return errors.Is(err, jwt.ErrInvalidKey) ||
		errors.Is(err, jwt.ErrInvalidKeyType) ||
		errors.Is(err, jwt.ErrHashUnavailable) ||
		errors.Is(err, jwt.ErrTokenMalformed) ||
		errors.Is(err, jwt.ErrTokenUnverifiable) ||
		errors.Is(err, jwt.ErrTokenSignatureInvalid) ||
		errors.Is(err, jwt.ErrTokenRequiredClaimMissing) ||
		errors.Is(err, jwt.ErrTokenInvalidAudience) ||
		errors.Is(err, jwt.ErrTokenExpired) ||
		errors.Is(err, jwt.ErrTokenUsedBeforeIssued) ||
		errors.Is(err, jwt.ErrTokenInvalidIssuer) ||
		errors.Is(err, jwt.ErrTokenInvalidSubject) ||
		errors.Is(err, jwt.ErrTokenNotValidYet) ||
		errors.Is(err, jwt.ErrTokenInvalidId) ||
		errors.Is(err, jwt.ErrTokenInvalidClaims) ||
		errors.Is(err, jwt.ErrInvalidType)
}
