// SPDX-License-Identifier: EUPL-1.2

// Package credential provides mso_mdoc (ISO 18013-5 CBOR) credential minting.
//
// The encoding follows the OpenID4VCI mso_mdoc profile:
//   - Issuer-signed CBOR with COSE_Sign1 envelope (alg: ES256, untagged per ISO 18013-5 §9.1.2)
//   - Namespaces: eu.europa.ec.eudi.pid.1
//   - IssuerSignedItems wrapped as #6.24(bstr) per ISO 18013-5
//   - Holder binding via DeviceKeyInfo (P-256 COSE key with integer labels)
//   - ValidityInfo carries CBOR-tagged tdate (tag 0) timestamps

package credential

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// MintMDoc creates and signs an mso_mdoc credential.
// Returns the base64url-encoded IssuerSigned document bytes.
func MintMDoc(docType string, claims map[string]any, result *ProofResult, ctx *IssuanceContext, expiry time.Duration) (string, error) {
	privKey, _, err := ctx.SigningKeyFunc()
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrSigningKeyLoadFailed, err)
	}

	ecKey, ok := privKey.(*ecdsa.PrivateKey)
	if !ok {
		return "", ErrSigningKeyInvalidType
	}

	now := time.Now()

	// Build IssuerSignedItems (wrapped as #6.24(bstr)) and their digests in one pass.
	issuerSignedItems, digests, err := buildIssuerSignedItems(claims)
	if err != nil {
		return "", fmt.Errorf("failed to build namespace items: %w", err)
	}

	nameSpaces := map[string][]cbor.RawMessage{
		docType: issuerSignedItems,
	}

	// Build MSO (Mobile Security Object) using the actual digests from above.
	mso, err := buildMSO(docType, digests, result, ctx, now, expiry)
	if err != nil {
		return "", fmt.Errorf("failed to build MSO: %w", err)
	}

	// Decode x5c strings (base64 std-encoded DER) to raw DER byte slices.
	x5cDER := make([][]byte, 0, len(ctx.X5C))
	for _, b64cert := range ctx.X5C {
		der, err := base64.StdEncoding.DecodeString(b64cert)
		if err != nil {
			return "", fmt.Errorf("%w: %w", ErrMDocCertDecodeFailed, err)
		}

		x5cDER = append(x5cDER, der)
	}

	// Sign MSO as COSE_Sign1 (tag 18) with x5chain in unprotected header.
	issuerAuth, err := cosSign1(ecKey, mso, x5cDER)
	if err != nil {
		return "", fmt.Errorf("failed to sign MSO: %w", err)
	}

	// Assemble IssuerSigned document.
	// issuerAuth is embedded as cbor.RawMessage so it is inlined as a CBOR array,
	// not re-encoded as a byte string.
	//
	// The credential value must be just the IssuerSigned map (nameSpaces + issuerAuth)
	// because the Android EUDI SDK's MsoMdocCredentialCertifier.certifyCredential
	// calls DecodeFromBytes(data) and then data["issuerAuth"] directly at the top level.
	issuerSignedMap := map[string]any{
		"nameSpaces": nameSpaces,
		"issuerAuth": cbor.RawMessage(issuerAuth),
	}

	// Encode as CBOR and return as base64url.
	encoded, err := cbor.Marshal(issuerSignedMap)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrMDocDocumentEncodingFailed, err)
	}

	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

// issuerSignedItem is a single IssuerSignedItem as per ISO 18013-5.
type issuerSignedItem struct {
	DigestID          uint64 `cbor:"digestID"`
	Random            []byte `cbor:"random"`
	ElementIdentifier string `cbor:"elementIdentifier"`
	ElementValue      any    `cbor:"elementValue"`
}

// buildIssuerSignedItems creates CBOR-encoded IssuerSignedItems for each claim.
// Each item is wrapped as #6.24(bstr) per ISO 18013-5.
// Returns both the wrapped items and a map of digestID → SHA-256(IssuerSignedItemBytes).
// Per ISO 18013-5 §9.1.2.5, the digest is computed over the full IssuerSignedItemBytes
// = CBOR_encode(#6.24(bstr(IssuerSignedItem))), not over the raw item bytes.
func buildIssuerSignedItems(claims map[string]any) ([]cbor.RawMessage, map[uint64][]byte, error) {
	items := make([]cbor.RawMessage, 0, len(claims))
	digests := make(map[uint64][]byte, len(claims))

	var digestID uint64

	for name, value := range claims {
		rnd := make([]byte, 16)
		if _, err := rand.Read(rnd); err != nil {
			return nil, nil, fmt.Errorf("%w: %w", ErrMDocNonceGenerationFailed, err)
		}

		item := issuerSignedItem{
			DigestID:          digestID,
			Random:            rnd,
			ElementIdentifier: name,
			ElementValue:      value,
		}

		enc, err := cbor.Marshal(item)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %w", ErrMDocClaimEncodingFailed, err)
		}

		// Wrap as #6.24(bstr) per ISO 18013-5.
		tagged, err := cbor.Marshal(cbor.Tag{Number: 24, Content: enc})
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %w", ErrMDocClaimEncodingFailed, err)
		}

		// Digest per ISO 18013-5 §9.1.2.5: SHA-256(IssuerSignedItemBytes)
		// IssuerSignedItemBytes = CBOR_encode(#6.24(bstr(IssuerSignedItem))) = tagged.
		h := sha256.Sum256(tagged)
		digests[digestID] = h[:]

		digestID++

		items = append(items, cbor.RawMessage(tagged))
	}

	return items, digests, nil
}

// msoDoc is the Mobile Security Object structure.
type msoDoc struct {
	Version         string                       `cbor:"version"`
	DigestAlgorithm string                       `cbor:"digestAlgorithm"`
	ValueDigests    map[string]map[uint64][]byte `cbor:"valueDigests"`
	DeviceKeyInfo   map[string]any               `cbor:"deviceKeyInfo"`
	DocType         string                       `cbor:"docType"`
	ValidityInfo    map[string]any               `cbor:"validityInfo"`
	Status          map[string]any               `cbor:"status,omitempty"`
}

// buildMSO constructs the Mobile Security Object to be signed.
// digests must be the precomputed SHA-256 digests from buildIssuerSignedItems.
func buildMSO(docType string, digests map[uint64][]byte, result *ProofResult, ctx *IssuanceContext, now time.Time, expiry time.Duration) ([]byte, error) {
	xBytes := mustDecodeBase64URL(result.HolderJWK["x"])
	yBytes := mustDecodeBase64URL(result.HolderJWK["y"])

	// COSE key with integer labels per RFC 8152.
	// 1 = kty (EC2=2), -1 = crv (P-256=1), -2 = x, -3 = y.
	deviceKey := map[int]any{
		1:  2,
		-1: 1,
		-2: xBytes,
		-3: yBytes,
	}

	deviceKeyInfo := map[string]any{
		"deviceKey": deviceKey,
	}

	// ValidityInfo dates as CBOR tdate (tag 0 + RFC 3339 string).
	signed := now.UTC().Format(time.RFC3339)
	validityInfo := map[string]any{
		"signed":     cbor.Tag{Number: 0, Content: signed},
		"validFrom":  cbor.Tag{Number: 0, Content: signed},
		"validUntil": cbor.Tag{Number: 0, Content: now.Add(expiry).UTC().Format(time.RFC3339)},
	}

	mso := msoDoc{
		Version:         "1.0",
		DigestAlgorithm: "SHA-256",
		ValueDigests:    map[string]map[uint64][]byte{docType: digests},
		DeviceKeyInfo:   deviceKeyInfo,
		DocType:         docType,
		ValidityInfo:    validityInfo,
	}

	if ctx.StatusListURI != "" {
		mso.Status = map[string]any{
			"status_list": map[string]any{
				"idx": ctx.StatusListIdx,
				"uri": ctx.StatusListURI,
			},
		}
	}

	encoded, err := cbor.Marshal(mso)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMDocMSOBuildFailed, err)
	}

	return encoded, nil
}

// cosSign1 creates an untagged COSE_Sign1 array over the payload bytes.
// Protected header: {1: -7} (alg: ES256).
// Per ISO 18013-5 §9.1.2 the IssuerAuth field is embedded in the IssuerSigned CBOR map
// and must be an untagged COSE_Sign1 (4-element array). CBOR tag 18 is reserved for
// standalone COSE messages and is rejected by strict parsers (e.g. iOS EUDIW SDK).
// Position [2] is a plain bstr whose content is CBOR_encode(#6.24(bstr(MSO))).
// x5cDER is the DER-encoded signing certificate chain placed in the unprotected header
// (COSE header label 33) so verifiers can trust the issuer signature.
func cosSign1(key *ecdsa.PrivateKey, payload []byte, x5cDER [][]byte) ([]byte, error) {
	// Protected header: alg ES256 (-7 in COSE) encoded as a bstr.
	protected, err := cbor.Marshal(map[int]int{1: -7})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMDocCOSEStructureFailed, err)
	}

	// Encode the MSO as #6.24(bstr(MSO)) - this becomes the bstr content at COSE[2].
	// Using []byte (not cbor.RawMessage) so fxamacker wraps it in a bstr in the array.
	payloadTagged, err := cbor.Marshal(cbor.Tag{Number: 24, Content: payload})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMDocCOSEStructureFailed, err)
	}

	// Sig_structure for COSE_Sign1: ["Signature1", protected, external_aad, payload].
	// The payload bstr content = payloadTagged (the CBOR-encoded #6.24(bstr(MSO))).
	// This matches what's stored at COSE_Sign1[2] as per RFC 8152.
	sigStructure, err := cbor.Marshal([]any{
		"Signature1",
		protected,
		[]byte{},      // external_aad
		payloadTagged, // []byte → bstr in Sig_structure
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMDocCOSEStructureFailed, err)
	}

	h := sha256.Sum256(sigStructure)

	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSignatureComputationFailed, err)
	}

	sig := make([]byte, 64)
	copy(sig[32-len(r.Bytes()):32], r.Bytes())
	copy(sig[64-len(s.Bytes()):64], s.Bytes())

	// Build unprotected header: {33: x5chain} where 33 is the COSE x5chain label.
	// If there's only one cert, use a single bstr; if multiple, use an array of bstr.
	var unprotectedHeader map[int]any
	if len(x5cDER) == 1 {
		unprotectedHeader = map[int]any{33: x5cDER[0]}
	} else if len(x5cDER) > 1 {
		certs := make([]any, len(x5cDER))
		for i, der := range x5cDER {
			certs[i] = der
		}

		unprotectedHeader = map[int]any{33: certs}
	} else {
		unprotectedHeader = map[int]any{}
	}

	// IssuerAuth is an untagged COSE_Sign1 array per ISO 18013-5 §9.1.2.
	// CBOR tag 18 is only used for standalone COSE messages; when embedded inside
	// the IssuerSigned map it must be the raw 4-element array so iOS and other
	// strict parsers can read it. Android's waltid accepts both tagged and untagged.
	// Position [2] must be a plain bstr whose content = CBOR_encode(#6.24(bstr(MSO))).
	return cbor.Marshal([]any{
		protected,
		unprotectedHeader,
		payloadTagged, // []byte → bstr(CBOR_encode(#6.24(bstr(MSO))))
		sig,
	})
}

func mustDecodeBase64URL(s string) []byte {
	b, _ := base64.RawURLEncoding.DecodeString(s)
	return b
}
