// SPDX-License-Identifier: EUPL-1.2

package credential

import "errors"

// Sentinel errors for credential minting failures, used with errors.Is by
// routes/credential.go to attach a fine-grained problem detail to the
// generic mint failure this package already reports to its caller.
var (
	ErrSigningKeyLoadFailed       = errors.New("failed to load signing key")
	ErrSigningKeyInvalidType      = errors.New("signing key is not ECDSA")
	ErrJWTPartMarshalFailed       = errors.New("failed to marshal JWT part")
	ErrSignatureComputationFailed = errors.New("failed to compute signature")
	ErrMDocNonceGenerationFailed  = errors.New("failed to generate random nonce")
	ErrMDocClaimEncodingFailed    = errors.New("failed to encode claim item")
	ErrMDocMSOBuildFailed         = errors.New("failed to build MSO")
	ErrMDocCertDecodeFailed       = errors.New("failed to decode x5c certificate")
	ErrMDocCOSEStructureFailed    = errors.New("failed to build COSE structure")
	ErrMDocDocumentEncodingFailed = errors.New("failed to encode mdoc document")
)
