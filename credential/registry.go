// SPDX-License-Identifier: EUPL-1.2

package credential

import (
	"time"

	"github.com/digimaks/api-issuer/openid4vci"
)

// ProofResult contains the verified holder context extracted from the proof JWT.
type ProofResult struct {
	// HolderKeyID is the hex-encoded SHA-256 of the uncompressed EC public key.
	HolderKeyID string

	// HolderJWK is the raw public key as a string map (kty, crv, x, y).
	HolderJWK map[string]string

	// SessionID is the IDAuth session that authorized this issuance.
	SessionID string

	// UserData carries person attributes from the IDAuth session or WUA payload.
	UserData map[string]any

	// KeyAttestationVerified is true when this result's holder key was
	// extracted from a verified key_attestation (WUA-bound proof, or the
	// key-attestation+jwt proof type) rather than a bare JWK. parseAttestedKeys
	// already hard-rejects any key_storage other than "iso_18045_high", so a
	// true value here implies that storage level — no separate level field needed.
	KeyAttestationVerified bool

	// HardwareKeyTag is the device-binding tag read from the proof's
	// key-attestation JWT (hardware_key_tag claim), if present. Empty when
	// the proof carries no key attestation or the claim is absent.
	HardwareKeyTag string
}

// Config describes a single issuable credential type.
type Config struct {
	// ID is the credential_configuration_id key used in OID4VCI metadata.
	ID string

	// Format is "dc+sd-jwt" or "mso_mdoc".
	Format string

	// VCT is the Verifiable Credential Type URI (SD-JWT-VC only).
	VCT string

	// DocType is the ISO mdoc document type (mso_mdoc only).
	DocType string

	// DisplayName is the human-readable credential name.
	DisplayName string

	// Description is the human-readable credential description.
	Description string

	// Claims defines the claim names and metadata for OID4VCI metadata.
	Claims map[string]any

	// Metadata returns the openid4vci.CredentialConfiguration for the issuer metadata document.
	Metadata func() openid4vci.CredentialConfiguration

	// Issue signs and encodes the credential, returning the serialized form.
	Issue func(result *ProofResult, vci *IssuanceContext) (string, error)
}

// Registry maps credential_configuration_id to credential configs.
var Registry = map[string]*Config{}

// Register adds a credential type to the global registry.
func Register(c *Config) {
	Registry[c.ID] = c
}

// IssuanceContext carries signing material and issuer settings needed during issuance.
type IssuanceContext struct {
	// PublicURL is the issuer's public base URL.
	PublicURL string

	// Country is the ISO two-letter issuer country code.
	Country string

	// IssuingAuthority is the human-readable name of the issuing authority.
	// Used as a fallback when the credential data does not supply issuing_authority.
	IssuingAuthority string

	// SigningKeyFunc returns the private key used for signing.
	SigningKeyFunc func() (any, string, error)

	// X5C is the PEM certificate chain included in JWT headers.
	X5C []string

	// StatusListIdx is the revocation status list index for this credential.
	StatusListIdx int

	// StatusListURI is the URI of the IETF Token Status List JWT for this credential.
	StatusListURI string

	// CredentialTTL is the validity period to embed in the issued credential.
	CredentialTTL time.Duration

	// PIDExpiry is the technical validity period for PID credentials.
	// ARF §5.3 requires short-lived PIDs; distinct from CredentialTTL.
	PIDExpiry time.Duration
}
