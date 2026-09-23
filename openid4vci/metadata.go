// SPDX-License-Identifier: EUPL-1.2

package openid4vci

import (
	_ "embed"
	"encoding/json"
	"os"

	"azugo.io/azugo"
)

//go:embed issuer_metadata.json
var embeddedIssuerMetadataJSON []byte

// loadIssuerMetadataJSON returns metadataPath's contents when set, otherwise
// the embedded default. Ignores read errors — an invalid override falls back
// to the embedded document rather than crashing metadata serving.
func loadIssuerMetadataJSON(metadataPath string) []byte {
	if metadataPath == "" {
		return embeddedIssuerMetadataJSON
	}

	b, err := os.ReadFile(metadataPath)
	if err != nil {
		return embeddedIssuerMetadataJSON
	}

	return b
}

// issuerMetadataTemplate is the static portion of the issuer metadata loaded from the embedded JSON.
// URL fields (credential_issuer, credential_endpoint, etc.) are filled in at serve time.
type issuerMetadataTemplate struct {
	BatchCredentialIssuance                       *BatchCredentialIssuance           `json:"batch_credential_issuance,omitempty"`
	ClientAttestationPopSigningAlgValuesSupported []string                           `json:"client_attestation_pop_signing_alg_values_supported,omitempty"`
	ClientAttestationSigningAlgValuesSupported    []string                           `json:"client_attestation_signing_alg_values_supported,omitempty"`
	CredentialConfigurationsSupported             map[string]CredentialConfiguration `json:"credential_configurations_supported"`
	CredentialRequestEncryption                   *EncryptionConfig                  `json:"credential_request_encryption,omitempty"`
	CredentialResponseEncryption                  *EncryptionConfig                  `json:"credential_response_encryption,omitempty"`
	Display                                       []IssuerDisplay                    `json:"display,omitempty"`
}

// IssuerMetadata is the OpenID4VCI credential issuer metadata document (OID4VCI §11.2.3).
type IssuerMetadata struct {
	CredentialIssuer                              string                             `json:"credential_issuer"`
	AuthorizationServers                          []string                           `json:"authorization_servers"`
	CredentialEndpoint                            string                             `json:"credential_endpoint"`
	NonceEndpoint                                 string                             `json:"nonce_endpoint"`
	BatchCredentialIssuance                       *BatchCredentialIssuance           `json:"batch_credential_issuance,omitempty"`
	ClientAttestationSigningAlgValuesSupported    []string                           `json:"client_attestation_signing_alg_values_supported,omitempty"`
	ClientAttestationPopSigningAlgValuesSupported []string                           `json:"client_attestation_pop_signing_alg_values_supported,omitempty"`
	CredentialConfigurationsSupported             map[string]CredentialConfiguration `json:"credential_configurations_supported"`
	CredentialRequestEncryption                   *EncryptionConfig                  `json:"credential_request_encryption,omitempty"`
	CredentialResponseEncryption                  *EncryptionConfig                  `json:"credential_response_encryption,omitempty"`
	Display                                       []IssuerDisplay                    `json:"display,omitempty"`
	TrustListURI                                  string                             `json:"trust_list_uri,omitempty"`
	SignedMetadata                                string                             `json:"signed_metadata,omitempty"`
}

// BatchCredentialIssuance advertises support for the OID4VCI batch issuance extension.
type BatchCredentialIssuance struct {
	BatchSize int `json:"batch_size"`
}

// IssuerDisplay is a localized display entry for the issuer.
type IssuerDisplay struct {
	Name   string          `json:"name"`
	Locale string          `json:"locale"`
	Logo   *DisplayLogoURI `json:"logo,omitempty"`
}

// DisplayLogoURI is a logo with a URI and optional alt text.
type DisplayLogoURI struct {
	URI     string `json:"uri,omitempty"`
	URL     string `json:"url,omitempty"`
	AltText string `json:"alt_text,omitempty"`
}

// EncryptionConfig describes supported encryption algorithms for request/response encryption.
type EncryptionConfig struct {
	AlgValuesSupported []string `json:"alg_values_supported"`
	EncValuesSupported []string `json:"enc_values_supported"`
	EncryptionRequired bool     `json:"encryption_required"`
}

// CredentialConfiguration describes a single issuable credential type in issuer metadata.
type CredentialConfiguration struct {
	Format                               string                      `json:"format"`
	VCT                                  string                      `json:"vct,omitempty"`
	DocType                              string                      `json:"doctype,omitempty"`
	Scope                                string                      `json:"scope,omitempty"`
	Policy                               *CredentialPolicy           `json:"policy,omitempty"`
	CryptographicBindingMethodsSupported []string                    `json:"cryptographic_binding_methods_supported,omitempty"`
	CredentialSigningAlgValuesSupported  []string                    `json:"credential_signing_alg_values_supported,omitempty"`
	CredentialAlgValuesSupported         []int                       `json:"credential_alg_values_supported,omitempty"`
	CredentialCrvValuesSupported         []int                       `json:"credential_crv_values_supported,omitempty"`
	ProofTypesSupported                  map[string]ProofTypeSupport `json:"proof_types_supported,omitempty"`
	CredentialMetadata                   *CredentialMetadata         `json:"credential_metadata,omitempty"`
	// Claims is kept for backward-compat with existing Registry callers that set it directly.
	// Omitted from JSON when CredentialMetadata is present.
	Claims map[string]any `json:"claims,omitempty"`
	// Display is kept for backward-compat; prefer CredentialMetadata.Display.
	Display []CredentialDisplay `json:"display,omitempty"`
}

// CredentialPolicy describes issuance policy for a credential type.
type CredentialPolicy struct {
	BatchSize  int  `json:"batch_size,omitempty"`
	OneTimeUse bool `json:"one_time_use,omitempty"`
}

// CredentialMetadata holds the display and claims metadata for a credential configuration.
type CredentialMetadata struct {
	Display []CredentialMetadataDisplay `json:"display,omitempty"`
	Claims  []CredentialClaim           `json:"claims,omitempty"`
}

// CredentialMetadataDisplay is a localized display entry with logo for a credential type.
type CredentialMetadataDisplay struct {
	Name   string          `json:"name"`
	Locale string          `json:"locale"`
	Logo   *DisplayLogoURI `json:"logo,omitempty"`
}

// CredentialClaim describes a single claim in a credential, with its path and display.
type CredentialClaim struct {
	Path      []string       `json:"path"`
	Mandatory bool           `json:"mandatory,omitempty"`
	ValueType string         `json:"value_type,omitempty"`
	Display   []ClaimDisplay `json:"display,omitempty"`
}

// ClaimDisplay is a localized display name for a claim.
type ClaimDisplay struct {
	Name   string `json:"name"`
	Locale string `json:"locale"`
}

// ProofTypeSupport lists supported signing algorithms for a proof type.
type ProofTypeSupport struct {
	ProofSigningAlgValuesSupported []string            `json:"proof_signing_alg_values_supported"`
	ProofAlgValuesSupported        []int               `json:"proof_alg_values_supported,omitempty"`
	ProofCrvValuesSupported        []int               `json:"proof_crv_values_supported,omitempty"`
	KeyAttestationsRequired        map[string][]string `json:"key_attestations_required,omitempty"`
}

// CredentialDisplay is a localized display entry for a credential type (legacy, used by Registry).
type CredentialDisplay struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Locale      string `json:"locale"`
}

// OAuthServerMetadata is the OAuth 2.0 authorization server metadata document.
type OAuthServerMetadata struct {
	Issuer                                        string   `json:"issuer"`
	AuthorizationEndpoint                         string   `json:"authorization_endpoint"`
	TokenEndpoint                                 string   `json:"token_endpoint"`
	GrantTypesSupported                           []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported             []string `json:"token_endpoint_auth_methods_supported"`
	ClientAttestationSigningAlgValuesSupported    []string `json:"client_attestation_signing_alg_values_supported"`
	ClientAttestationPopSigningAlgValuesSupported []string `json:"client_attestation_pop_signing_alg_values_supported"`
	DpopSigningAlgValuesSupported                 []string `json:"dpop_signing_alg_values_supported"`
	PreAuthorizedGrantAnonymousAccessSupported    bool     `json:"pre-authorized_grant_anonymous_access_supported"`
}

// EmbeddedCredentialConfigurations returns the credential configurations
// declared in issuer_metadata.json — the source the credential registry
// auto-registers generic SD-JWT types from. metadataPath overrides the
// embedded default when set (see Configuration.MetadataPath).
func EmbeddedCredentialConfigurations(metadataPath string) map[string]CredentialConfiguration {
	var tmpl issuerMetadataTemplate

	_ = json.Unmarshal(loadIssuerMetadataJSON(metadataPath), &tmpl)

	return tmpl.CredentialConfigurationsSupported
}

// IssuerMeta returns the OpenID4VCI issuer metadata.
// Static fields (credential configurations, encryption caps, display, attestation algs) are loaded
// from the embedded issuer_metadata.json; URL fields are set from config at serve time.
func (s *Service) IssuerMeta(_ *azugo.Context, _ map[string]CredentialConfiguration) *IssuerMetadata {
	var tmpl issuerMetadataTemplate
	// Ignore unmarshal errors — an invalid document is caught at startup; serve best-effort.
	_ = json.Unmarshal(loadIssuerMetadataJSON(s.config.MetadataPath), &tmpl)

	authServer := s.config.AuthorizationServerURL
	if authServer == "" {
		authServer = s.config.PublicURL
	}

	return &IssuerMetadata{
		CredentialIssuer:                              s.config.PublicURL,
		AuthorizationServers:                          []string{authServer},
		CredentialEndpoint:                            s.config.PublicURL + "/credential",
		NonceEndpoint:                                 s.config.PublicURL + "/nonce",
		BatchCredentialIssuance:                       tmpl.BatchCredentialIssuance,
		ClientAttestationSigningAlgValuesSupported:    tmpl.ClientAttestationSigningAlgValuesSupported,
		ClientAttestationPopSigningAlgValuesSupported: tmpl.ClientAttestationPopSigningAlgValuesSupported,
		CredentialConfigurationsSupported:             tmpl.CredentialConfigurationsSupported,
		CredentialRequestEncryption:                   tmpl.CredentialRequestEncryption,
		CredentialResponseEncryption:                  tmpl.CredentialResponseEncryption,
		Display:                                       tmpl.Display,
		TrustListURI:                                  s.config.TrustListURI,
	}
}

// OAuthServerMeta returns the OAuth 2.0 authorization server metadata,
// served under /.well-known/openid-configuration for clients that look
// there instead of the standard oauth-authorization-server path (which
// api-wallet-digimaks now serves natively — issuer-go no longer proxies
// or duplicates it).
//
// issuer-go is not itself an authorization server — idauth is (see
// docs/plans/issuance-separation-plan.md Phase 3b). authorization_endpoint
// and token_endpoint point at AuthorizationServerURL (idauth's public URL)
// rather than routes issuer-go doesn't have. When AuthorizationServerURL is
// unset, falls back to PublicURL to preserve prior self-hosted-AS behavior.
func (s *Service) OAuthServerMeta(_ *azugo.Context) *OAuthServerMetadata {
	authServer := s.config.AuthorizationServerURL
	if authServer == "" {
		authServer = s.config.PublicURL
	}

	return &OAuthServerMetadata{
		Issuer:                s.config.PublicURL,
		AuthorizationEndpoint: authServer + "/authorizationV3",
		TokenEndpoint:         authServer + "/api/1.0/token",
		GrantTypesSupported: []string{
			"authorization_code",
			"refresh_token",
			"urn:ietf:params:oauth:grant-type:pre-authorized_code",
		},
		TokenEndpointAuthMethodsSupported:             []string{"attest_jwt_client_auth"},
		ClientAttestationSigningAlgValuesSupported:    []string{"ES256"},
		ClientAttestationPopSigningAlgValuesSupported: []string{"ES256"},
		DpopSigningAlgValuesSupported:                 []string{"ES256"},
		PreAuthorizedGrantAnonymousAccessSupported:    true,
	}
}
