// SPDX-License-Identifier: EUPL-1.2

package response

// CredentialEntry is a single issued credential within a CredentialResponse.
type CredentialEntry struct {
	Credential string `json:"credential"`
	// Format is the OpenID4VCI credential format ("mso_mdoc" or "dc+sd-jwt").
	Format string `json:"format"`
	// ExpiresAt is the credential's actual, WIA/KA-capped expiry (RFC3339, UTC).
	ExpiresAt string `json:"expires_at"`
	// StatusListURI is the revocation status list this credential's slot belongs to.
	StatusListURI string `json:"status_list_uri"`
	// StatusListIdx is this credential's slot index within StatusListURI.
	StatusListIdx int `json:"status_list_idx"`
	// CredentialID identifies this credential's issuance record. Empty when
	// issuance tracking failed (non-fatal — the credential itself is still valid).
	CredentialID string `json:"credential_id,omitempty"`
}

// CredentialResponse is returned by POST /credential (OpenID4VCI Draft 14+).
type CredentialResponse struct {
	Credentials []CredentialEntry `json:"credentials"`
	CNonce      string            `json:"c_nonce,omitempty"`
	CNonceExp   int               `json:"c_nonce_expires_in,omitempty"`
	// CredentialID is the first issued credential's tracking ID, duplicated
	// here for single-credential requests (the common case). Batch requests
	// should use each CredentialEntry's own CredentialID instead.
	CredentialID string `json:"credential_id,omitempty"`
}

// NonceResponse is returned by POST /nonce.
type NonceResponse struct {
	CNonce    string `json:"c_nonce"`
	ExpiresIn int    `json:"c_nonce_expires_in"`
}

// GenerateCredentialOfferResponse is returned by POST /generate_credential_offer.
type GenerateCredentialOfferResponse struct {
	// TXCode is the numeric transaction code displayed to the user.
	// Omitted when the offer was generated with tx_code disabled.
	TXCode int `json:"tx_code,omitempty"`

	// URLData is the raw credential-offer deep link URL.
	URLData string `json:"urlData"`
}

// WUATokenResponse is returned by POST /wua/token.
type WUATokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

// ErrorResponse is the standard error payload.
type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}
