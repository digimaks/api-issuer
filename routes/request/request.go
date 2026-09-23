// SPDX-License-Identifier: EUPL-1.2

package request

import "encoding/json"

// TokenRequest is the form-urlencoded body for POST /token.
type TokenRequest struct {
	// GrantType must be "urn:ietf:params:oauth:grant-type:pre-authorized_code".
	GrantType string `form:"grant_type"`

	// PreAuthorizedCode is the code from the credential offer.
	PreAuthorizedCode string `form:"pre-authorized_code"`

	// TXCode is the optional 5-digit transaction code from the credential offer.
	TXCode string `form:"tx_code"`
}

// CredentialRequest is the JSON body for POST /credential.
type CredentialRequest struct {
	// CredentialConfigurationID identifies the credential type.
	CredentialConfigurationID string `json:"credential_configuration_id" validate:"required"`

	// Proof is the holder-binding proof of possession (singular, legacy format).
	Proof CredentialProof `json:"proof"`

	// ProofJWTs holds all JWT strings collected from whichever proofs format was sent.
	// Populated by UnmarshalJSON - do not set directly.
	ProofJWTs []string `json:"-"`
}

// UnmarshalJSON handles both proofs formats:
//   - OID4VCI draft 14 map:   {"proofs": {"jwt": ["tok1", "tok2"]}}
//   - Android wallet array:   {"proofs": [{"jwt": "tok1"}, {"jwt": "tok2"}]}
//   - Legacy singular:        {"proof": {"proof_type": "jwt", "jwt": "tok"}}
func (r *CredentialRequest) UnmarshalJSON(data []byte) error {
	type alias CredentialRequest

	var raw struct {
		alias
		Proofs json.RawMessage `json:"proofs,omitempty"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	*r = CredentialRequest(raw.alias)

	if len(raw.Proofs) == 0 {
		return nil
	}

	// Try map format first: {"jwt": ["tok1", "tok2"]} or {"attestation": ["tok1"]}
	// OID4VCI §7.2.2 - keys are proof_type names; we collect JWT tokens from both.
	var mapFormat map[string][]string
	if err := json.Unmarshal(raw.Proofs, &mapFormat); err == nil {
		r.ProofJWTs = append(r.ProofJWTs, mapFormat["jwt"]...)
		r.ProofJWTs = append(r.ProofJWTs, mapFormat["attestation"]...)

		return nil
	}

	// Try array-of-objects format: [{"proof_type": "jwt", "jwt": "tok1"}, ...]
	// or [{"proof_type": "attestation", "attestation": "tok1"}, ...]
	var arrFormat []map[string]any
	if err := json.Unmarshal(raw.Proofs, &arrFormat); err == nil {
		for _, obj := range arrFormat {
			for _, key := range []string{"jwt", "attestation"} {
				switch v := obj[key].(type) {
				case string:
					if v != "" {
						r.ProofJWTs = append(r.ProofJWTs, v)
					}
				case []any:
					for _, elem := range v {
						if s, ok := elem.(string); ok && s != "" {
							r.ProofJWTs = append(r.ProofJWTs, s)
						}
					}
				}
			}
		}
	}

	return nil
}

// CredentialProof is the proof-of-possession in a credential request.
type CredentialProof struct {
	// ProofType must be "jwt".
	ProofType string `json:"proof_type" validate:"required"`

	// JWT is the signed proof JWT.
	JWT string `json:"jwt" validate:"required"`
}

// GenerateCredentialOfferRequest is the JSON body for POST /generate_credential_offer.
type GenerateCredentialOfferRequest struct {
	// Form contains raw session attributes to embed as credential claims.
	Form map[string]any `json:"form"`

	// CredentialIDs lists the credential_configuration_ids to offer.
	CredentialIDs []string `json:"credentialIds" validate:"required,min=1"`

	// CredentialOfferURI is the base URI for the credential offer deep link.
	CredentialOfferURI string `json:"credentialOfferURI"`

	// SessionID is an optional hint for the IDAuth session.
	SessionID string `json:"sessionId"`

	// GrantTypes selects which grants the offer carries. Empty means
	// pre-authorized_code only (legacy portal behavior).
	GrantTypes []string `json:"grantTypes" validate:"omitempty,dive,oneof=urn:ietf:params:oauth:grant-type:pre-authorized_code authorization_code"`
}
