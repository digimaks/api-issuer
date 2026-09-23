// SPDX-License-Identifier: EUPL-1.2

package credential

import (
	"github.com/digimaks/api-issuer/openid4vci"
)

// genericExcludedClaims are reserved JWT claims and internal session
// attributes that ride along in userData (IDAuth introspection claims,
// offer form bookkeeping) and must never be minted as credential claims.
var genericExcludedClaims = map[string]struct{}{
	"iss": {}, "sub": {}, "aud": {}, "exp": {}, "nbf": {}, "iat": {},
	"jti": {}, "vct": {}, "cnf": {}, "status": {}, "scope": {},
	"session_id": {}, "username": {}, "active": {}, "client_id": {},
	"token_type": {},
}

// genericSDJWTIssue returns an Issue func that mints an SD-JWT whose
// selectively-disclosable claims are the resolved userData map verbatim
// (nested objects stay structured and disclose as whole values), minus
// reserved keys. Validity is the generic CredentialTTL — PIDExpiry is
// PID-specific.
func genericSDJWTIssue(vct string) func(result *ProofResult, ctx *IssuanceContext) (string, error) {
	return func(result *ProofResult, ctx *IssuanceContext) (string, error) {
		claims := make(map[string]any, len(result.UserData))

		for k, v := range result.UserData {
			if _, excluded := genericExcludedClaims[k]; excluded {
				continue
			}

			claims[k] = v
		}

		return MintSDJWT(vct, claims, result, ctx, ctx.CredentialTTL)
	}
}

// RegisterGenericFromMetadata registers a generic SD-JWT credential type for
// every dc+sd-jwt configuration in the issuer metadata document that no
// code-registered type (PID) already claims. Adding a custom credential type
// therefore only requires an issuer_metadata.json entry — no Go changes.
// mso_mdoc entries are skipped: generic mdoc minting is unsupported, and an
// unregistered configuration is rejected at /credential as today.
func RegisterGenericFromMetadata(configs map[string]openid4vci.CredentialConfiguration) {
	for id, cfg := range configs {
		if cfg.Format != "dc+sd-jwt" {
			continue
		}

		if _, exists := Registry[id]; exists {
			continue
		}

		vct := cfg.VCT
		if vct == "" {
			vct = id
		}

		displayName := id

		var description string

		if cfg.CredentialMetadata != nil && len(cfg.CredentialMetadata.Display) > 0 {
			displayName = cfg.CredentialMetadata.Display[0].Name
		} else if len(cfg.Display) > 0 {
			displayName = cfg.Display[0].Name
			description = cfg.Display[0].Description
		}

		metaCfg := cfg

		Register(&Config{
			ID:          id,
			Format:      "dc+sd-jwt",
			VCT:         vct,
			DocType:     vct,
			DisplayName: displayName,
			Description: description,
			Claims:      cfg.Claims,
			Metadata: func() openid4vci.CredentialConfiguration {
				return metaCfg
			},
			Issue: genericSDJWTIssue(vct),
		})
	}
}
