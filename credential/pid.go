// SPDX-License-Identifier: EUPL-1.2

package credential

import (
	"time"

	"github.com/digimaks/api-issuer/openid4vci"
)

// PID credential configuration IDs - match temp-py-issuer-eu credential IDs.
const (
	PIDSDJTVCID = "eu.europa.ec.eudi.pid_digimaks_pid_jwt_vc_json"
	PIDMDocID   = "eu.europa.ec.eudi.pid_digimaks_pid_mdoc"
)

// PID claim definitions - shared by SD-JWT-VC and mso_mdoc configurations.
var pidSDJWTClaims = map[string]any{
	"family_name":                    map[string]any{"mandatory": true, "value_type": "string", "display": []map[string]string{{"name": "Family Name", "locale": "en"}}},
	"given_name":                     map[string]any{"mandatory": true, "value_type": "string", "display": []map[string]string{{"name": "Given Name", "locale": "en"}}},
	"birth_date":                     map[string]any{"mandatory": true, "value_type": "string", "display": []map[string]string{{"name": "Date of Birth", "locale": "en"}}},
	"personal_administrative_number": map[string]any{"mandatory": false, "value_type": "string"},
	"issuance_date":                  map[string]any{"mandatory": true},
	"expiry_date":                    map[string]any{"mandatory": true, "value_type": "string"},
	"issuing_authority":              map[string]any{"mandatory": true, "value_type": "string"},
	"issuing_country":                map[string]any{"mandatory": true, "value_type": "string"},
}

func init() {
	Register(&Config{
		ID:          PIDSDJTVCID,
		Format:      "dc+sd-jwt",
		VCT:         "urn:eu.europa.ec.eudi:pid:1",
		DocType:     "eu.europa.ec.eudi.pid.1",
		DisplayName: "PID",
		Description: "Person Identification Data",
		Claims:      pidSDJWTClaims,
		Metadata: func() openid4vci.CredentialConfiguration {
			return JWK4SDJWTMeta(
				"urn:eu.europa.ec.eudi:pid:1",
				"PID",
				"Person Identification Data",
				pidSDJWTClaims,
			)
		},
		Issue: func(result *ProofResult, ctx *IssuanceContext) (string, error) {
			claims := buildPIDClaims(result.UserData, ctx)
			return MintSDJWT("urn:eu.europa.ec.eudi:pid:1", claims, result, ctx, ctx.PIDExpiry)
		},
	})

	Register(&Config{
		ID:          PIDMDocID,
		Format:      "mso_mdoc",
		DocType:     "eu.europa.ec.eudi.pid.1",
		DisplayName: "PID (mdoc)",
		Description: "Person Identification Data - ISO 18013-5 CBOR",
		Claims:      pidSDJWTClaims,
		Metadata: func() openid4vci.CredentialConfiguration {
			return openid4vci.CredentialConfiguration{
				Format:                               "mso_mdoc",
				DocType:                              "eu.europa.ec.eudi.pid.1",
				CryptographicBindingMethodsSupported: []string{"jwk"},
				CredentialSigningAlgValuesSupported:  []string{"ES256"},
				ProofTypesSupported: map[string]openid4vci.ProofTypeSupport{
					"jwt": {
						ProofSigningAlgValuesSupported: []string{"ES256"},
						KeyAttestationsRequired: map[string][]string{
							"key_storage": {"iso_18045_high"},
						},
					},
				},
				Claims: pidSDJWTClaims,
				Display: []openid4vci.CredentialDisplay{
					{Name: "PID", Description: "Person Identification Data (mdoc)", Locale: "en"},
				},
			}
		},
		Issue: func(result *ProofResult, ctx *IssuanceContext) (string, error) {
			claims := buildPIDClaims(result.UserData, ctx)
			return MintMDoc("eu.europa.ec.eudi.pid.1", claims, result, ctx, ctx.PIDExpiry)
		},
	})
}

// buildPIDClaims extracts PID claim values from userData, using ctx for fallbacks.
// issuing_country falls back to ctx.Country; issuing_authority falls back to ctx.IssuingAuthority.
func buildPIDClaims(userData map[string]any, ctx *IssuanceContext) map[string]any {
	get := func(key string) string {
		if v, ok := userData[key]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}

		return ""
	}

	issuingCountry := get("issuing_country")
	if issuingCountry == "" {
		issuingCountry = ctx.Country
	}

	claims := map[string]any{
		"family_name":     get("family_name"),
		"given_name":      get("given_name"),
		"issuing_country": issuingCountry,
	}

	if pan := get("personal_administrative_number"); pan != "" {
		claims["personal_administrative_number"] = pan
	}

	issuingAuthority := get("issuing_authority")
	if issuingAuthority == "" {
		issuingAuthority = ctx.IssuingAuthority
	}

	if issuingAuthority != "" {
		claims["issuing_authority"] = issuingAuthority
	}

	// issuance_date: use provided value or fall back to today.
	if id := get("issuance_date"); id != "" {
		claims["issuance_date"] = id
	} else {
		claims["issuance_date"] = time.Now().UTC().Format("2006-01-02")
	}

	// expiry_date may arrive as "expiry_date" or "estimated_expiry_date" from api-wallet.
	// If neither is present, fall back to today + PIDExpiry (matching old issuer behaviour).
	if ed := get("expiry_date"); ed != "" {
		claims["expiry_date"] = ed
	} else if ed := get("estimated_expiry_date"); ed != "" {
		claims["expiry_date"] = ed
	} else if ctx.PIDExpiry > 0 {
		claims["expiry_date"] = time.Now().UTC().Add(ctx.PIDExpiry).Format("2006-01-02")
	}

	return claims
}
