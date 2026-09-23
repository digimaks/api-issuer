// SPDX-License-Identifier: EUPL-1.2

package routes

import (
	"errors"
	"time"

	"azugo.io/azugo"
	"github.com/digimaks/api-issuer/credential"
	"github.com/digimaks/api-issuer/idauth"
	"github.com/digimaks/api-issuer/openid4vci"
	"github.com/digimaks/api-issuer/routes/request"
	"github.com/digimaks/api-issuer/routes/response"
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"
	"go.uber.org/zap"
)

// @operationId credential
// @title Issue credential
// @description Issues a verifiable credential for the authenticated holder. Accepts holder-binding proofs in OID4VCI draft-14 map format, array-of-objects format, or legacy singular proof. Requires a Bearer access token.
// @param Authorization header string true "Bearer access token"
// @success 200 CredentialResponse response.CredentialResponse "Issued credentials"
// @failure 400 string string "Bad request"
// @failure 401 string string "Unauthorized"
// @failure 500 string string "Internal server error"
// @resource Credential
// @route /credential [post].
func (r *router) credential(ctx *azugo.Context) {
	// Retrieve the access token from context (set by BearerAuthenticate middleware).
	bearerToken, _ := ctx.UserValue("bearer_token").(string)
	if bearerToken == "" {
		ctx.Log().Warn("credential request: bearer token not in context (middleware bug)")
		ctx.Error(pkerrors.NewProblem("err:credential:missingBearerToken"))

		return
	}

	// Get credential request
	var req request.CredentialRequest
	if err := ctx.Body.JSON(&req); err != nil {
		ctx.Log().Warn("credential request: body parse failed", zap.Error(err))
		ctx.Error(pkerrors.NewProblem("err:credential:invalidRequestBody"))

		return
	}

	// Collect all proof JWTs: parsed proofs array takes precedence over singular proof.
	var proofJWTs []string
	if len(req.ProofJWTs) > 0 {
		proofJWTs = req.ProofJWTs
	} else if req.Proof.ProofType == "jwt" && req.Proof.JWT != "" {
		proofJWTs = []string{req.Proof.JWT}
	}

	ctx.Log().Info(
		"credential request parsed",
		zap.String("credential_configuration_id", req.CredentialConfigurationID),
		zap.Int("proof_jwts", len(req.ProofJWTs)),
		zap.String("singular_proof_type", req.Proof.ProofType),
		zap.Int("total_proofs", len(proofJWTs)),
	)

	if len(proofJWTs) == 0 {
		ctx.Log().Warn(
			"credential request: no proof JWTs provided",
			zap.String("credential_configuration_id", req.CredentialConfigurationID),
			zap.String("proof_type", req.Proof.ProofType),
		)
		ctx.Error(pkerrors.NewProblem("err:credential:proofTypeUnsupported",
			pkerrors.WithDetail("only proof_type=jwt is supported")))

		return
	}

	// Determine the c_nonce and session information.
	// WUA path: token was registered by POST /wua/token
	var (
		cNonce    string
		sessionID string
		userData  map[string]any
	)

	if wuaSession, ok := ctx.UserValue("wua_session").(*openid4vci.WUASession); ok {
		// WUA session - nonce from PASETO endpoint, session from WUA payload
		if sid, ok := wuaSession.Payload["session_id"].(string); ok {
			sessionID = sid
		}

		userData = wuaSession.Payload

		// Mint a fresh nonce for proof validation (WUA flow uses server-generated nonce)
		n, err := r.OpenID4VCI().Nonce(ctx)
		if err != nil {
			ctx.Log().Error("failed to mint nonce for WUA credential request", zap.Error(err))
			ctx.Error(pkerrors.NewProblem("err:credential:nonceMintFailed"))

			return
		}

		cNonce = n
	} else {
		// IDAuth-authenticated path: bearer token validated via IDAuth introspection
		// by BearerAuthenticate middleware. Used when api-wallet-digimaks forwards a
		// credential request.
		//
		// The proof nonce and audience reference api-wallet-digimaks (its PASETO key
		// and public URL), so we skip those checks and only verify the ES256 signature
		// for holder binding. All other validation was done upstream.
		introspection, _ := ctx.UserValue("introspection").(*idauth.IntrospectionResponse)
		if introspection == nil {
			ctx.Log().Warn("IDAuth path: no introspection context, token may have expired")
			ctx.Error(pkerrors.NewProblem("err:credential:tokenExpiredOrNotFound",
				pkerrors.WithDetail("token expired or not found")))

			return
		}

		ctx.Log().Info(
			"IDAuth path: credential request",
			zap.String("credential_configuration_id", req.CredentialConfigurationID),
			zap.Int("proof_jwts", len(proofJWTs)),
		)

		credConfig, ok := credential.Registry[req.CredentialConfigurationID]
		if !ok {
			ctx.Log().Error(
				"IDAuth path: unknown credential_configuration_id",
				zap.String("id", req.CredentialConfigurationID),
				zap.Any("registered", func() []string {
					keys := make([]string, 0, len(credential.Registry))
					for k := range credential.Registry {
						keys = append(keys, k)
					}

					return keys
				}()),
			)
			ctx.Error(pkerrors.NewProblem("err:credential:configurationUnsupported",
				pkerrors.WithDetail("unknown credential_configuration_id")))

			return
		}

		userData := introspection.Claims
		if userData == nil {
			userData = map[string]any{"sub": introspection.Sub}
		}

		// Merge offer form data (contains birth_date, issuing_country, etc.) into
		// userData.
		if storedForm, ok := r.OpenID4VCI().GetFormData(ctx, introspection.Sub); ok {
			merged := make(map[string]any, len(userData)+len(storedForm))
			for k, v := range userData {
				merged[k] = v
			}

			for k, v := range storedForm {
				merged[k] = v
			}

			userData = merged
		}

		var proofResults []*credential.ProofResult

		for _, jwt := range proofJWTs {
			// Phase 3: verify any embedded key-attestation (WUA) signature before
			// trusting its attested keys. Flag-gated — see validateProofKeyAttestation.
			if err := r.validateProofKeyAttestation(ctx, jwt); err != nil {
				ctx.Log().Warn("IDAuth path: proof key-attestation verification failed", zap.Error(err))
				ctx.Error(pkerrors.NewProblem("err:credential:keyAttestationInvalid"))

				return
			}

			// VerifyProofSignatureAll returns one result per attested key when
			// the proof carries a WUA with multiple attested_keys (Android batch flow).
			prs, err := credential.VerifyProofSignatureAll(jwt)
			if err != nil {
				ctx.Log().Error("IDAuth path: VerifyProofSignature failed", zap.Error(err))
				ctx.Error(pkerrors.NewProblem("err:credential:proofInvalid"))

				return
			}

			for _, pr := range prs {
				pr.SessionID = introspection.Sub
				pr.UserData = userData
				proofResults = append(proofResults, pr)
			}
		}

		// ARF §6.6.2.3 draws no distinction by grant type for hardware key
		// attestation — a device-bound credential needs it uniformly. Reject
		// the whole request rather than partially issue if any proof lacks
		// attestation the credential config's own metadata requires.
		if credentialConfigRequiresKeyAttestation(credConfig) {
			for _, pr := range proofResults {
				if !pr.KeyAttestationVerified {
					ctx.Log().Warn(
						"IDAuth path: proof missing required key_attestation",
						zap.String("credential_configuration_id", req.CredentialConfigurationID),
					)
					ctx.Error(pkerrors.NewProblem("err:credential:keyAttestationRequired",
						pkerrors.WithDetail("this credential type requires a hardware key attestation on the proof")))

					return
				}
			}
		}

		r.issueAndRespond(ctx, credConfig, proofResults, time.Time{}, "")

		return
	}

	// Find the credential config
	credConfig, ok := credential.Registry[req.CredentialConfigurationID]
	if !ok {
		ctx.Log().Error(
			"WUA path: unknown credential_configuration_id",
			zap.String("id", req.CredentialConfigurationID),
			zap.Any("registered", func() []string {
				keys := make([]string, 0, len(credential.Registry))
				for k := range credential.Registry {
					keys = append(keys, k)
				}

				return keys
			}()),
		)
		ctx.Error(pkerrors.NewProblem("err:credential:configurationUnsupported",
			pkerrors.WithDetail("unknown credential_configuration_id")))

		return
	}

	// Verify all proof JWTs
	var proofResults []*credential.ProofResult

	for i, jwt := range proofJWTs {
		// Phase 3: verify any embedded key-attestation (WUA) signature before
		// trusting its attested keys. Flag-gated — see validateProofKeyAttestation.
		if err := r.validateProofKeyAttestation(ctx, jwt); err != nil {
			ctx.Log().Warn("WUA path: proof key-attestation verification failed", zap.Int("proof_index", i), zap.Error(err))
			ctx.Error(pkerrors.NewProblem("err:credential:keyAttestationInvalid"))

			return
		}

		pr, err := credential.VerifyProof(jwt, cNonce, r.Config().PublicURL, r.Config().OpenID4VCI.ProofMaxAge)
		if err != nil {
			ctx.Log().Warn(
				"WUA path: proof JWT verification failed",
				zap.Int("proof_index", i),
				zap.Int("total_proofs", len(proofJWTs)),
				zap.Error(err),
			)
			ctx.Error(pkerrors.NewProblem("err:credential:proofInvalid"))

			return
		}

		pr.SessionID = sessionID
		pr.UserData = userData
		proofResults = append(proofResults, pr)
	}

	// ARF §6.6.2.3.3: cap PID expiry to the WUA assertion's exp if present.
	// wallet_provider is sourced from the same assertion's iss claim, per the
	// issuance-separation plan (empty on the IDAuth-forwarded path, which has
	// no reliable wallet-provider signal at this layer).
	var (
		attestationExp time.Time
		walletProvider string
	)

	if wuaSession, ok := ctx.UserValue("wua_session").(*openid4vci.WUASession); ok {
		if assertion, ok := wuaSession.Payload["assertion"].(string); ok {
			attestationExp = credential.ExtractJWTExp(assertion)
			walletProvider = credential.ExtractJWTIssuer(assertion)
		}
	}

	r.issueAndRespond(ctx, credConfig, proofResults, attestationExp, walletProvider)
}

// issueAndRespond signs and returns one credential per proof.
// notAfter, when non-zero, caps the credential expiry to that time (ARF §6.6.2.3.3: PID SHALL
// end before WIA/KA exp). walletProvider identifies the wallet instance that requested
// issuance (WUA assertion iss claim on the WUA path, empty on the IDAuth-forwarded path).
func (r *router) issueAndRespond(
	ctx *azugo.Context,
	credConfig *credential.Config,
	proofResults []*credential.ProofResult,
	notAfter time.Time,
	walletProvider string,
) {
	signingKeyFunc := func() (any, string, error) {
		cert, err := r.Config().OpenID4VCI.SigningCertificate()
		if err != nil {
			return nil, "", err
		}

		kid, err := r.OpenID4VCI().SigningCertificateKID()
		if err != nil {
			return nil, "", err
		}

		return cert.PrivateKey, kid, nil
	}

	x5c, err := r.OpenID4VCI().SigningCertificateX5C()
	if err != nil {
		ctx.Log().Error("failed to load signing certificate x5c", zap.Error(err))
		ctx.Error(pkerrors.NewProblem("err:credential:signingCertUnavailable"))

		return
	}

	credExpiry := time.Now().Add(r.Config().OpenID4VCI.PIDExpiry)
	if !notAfter.IsZero() && notAfter.Before(credExpiry) {
		credExpiry = notAfter
	}

	ctx.Log().Info(
		"issuing credentials",
		zap.String("credential_type", credConfig.DocType),
		zap.Int("proof_count", len(proofResults)),
		zap.Time("expiry", credExpiry),
	)

	// DoctypeVct records the mdoc doctype or SD-JWT-VC vct — whichever this
	// credential config defines (PID configs currently set DocType on both
	// formats, so this prefers VCT for the SD-JWT-VC config only).
	doctypeVct := credConfig.VCT
	if doctypeVct == "" {
		doctypeVct = credConfig.DocType
	}

	issuedAt := time.Now()

	var credentials []response.CredentialEntry

	for _, proofResult := range proofResults {
		// Allocate a revocation slot per credential.
		slot, err := r.StatusList().Take(ctx, credConfig.DocType, credExpiry)
		if err != nil {
			ctx.Log().Error("statuslist take failed", zap.Error(err))
			ctx.Error(pkerrors.NewProblem("err:credential:slotAllocationFailed",
				pkerrors.WithDetail("could not allocate revocation slot")))

			return
		}

		issuanceCtx := &credential.IssuanceContext{
			PublicURL:        r.Config().PublicURL,
			Country:          r.Config().OpenID4VCI.IssuerCountry,
			IssuingAuthority: r.Config().OpenID4VCI.IssuingAuthority,
			SigningKeyFunc:   signingKeyFunc,
			X5C:              x5c,
			StatusListIdx:    slot.StatusList.Idx,
			StatusListURI:    slot.StatusList.URI,
			CredentialTTL:    r.Config().OpenID4VCI.CredentialTTL,
			PIDExpiry:        r.Config().OpenID4VCI.PIDExpiry,
		}

		credentialValue, err := credConfig.Issue(proofResult, issuanceCtx)
		if err != nil {
			ctx.Log().Error("credential issuance failed", zap.Error(err))
			ctx.Error(pkerrors.NewProblem(classifyMintError(err)))

			return
		}

		credentialID, err := openid4vci.RecordCredentialIssuance(ctx, r.Store(), openid4vci.RecordCredentialIssuanceParams{
			CredentialIdentifier: credConfig.ID,
			Format:               credConfig.Format,
			DoctypeVct:           doctypeVct,
			IssuedAt:             issuedAt,
			ExpiresAt:            credExpiry,
			HolderIdentifier:     stringUserData(proofResult.UserData, "personal_administrative_number"),
			HolderGivenName:      stringUserData(proofResult.UserData, "given_name"),
			HolderFamilyName:     stringUserData(proofResult.UserData, "family_name"),
			WalletProvider:       walletProvider,
			StatusListSlots: []openid4vci.StatusList{
				{URI: slot.StatusList.URI, Idx: slot.StatusList.Idx},
			},
			HardwareKeyTag: proofResult.HardwareKeyTag,
		})
		if err != nil {
			// Issuance tracking is best-effort: the credential itself is already
			// minted and must still be returned to the caller.
			ctx.Log().Error("record credential issuance failed", zap.Error(err))
		}

		credentials = append(credentials, response.CredentialEntry{
			Credential:    credentialValue,
			Format:        credConfig.Format,
			ExpiresAt:     credExpiry.UTC().Format(time.RFC3339),
			StatusListURI: slot.StatusList.URI,
			StatusListIdx: slot.StatusList.Idx,
			CredentialID:  credentialID,
		})
	}

	ctx.Header.Set("Cache-Control", "no-store")

	credentialResponse := response.CredentialResponse{
		Credentials: credentials,
	}

	if len(credentials) > 0 && credentials[0].CredentialID != "" {
		credentialResponse.CredentialID = credentials[0].CredentialID
		ctx.Header.Set("Credential-ID", credentials[0].CredentialID)
	}

	ctx.JSON(credentialResponse)
}

// validateProofKeyAttestation extracts any key-attestation (WUA) JWT embedded
// in proofJWT and cryptographically verifies it via ValidateWUA (Phase 3:
// signature, key_storage level, revocation status — see
// docs/plans/issuance-separation-plan.md). Returns nil when the proof carries
// no key attestation at all (nothing to verify at this layer).
//
// Flag-gated: while OpenID4VCI.WUAVerificationEnforced is false (default), a
// failed verification is logged only and nil is returned, since wallet-api's
// JWKS today publishes use:"enc" keys rather than use:"sig" — enforcing here
// would reject legitimate attestations until that upstream fix ships.
func (r *router) validateProofKeyAttestation(ctx *azugo.Context, proofJWT string) error {
	ka, err := credential.ExtractKeyAttestation(proofJWT)
	if err != nil || ka == "" {
		return nil
	}

	verr := r.OpenID4VCI().ValidateWUA(ctx, ka)
	if verr == nil {
		return nil
	}

	if r.Config().OpenID4VCI.WUAVerificationEnforced {
		return verr
	}

	ctx.Log().Warn("proof key-attestation failed cryptographic verification (not enforced)", zap.Error(verr))

	return nil
}

// stringUserData returns userData[key] as a string, or "" if absent or not a string.
func stringUserData(userData map[string]any, key string) string {
	s, _ := userData[key].(string)

	return s
}

// credentialConfigRequiresKeyAttestation reports whether cfg's OpenID4VCI
// metadata declares key_attestations_required on the "jwt" proof type.
// Per-config, not global — a credential type that omits this from its
// metadata is unaffected by the enforcement in the IDAuth path above.
func credentialConfigRequiresKeyAttestation(cfg *credential.Config) bool {
	jwtProof, ok := cfg.Metadata().ProofTypesSupported["jwt"]
	if !ok {
		return false
	}

	return len(jwtProof.KeyAttestationsRequired) > 0
}

// sentinel (see credential/errors.go), to a fine-grained err:mint:* code.
// Falls back to the generic credential code for any error that doesn't match
// a known sentinel (e.g. an error from a future minting path not yet
// classified here).
func classifyMintError(err error) string {
	switch {
	case errors.Is(err, credential.ErrSigningKeyLoadFailed):
		return "err:mint:signingKeyLoadFailed"
	case errors.Is(err, credential.ErrSigningKeyInvalidType):
		return "err:mint:signingKeyInvalidType"
	case errors.Is(err, credential.ErrJWTPartMarshalFailed):
		return "err:mint:sdjwtPartMarshalFailed"
	case errors.Is(err, credential.ErrMDocNonceGenerationFailed):
		return "err:mint:mdocNonceGenerationFailed"
	case errors.Is(err, credential.ErrMDocClaimEncodingFailed):
		return "err:mint:mdocClaimEncodingFailed"
	case errors.Is(err, credential.ErrMDocMSOBuildFailed):
		return "err:mint:mdocMSOBuildFailed"
	case errors.Is(err, credential.ErrMDocCertDecodeFailed):
		return "err:mint:mdocCertDecodeFailed"
	case errors.Is(err, credential.ErrMDocCOSEStructureFailed):
		return "err:mint:mdocCOSEStructureFailed"
	case errors.Is(err, credential.ErrMDocDocumentEncodingFailed):
		return "err:mint:mdocDocumentEncodingFailed"
	case errors.Is(err, credential.ErrSignatureComputationFailed):
		return "err:mint:signatureComputationFailed"
	default:
		return "err:credential:issuanceMintFailed"
	}
}
