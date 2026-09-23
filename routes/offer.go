// SPDX-License-Identifier: EUPL-1.2

package routes

import (
	"encoding/json"
	"net/url"
	"slices"
	"strings"

	"azugo.io/azugo"
	"github.com/digimaks/api-issuer/idauth"
	"github.com/digimaks/api-issuer/routes/request"
	"github.com/digimaks/api-issuer/routes/response"
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"
	"github.com/oklog/ulid/v2"
	"go.uber.org/zap"
)

// @operationId generateCredentialOffer
// @title Generate credential offer
// @description Creates a credential offer and returns the wallet deep-link. Supports pre-authorized_code and/or authorization_code grants. Defaults to pre-authorized_code when grantTypes is empty.
// @success 200 GenerateCredentialOfferResponse response.GenerateCredentialOfferResponse "Credential offer response"
// @failure 400 string string "Bad request"
// @failure 422 string string "Invalid grant type"
// @failure 500 string string "Internal server error"
// @resource CredentialOffer
// @route /generate_credential_offer [post].
func (r *router) generateCredentialOffer(ctx *azugo.Context) {
	var req request.GenerateCredentialOfferRequest
	if err := ctx.Body.JSON(&req); err != nil {
		ctx.Error(pkerrors.NewProblem("err:offer:invalidRequestBody", pkerrors.WithDetail(err.Error())))

		return
	}

	if len(req.CredentialIDs) == 0 {
		ctx.Error(pkerrors.NewProblem("err:offer:credentialIDsRequired"))

		return
	}

	if err := ctx.Validate().Var(req.GrantTypes, "omitempty,dive,oneof=urn:ietf:params:oauth:grant-type:pre-authorized_code authorization_code"); err != nil {
		ctx.Error(err)

		return
	}

	grantTypes := req.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{"urn:ietf:params:oauth:grant-type:pre-authorized_code"}
	}

	grants := map[string]any{}
	txCode := 0

	if slices.Contains(grantTypes, "urn:ietf:params:oauth:grant-type:pre-authorized_code") {
		scope := strings.Join(req.CredentialIDs, " ")

		sessionID := req.SessionID

		var givenName, familyName string

		if req.Form != nil {
			if sessionID == "" {
				if pan, ok := req.Form["personal_administrative_number"].(string); ok {
					sessionID = pan
				}
			}

			givenName, _ = req.Form["given_name"].(string)
			familyName, _ = req.Form["family_name"].(string)
		}

		preauthResp, err := r.IDAuth().GeneratePreauth(ctx, idauth.PreauthRequest{
			Scope:      scope,
			SessionID:  sessionID,
			GivenName:  givenName,
			FamilyName: familyName,
			NoTXCode:   r.Config().OpenID4VCI.TXCodeDisabled,
		})
		if err != nil {
			ctx.Log().Error("failed to generate preauth code", zap.Error(err))
			ctx.Error(pkerrors.NewProblem("err:offer:preauthGenerationFailed"))

			return
		}

		// Cache under IDAuth's authoritative session id (echoes the caller's
		// hint when one was sent, IDAuth-generated otherwise) — /credential
		// looks the form up by introspection.Sub, which equals this value.
		if len(req.Form) > 0 && preauthResp.SessionID != "" {
			if err := r.OpenID4VCI().AddFormData(ctx, preauthResp.SessionID, req.Form); err != nil {
				ctx.Log().Error("failed to store offer form data", zap.Error(err))
				ctx.Error(pkerrors.NewProblem("err:offer:formDataStoreFailed"))

				return
			}
		}

		preauthGrant := map[string]any{
			"pre-authorized_code": preauthResp.PreauthCode,
		}

		// tx_code_disabled offers omit the tx_code requirement entirely —
		// idauth was told not to store one, so /token accepts the code bare.
		if !r.Config().OpenID4VCI.TXCodeDisabled {
			preauthGrant["tx_code"] = map[string]any{
				"length":      5,
				"input_mode":  "numeric",
				"description": "Please enter the 5-digit transaction code",
			}
			txCode = preauthResp.TXCode
		}

		grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"] = preauthGrant
	}

	if slices.Contains(grantTypes, "authorization_code") {
		grants["authorization_code"] = map[string]any{
			"issuer_state": ulid.Make().String(),
		}
	}

	offerObject := map[string]any{
		"credential_issuer":            r.Config().PublicURL,
		"credential_configuration_ids": req.CredentialIDs,
		"grants":                       grants,
	}

	offerJSON, err := json.Marshal(offerObject)
	if err != nil {
		ctx.Log().Error("failed to marshal credential offer", zap.Error(err))
		ctx.Error(pkerrors.NewProblem("err:offer:offerMarshalFailed"))

		return
	}

	deepLink := "haip-vci://?credential_offer=" + url.QueryEscape(string(offerJSON))

	ctx.JSON(response.GenerateCredentialOfferResponse{
		TXCode:  txCode,
		URLData: deepLink,
	})
}
