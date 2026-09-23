// SPDX-License-Identifier: EUPL-1.2

package routes

import (
	"azugo.io/azugo"
	"github.com/digimaks/api-issuer/openid4vci"
	"go.uber.org/zap"
)

// @operationId openIDCredentialIssuer
// @title OpenID4VCI credential issuer metadata
// @description Returns the OpenID for Verifiable Credential Issuance issuer metadata document, as JSON or, when requested via Accept, as a signed JWT.
// @success 200 {empty} "Issuer metadata"
// @failure 500 string string "Internal server error"
// @resource WellKnown
// @route /.well-known/openid-credential-issuer [get].
func (r *router) openIDCredentialIssuer(ctx *azugo.Context) {
	meta := r.OpenID4VCI().IssuerMeta(ctx, nil)
	ctx.Header.Set("Cache-Control", "no-store")

	token, err := r.OpenID4VCI().SignedIssuerMeta(meta)
	if err != nil {
		ctx.Log().Error("failed to sign issuer metadata", zap.Error(err))
		ctx.StatusCode(500)

		return
	}

	if ctx.AcceptsExplicit(openid4vci.SignedMetadataContentType) || ctx.AcceptsExplicit("application/jwt") {
		ctx.ContentType("application/jwt")
		ctx.Raw([]byte(token))

		return
	}

	// eudi-lib-android-openid4vci and other clients expect the JWT embedded
	// as signed_metadata in the plain JSON document, per OID4VCI §12.2.3.
	meta.SignedMetadata = token
	ctx.JSON(meta)
}

// @operationId openIDConfiguration
// @title OpenID Connect configuration
// @description Returns OAuth 2.0 metadata under the OpenID Connect well-known path.
// @success 200 {empty} "OpenID Connect configuration"
// @resource WellKnown
// @route /.well-known/openid-configuration [get].
func (r *router) openIDConfiguration(ctx *azugo.Context) {
	meta := r.OpenID4VCI().OAuthServerMeta(ctx)
	ctx.JSON(meta)
}
