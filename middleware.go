// SPDX-License-Identifier: EUPL-1.2

package issuer

import (
	"strings"

	"azugo.io/azugo"
	"azugo.io/core/http"
	"github.com/digimaks/api-issuer/dpop"
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

// BearerAuthenticate is middleware that validates the access token (sent
// with the Bearer or DPoP Authorization scheme) against the WUA session
// store first, then falls back to IDAuth introspection.
// DPoP-bound tokens (introspection cnf.jkt) additionally require a valid
// proof per RFC 9449 section 7. On success it sets a synthetic user context
// so handlers can call ctx.User().
func BearerAuthenticate(a *App, dpopValidator *dpop.Validator) azugo.RequestHandlerFunc {
	return func(next azugo.RequestHandler) azugo.RequestHandler {
		return func(ctx *azugo.Context) {
			authHeader := ctx.Header.Get("Authorization")

			scheme, token, found := strings.Cut(authHeader, " ")
			if !found || token == "" {
				ctx.Error(http.UnauthorizedError{})
				return
			}

			isDPoPScheme := strings.EqualFold(scheme, "DPoP")
			if !isDPoPScheme && !strings.EqualFold(scheme, "Bearer") {
				ctx.Error(http.UnauthorizedError{})
				return
			}

			// First check WUA session store (tokens issued by /wua/token bypass IDAuth)
			if session, ok := a.OpenID4VCI().GetWUASession(ctx, token); ok {
				ctx.SetUserValue("wua_session", session)
				ctx.SetUserValue("bearer_token", token)
				next(ctx)

				return
			}

			ctx.Log().Info("Checking access token via IDAuth introspection", zap.Int("length", len(token)))

			// Fall back to IDAuth introspection for standard access tokens
			info, err := a.IDAuth().Introspect(ctx, token)
			if err != nil {
				ctx.Log().Error("bearer token IDAuth introspection failed", zap.Error(err))
				ctx.Error(pkerrors.NewProblem("err:credential:introspectionFailed"))

				return
			}

			if !info.Active {
				ctx.Log().Warn("bearer token inactive per IDAuth introspection")
				ctx.Error(http.UnauthorizedError{})

				return
			}

			if info.Cnf != nil && info.Cnf.JKT != "" {
				proof := ctx.Header.Get(dpop.HeaderName)

				jkt, err := dpopValidator.Validate(ctx, proof, fasthttp.MethodPost, token, ctx.RouterPath(), ctx.Path())
				if !isDPoPScheme || err != nil || jkt != info.Cnf.JKT {
					switch {
					case !isDPoPScheme:
						ctx.Log().Warn("DPoP-bound token presented with Bearer scheme")
					case err != nil:
						ctx.Log().Warn("DPoP proof validation failed", zap.Error(err))
					default:
						ctx.Log().Warn("DPoP proof key does not match token binding")
					}

					ctx.Header.SetAlways("WWW-Authenticate",
						`DPoP error="invalid_token", error_description="DPoP binding validation failed"`)
					ctx.Error(http.UnauthorizedError{})

					return
				}
			}

			ctx.SetUserValue("introspection", info)
			ctx.SetUserValue("bearer_token", token)

			next(ctx)
		}
	}
}
