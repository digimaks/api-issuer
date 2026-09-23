// SPDX-License-Identifier: EUPL-1.2

package routes

import (
	"context"
	"net/url"
	"strings"
	"time"

	issuer "github.com/digimaks/api-issuer"
	"github.com/digimaks/api-issuer/dpop"
	"github.com/digimaks/api-issuer/openapi"
	oa "github.com/lx-lib/go-openapi"

	"azugo.io/core/cache"
)

type router struct {
	*issuer.App
	openapi *oa.OpenAPI
}

// Init registers all HTTP routes on the application.
func Init(a *issuer.App) error {
	r := &router{App: a}

	r.openapi = oa.NewDefaultOpenAPIHandler(openapi.OpenAPIDefinition, a.App)

	registerCustomRoutes(a, r)

	// OpenID4VCI well-known endpoints
	a.Get("/.well-known/openid-credential-issuer", r.openIDCredentialIssuer)
	a.Get("/.well-known/openid-configuration", r.openIDConfiguration)

	// Nonce endpoint - unauthenticated; nonce itself is proof-bound
	a.Post("/nonce", r.nonce)

	jtiCache, err := cache.Create[bool](a.Cache(), "dpop-jti", cache.DefaultTTL(5*time.Minute))
	if err != nil {
		return err
	}

	jtiCacheGet := func(ctx context.Context, key string) (bool, error) { return jtiCache.Get(ctx, key) }
	jtiCacheSet := func(ctx context.Context, key string) error { return jtiCache.Set(ctx, key, true) }

	dpopValidator := dpop.NewValidator(dpop.Config{
		ExtraHTUs: buildExtraHTUs(append([]string{
			a.Config().PublicURL + "/credential",
		}, a.Config().DPoPAcceptedHTU...)),
		PublicURL: a.Config().PublicURL,
		ReplayCheck: func(ctx context.Context, jti string) (bool, error) {
			seen, err := jtiCacheGet(ctx, jti)
			if err != nil {
				return false, nil //nolint:nilerr // fail-open on cache errors
			}

			if seen {
				return true, nil
			}

			return false, jtiCacheSet(ctx, jti)
		},
	})

	// Credential issuance — requires bearer token
	credGroup := a.Group("")
	credGroup.Use(issuer.BearerAuthenticate(a, dpopValidator))
	credGroup.Post("/credential", r.credential)

	return nil
}

// buildExtraHTUs groups external proxy HTUs by local endpoint path derived
// from each URL's last path segment (e.g. ".../wallet/credential" → "/credential").
// This supports RFC 9449 §4.3 forwarded-proof scenarios where the client's DPoP
// proof htu contains the proxy's public URL rather than the backend's URL.
func buildExtraHTUs(externalHTUs []string) map[string][]string {
	if len(externalHTUs) == 0 {
		return nil
	}

	extra := make(map[string][]string, len(externalHTUs))

	for _, u := range externalHTUs {
		parsed, err := url.Parse(u)
		if err != nil {
			continue
		}

		segments := strings.Split(strings.TrimRight(parsed.Path, "/"), "/")
		localPath := "/" + segments[len(segments)-1]
		extra[localPath] = append(extra[localPath], u)
	}

	return extra
}
