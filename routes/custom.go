// SPDX-License-Identifier: EUPL-1.2

package routes

import (
	issuer "github.com/digimaks/api-issuer"

	"azugo.io/azugo"
)

// registerCustomRoutes registers endpoints that are not part of the OID4VCI
// spec — infra/health checks and proprietary portal endpoints.
func registerCustomRoutes(a *issuer.App, r *router) {
	// Health check
	a.Get("/healthz", r.healthz)

	// Credential offer management
	a.Post("/generate_credential_offer", r.generateCredentialOffer)
}

// healthz returns 200 OK for health checks.
func (r *router) healthz(ctx *azugo.Context) {
	ctx.SkipRequestLog()
	ctx.StatusCode(200)
}
