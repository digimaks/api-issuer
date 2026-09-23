// SPDX-License-Identifier: EUPL-1.2

package routes

import (
	"time"

	"azugo.io/azugo"
	"github.com/digimaks/api-issuer/routes/response"
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"
	"go.uber.org/zap"
)

// @operationId nonce
// @title Issue c_nonce
// @description Issues a fresh c_nonce value for holder-binding proof construction. Unauthenticated; the nonce itself is proof-bound.
// @success 200 NonceResponse response.NonceResponse "Nonce response"
// @failure 500 string string "Internal server error"
// @resource Credential
// @route /nonce [post].
func (r *router) nonce(ctx *azugo.Context) {
	nonce, err := r.OpenID4VCI().Nonce(ctx)
	if err != nil {
		ctx.Log().Error("failed to mint nonce", zap.Error(err))
		ctx.Error(pkerrors.NewProblem("err:nonce:mintFailed"))

		return
	}

	nonceTTL := r.Config().OpenID4VCI.NonceTTL
	if nonceTTL == 0 {
		nonceTTL = 10 * time.Minute
	}

	ctx.Header.Set("Cache-Control", "no-store")

	ctx.JSON(response.NonceResponse{
		CNonce:    nonce,
		ExpiresIn: int(nonceTTL.Seconds()),
	})
}
