// SPDX-License-Identifier: EUPL-1.2

package openid4vci

import (
	"errors"
	"strings"
	"time"

	"aidanwoods.dev/go-paseto"
	"azugo.io/azugo"
	"azugo.io/core/cache"
	"github.com/oklog/ulid/v2"
	"go.uber.org/zap"
)

var errInvalidNonce = errors.New("invalid nonce")

// Nonce mints a fresh c_nonce as a PASETO v4 local token and registers it in
// the cache so ValidateNonce can Pop it atomically (one-time use, race-free).
// The "v4.local." prefix is stripped - only the payload is returned.
func (s *Service) Nonce(ctx *azugo.Context) (string, error) {
	now := time.Now().UTC()

	t := paseto.NewToken()
	t.SetIssuer(s.config.PublicURL)
	t.SetIssuedAt(now)
	t.SetNotBefore(now)
	t.SetExpiration(now.Add(s.config.NonceTTL))
	t.SetSubject(ulid.Make().String())

	encrypted := strings.TrimPrefix(t.V4Encrypt(s.nonceKey, nil), "v4.local.")

	id, err := t.GetSubject()
	if err != nil {
		return "", err
	}

	if err := s.nonceCache.Set(ctx, id, true, cache.TTL[bool](s.config.NonceTTL)); err != nil {
		return "", err
	}

	return encrypted, nil
}

// ValidateNonce verifies a c_nonce and atomically consumes it to prevent replay.
// Returns the nonce subject ID on success.
func (s *Service) ValidateNonce(ctx *azugo.Context, nonce string) (string, error) {
	now := time.Now().UTC()

	parser := paseto.NewParser()
	parser.AddRule(paseto.IssuedBy(s.config.PublicURL))
	parser.AddRule(paseto.ValidAt(now))

	t, err := parser.ParseV4Local(s.nonceKey, "v4.local."+nonce, nil)
	if err != nil {
		return "", errInvalidNonce
	}

	id, err := t.GetSubject()
	if err != nil {
		return "", errInvalidNonce
	}

	if _, err := s.nonceCache.Pop(ctx, id); err != nil {
		ctx.Log().Warn("nonce invalid or already used", zap.String("nonce", id), zap.Error(err))

		return "", errInvalidNonce
	}

	return id, nil
}
