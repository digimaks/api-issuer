// SPDX-License-Identifier: EUPL-1.2

package openid4vci

import (
	"time"

	"azugo.io/azugo"
)

// WUASession holds the session data registered by POST /wua/token.
// The bearer token that the wallet presents at POST /credential is used
// as the map key so the credential handler can bypass IDAuth introspection.
type WUASession struct {
	Payload      map[string]any
	RegisteredAt time.Time
}

// AddWUASession registers a WUA session keyed by bearer token.
func (s *Service) AddWUASession(ctx *azugo.Context, bearerToken string, payload map[string]any) error {
	return s.wuaCache.Set(ctx, bearerToken, &WUASession{
		Payload:      payload,
		RegisteredAt: time.Now(),
	})
}

// GetWUASession returns the WUA session for the given bearer token if it exists.
func (s *Service) GetWUASession(ctx *azugo.Context, bearerToken string) (*WUASession, bool) {
	v, _ := s.wuaCache.Get(ctx, bearerToken)
	return v, v != nil
}

// DeleteWUASession removes a WUA session.
func (s *Service) DeleteWUASession(ctx *azugo.Context, bearerToken string) error {
	return s.wuaCache.Delete(ctx, bearerToken)
}
