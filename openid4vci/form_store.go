// SPDX-License-Identifier: EUPL-1.2

package openid4vci

import "azugo.io/azugo"

// AddFormData stores credential offer form data keyed by session ID.
func (s *Service) AddFormData(ctx *azugo.Context, sessionID string, data map[string]any) error {
	return s.formCache.Set(ctx, sessionID, data)
}

// GetFormData returns offer form data for the given session ID.
func (s *Service) GetFormData(ctx *azugo.Context, sessionID string) (map[string]any, bool) {
	v, _ := s.formCache.Get(ctx, sessionID)
	return v, v != nil
}
