// SPDX-License-Identifier: EUPL-1.2

package openid4vci

import (
	"encoding/base64"

	"aidanwoods.dev/go-paseto"
	"azugo.io/azugo"
	"azugo.io/core/cache"
)

// Service is the central OpenID4VCI service providing nonce and WUA session management.
type Service struct {
	app    *azugo.App
	config *Configuration

	// PASETO nonce support
	nonceKey   paseto.V4SymmetricKey
	nonceCache cache.Instance[bool]

	wuaCache  cache.Instance[*WUASession]
	formCache cache.Instance[map[string]any]
}

// New creates a new OpenID4VCI service.
func New(app *azugo.App, config *Configuration) (*Service, error) {
	b, err := base64.StdEncoding.DecodeString(config.NonceSharedSecret)
	if err != nil {
		return nil, err
	}

	key, err := paseto.V4SymmetricKeyFromBytes(b)
	if err != nil {
		return nil, err
	}

	nonceCache, err := cache.Create[bool](app.Cache(), "issuer-nonce-reuse", cache.DefaultTTL(config.NonceTTL))
	if err != nil {
		return nil, err
	}

	wuaCache, err := cache.Create[*WUASession](app.Cache(), "issuer-wua-session", cache.DefaultTTL(config.NonceTTL))
	if err != nil {
		return nil, err
	}

	formCache, err := cache.Create[map[string]any](app.Cache(), "issuer-form-data", cache.DefaultTTL(config.NonceTTL))
	if err != nil {
		return nil, err
	}

	return &Service{
		app:        app,
		config:     config,
		nonceKey:   key,
		nonceCache: nonceCache,
		wuaCache:   wuaCache,
		formCache:  formCache,
	}, nil
}

// Config returns the service configuration.
func (s *Service) Config() *Configuration {
	return s.config
}
