// SPDX-License-Identifier: EUPL-1.2

package idauth

import (
	corecfg "azugo.io/core/config"
	"azugo.io/core/validation"
	"github.com/spf13/viper"
)

// Configuration holds IDAuth connection settings.
type Configuration struct {
	// URL is the internal base URL of the IDAuth service.
	URL string `mapstructure:"url" validate:"required,url"`

	// ClientID is the OAuth2 client ID used when calling IDAuth endpoints.
	ClientID string `mapstructure:"client_id" validate:"required"`

	// ClientSecret is the OAuth2 client secret.
	ClientSecret string `mapstructure:"client_secret" validate:"required"`
}

// Bind maps environment variables to viper keys.
func (c *Configuration) Bind(prefix string, v *viper.Viper) {
	clientSecret, _ := corecfg.LoadRemoteSecret("IDAUTH_CLIENT_SECRET")
	v.SetDefault(prefix+".client_secret", clientSecret)

	_ = v.BindEnv(prefix+".url", "IDAUTH_URL")
	_ = v.BindEnv(prefix+".client_id", "IDAUTH_CLIENT_ID")
	_ = v.BindEnv(prefix+".client_secret", "IDAUTH_CLIENT_SECRET")
}

// Validate validates the configuration values.
func (c *Configuration) Validate(valid *validation.Validate) error {
	return valid.Struct(c)
}
