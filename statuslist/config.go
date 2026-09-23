// SPDX-License-Identifier: EUPL-1.2

package statuslist

import (
	corecfg "azugo.io/core/config"
	"azugo.io/core/validation"
	"github.com/spf13/viper"
)

// Config holds connection settings for the IETF Token Status List service.
type Config struct {
	// BaseURL is the base HTTP URL of the status list service, e.g.
	// "http://statuslist:8080/token_status_list". The client appends "/take" or "/set".
	BaseURL string `mapstructure:"base_url" validate:"required,url"`

	// APIKey is the secret passed as the X-API-Key request header.
	APIKey string `mapstructure:"api_key" validate:"required"`

	// CountryCode is the ISO 3166-1 alpha-2 country code sent with every /take request.
	CountryCode string `mapstructure:"country_code" validate:"required,len=2"`
}

// Bind maps environment variables and defaults to viper keys under the given prefix.
func (c *Config) Bind(prefix string, v *viper.Viper) {
	apiKey, _ := corecfg.LoadRemoteSecret("STATUS_LIST_API_KEY")
	v.SetDefault(prefix+".api_key", apiKey)
	v.SetDefault(prefix+".country_code", "LV")

	_ = v.BindEnv(prefix+".base_url", "STATUS_LIST_API_URL")
	_ = v.BindEnv(prefix+".api_key", "STATUS_LIST_API_KEY")
	_ = v.BindEnv(prefix+".country_code", "STATUS_LIST_COUNTRY_CODE")
}

// Validate checks that all required fields are set.
func (c *Config) Validate(valid *validation.Validate) error {
	return valid.Struct(c)
}
