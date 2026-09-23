// SPDX-License-Identifier: EUPL-1.2

package issuer

import (
	"azugo.io/opentelemetry"
	"github.com/digimaks/api-issuer/idauth"
	"github.com/digimaks/api-issuer/openid4vci"
	"github.com/digimaks/api-issuer/statuslist"
	"github.com/lx-lib/lx-go-jsondb"

	"azugo.io/azugo/config"
	corecfg "azugo.io/core/config"
	"azugo.io/core/validation"
	"github.com/spf13/viper"
)

// Configuration represents the configuration for the application.
type Configuration struct {
	*config.Configuration `mapstructure:",squash"`

	Postgres        *jsondb.Configuration        `mapstructure:"postgres"`
	IDAuth          *idauth.Configuration        `mapstructure:"idauth"`
	OpenID4VCI      *openid4vci.Configuration    `mapstructure:"openid4vci"`
	StatusList      *statuslist.Config           `mapstructure:"status_list"`
	Telemetry       *opentelemetry.Configuration `mapstructure:"telemetry"`
	PublicURL       string                       `mapstructure:"public_url" validate:"required,url"`
	DPoPAcceptedHTU []string                     `mapstructure:"dpop_accepted_htu" validate:"omitempty,dive,url"`
}

// NewConfiguration returns a new configuration.
func NewConfiguration() *Configuration {
	return &Configuration{
		Configuration: config.New(),
	}
}

// ServerCore returns the core server configuration.
func (c *Configuration) ServerCore() *config.Configuration {
	return c.Configuration
}

// Bind configuration to viper.
func (c *Configuration) Bind(_ string, v *viper.Viper) {
	c.Configuration.Bind("", v)

	c.Postgres = config.Bind(c.Postgres, "postgres", v)
	c.IDAuth = config.Bind(c.IDAuth, "idauth", v)
	c.OpenID4VCI = config.Bind(c.OpenID4VCI, "openid4vci", v)
	c.StatusList = config.Bind(c.StatusList, "status_list", v)
	c.Telemetry = config.Bind(c.Telemetry, "telemetry", v)

	_ = v.BindEnv("public_url", "ISSUER_PUBLIC_URL")
	_ = v.BindEnv("dpop_accepted_htu", "ISSUER_DPOP_ACCEPTED_HTU")

	// Allow ISSUER_API_URL as alias for backward compat with api-wallet-digimaks
	if key, _ := corecfg.LoadRemoteSecret("ISSUER_API_URL"); key != "" {
		v.SetDefault("public_url", key)
	}
}

// Validate application configuration.
func (c *Configuration) Validate(validate *validation.Validate) error {
	if err := validate.Struct(c); err != nil {
		return err
	}

	if err := c.Postgres.Validate(validate); err != nil {
		return err
	}

	if err := c.IDAuth.Validate(validate); err != nil {
		return err
	}

	if err := c.OpenID4VCI.Validate(validate); err != nil {
		return err
	}

	if err := c.StatusList.Validate(validate); err != nil {
		return err
	}

	if err := c.Telemetry.Validate(validate); err != nil {
		return err
	}

	return nil
}
