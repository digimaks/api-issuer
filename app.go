// SPDX-License-Identifier: EUPL-1.2

package issuer

import (
	"time"

	"azugo.io/azugo"
	"azugo.io/azugo/server"
	"azugo.io/opentelemetry"
	"github.com/digimaks/api-issuer/credential"
	"github.com/digimaks/api-issuer/idauth"
	"github.com/digimaks/api-issuer/openid4vci"
	"github.com/digimaks/api-issuer/statuslist"
	kitconfig "github.com/gmb-lib/go-platform-kit/config"
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"
	"github.com/gmb-lib/go-platform-kit/platform"
	"github.com/lx-lib/lx-go-jsondb"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// App is the application instance.
type App struct {
	*azugo.App

	config *Configuration

	store jsondb.Store

	vci        *openid4vci.Service
	idauth     *idauth.Client
	statuslist *statuslist.Client
}

// New returns a new application instance.
func New(cmd *cobra.Command, version string) (*App, error) {
	config := NewConfiguration()

	a, err := server.New(cmd, server.Options{
		AppName:       "EUDIW PID Credential Issuer",
		AppVer:        version,
		Configuration: config,
	})
	if err != nil {
		return nil, err
	}

	store, _, err := jsondb.New(a.App, config.Postgres)
	if err != nil {
		return nil, err
	}

	if err := platform.Setup(a, platform.Options{
		Config: &kitconfig.BaseConfiguration{Telemetry: config.Telemetry},
		TracingOptions: []opentelemetry.Option{
			opentelemetry.InstrumentationRecorder("db", jsondb.Tracing, jsondb.InstrumentationExec),
		},
		PublicErrors: false,
		OnFailure:    auditFailureHook(store),
	}); err != nil {
		return nil, err
	}

	// Custom SD-JWT credential types declared only in issuer_metadata.json
	// get the generic pass-through minter; code-registered types (PID) win.
	credential.RegisterGenericFromMetadata(openid4vci.EmbeddedCredentialConfigurations(config.OpenID4VCI.MetadataPath))

	idauthClient, err := idauth.NewClient(config.IDAuth)
	if err != nil {
		return nil, err
	}

	vci, err := openid4vci.New(a, config.OpenID4VCI)
	if err != nil {
		return nil, err
	}

	sl := statuslist.NewClient(config.StatusList)

	return &App{
		App:        a,
		config:     config,
		store:      store,
		vci:        vci,
		idauth:     idauthClient,
		statuslist: sl,
	}, nil
}

// auditFailureHook persists an audit.failure_events row for every error
// response this service itself originates (see pkerrors.Handler — a relayed
// downstream error does not reach here). Best-effort: a write failure is
// logged and swallowed, never allowed to affect the already-sent response.
func auditFailureHook(store jsondb.Store) pkerrors.FailureHook {
	return func(ctx *azugo.Context, evt pkerrors.FailureEvent) {
		var result struct {
			Success bool `json:"success"`
		}

		err := store.Exec(ctx, "audit.insert_failure_event", &struct {
			Service       string `json:"service"`
			Endpoint      string `json:"endpoint"`
			ErrorMessage  string `json:"error_message"`
			StatusCode    int    `json:"status_code"`
			AppInstanceID string `json:"app_instance_id"`
			OccurredAt    string `json:"occurred_at"`
		}{
			Service:       evt.Service,
			Endpoint:      evt.Endpoint,
			ErrorMessage:  evt.ErrorMessage,
			StatusCode:    evt.StatusCode,
			AppInstanceID: evt.AppInstanceID,
			OccurredAt:    evt.OccurredAt.Format(time.RFC3339),
		}, &result)
		if err != nil {
			ctx.Log().Error("failed to record failure audit event", zap.Error(err))
		}
	}
}

// Start the application.
func (a *App) Start() error {
	if err := a.store.Start(a.BackgroundContext()); err != nil {
		return err
	}

	return a.App.Start()
}

// Panics if configuration is not loaded.
func (a *App) Config() *Configuration {
	if a.config == nil || !a.config.Ready() {
		panic("configuration is not loaded")
	}

	return a.config
}

// Store returns the Postgres-backed data store.
func (a *App) Store() jsondb.Store {
	return a.store
}

// SetStore overrides the data store. Intended for tests that need to inject
// a fake jsondb.Store without contacting a real Postgres instance — normal
// startup always uses the store constructed in New from the app's Postgres
// configuration.
func (a *App) SetStore(store jsondb.Store) {
	a.store = store
}

// OpenID4VCI returns the OpenID4VCI service.
func (a *App) OpenID4VCI() *openid4vci.Service {
	return a.vci
}

// IDAuth returns the IDAuth API client.
func (a *App) IDAuth() *idauth.Client {
	return a.idauth
}

// StatusList returns the IETF Token Status List client.
func (a *App) StatusList() *statuslist.Client {
	return a.statuslist
}
