// SPDX-License-Identifier: EUPL-1.2

package openid4vci

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"time"

	"azugo.io/core/cert"
	corecfg "azugo.io/core/config"
	"azugo.io/core/validation"
	"github.com/spf13/viper"
)

// Configuration holds OpenID4VCI service configuration.
type Configuration struct {
	// Public issuer URL (used in metadata and token payloads).
	PublicURL string `mapstructure:"public_url" validate:"required,url"`

	// NonceType selects the nonce implementation: "paseto" (default) or "jwe".
	NonceType string `mapstructure:"nonce_type" validate:"required,oneof=paseto jwe"`

	// NonceSharedSecret is a Base64-encoded 32-byte PASETO v4 symmetric key.
	// Required when NonceType == "paseto".
	NonceSharedSecret string `mapstructure:"nonce_shared_secret" validate:"required_if=NonceType paseto,omitempty,base64"`

	// NonceTTL is how long a minted nonce remains valid.
	NonceTTL time.Duration `mapstructure:"nonce_ttl" validate:"required,gt=0"`

	// CredentialTTL is the validity period embedded in issued credentials.
	// ARF recommends short-lived credentials (≤24h) for linkability mitigation.
	CredentialTTL time.Duration `mapstructure:"credential_ttl" validate:"required,gt=0"`

	// PIDExpiry is the technical validity of PID credentials.
	// ARF §5.3 requires short-lived PIDs for linkability mitigation; defaults to 24h.
	PIDExpiry time.Duration `mapstructure:"pid_expiry" validate:"required,gt=0"`

	// IssuerCertificate is the PEM bundle (cert + private key) used to sign credentials.
	IssuerCertificate string `mapstructure:"issuer_certificate" validate:"required"`

	// IssuerCertificatePassword is the optional password protecting the private key.
	IssuerCertificatePassword string `mapstructure:"issuer_certificate_password"`

	// ProofMaxAge is the maximum allowed age of a proof JWT's iat claim.
	// OID4VCI §13 recommends a short window to prevent replay; defaults to 5m.
	ProofMaxAge time.Duration `mapstructure:"proof_max_age" validate:"required,gt=0"`

	// AuthorizationServerURL is the public URL of the OAuth 2.0 Authorization Server
	// advertised in issuer metadata (authorization_servers). Defaults to PublicURL.
	// Set to the public idauth URL so wallets discover the correct token endpoint.
	AuthorizationServerURL string `mapstructure:"authorization_server_url" validate:"omitempty,url"`

	// IssuerName is the human-readable name shown in credential displays.
	IssuerName string `mapstructure:"issuer_name"`

	// IssuerCountry is the two-letter ISO country code of the issuing country.
	IssuerCountry string `mapstructure:"issuer_country"`

	// IssuingAuthority is the human-readable name of the authority issuing PIDs.
	// Used as a fallback in credentials when the credential data does not supply issuing_authority.
	IssuingAuthority string `mapstructure:"issuing_authority"`

	// TrustListURI is an optional URL pointing to the national Trusted List (LoTE)
	// entry for this issuer. When set, advertised in issuer metadata as trust_list_uri.
	TrustListURI string `mapstructure:"trust_list_uri" validate:"omitempty,url"`

	// MetadataPath is an optional filesystem path to an issuer_metadata.json
	// override. When unset, falls back to the embedded default.
	MetadataPath string `mapstructure:"metadata_path" validate:"omitempty,file"`

	// TrustedWalletProviderRoots is a PEM bundle of CA certificates that anchor
	// trust for Wallet Unit Attestation (Key Attestation) signing certificates.
	// TS3 (Wallet Unit Attestation spec, v1.5+) dropped the WUA `iss` claim —
	// the Wallet Provider's identity and trust now derive solely from the `x5c`
	// certificate chain, verified against this Trusted List for Wallet Providers.
	TrustedWalletProviderRoots string `mapstructure:"trusted_wallet_provider_roots"`

	// WUAVerificationEnforced gates WUA cryptographic verification. When false
	// (default), ValidateWUA failures are logged but do not reject the request —
	// staged rollout until all wallet providers publish JWKS keys with use:"sig".
	WUAVerificationEnforced bool `mapstructure:"wua_verification_enforced"`

	// TXCodeDisabled generates pre-authorized offers WITHOUT a transaction code
	// (grant omits tx_code; idauth is told not to store one). Test/dev only —
	// tx_code is the user-binding factor of the pre-authorized flow.
	TXCodeDisabled bool `mapstructure:"tx_code_disabled"`

	signingCertificate         *tls.Certificate
	trustedWalletProviderRoots *x509.CertPool
}

// defaultMetadataPath returns the issuer_metadata.json path shipped next to
// the running binary, or "" (falling back to the embedded copy) when it's
// not there — resolving relative to the binary avoids breaking when the
// process is started from a different working directory (e.g. Docker).
func defaultMetadataPath() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}

	path := filepath.Join(filepath.Dir(exe), "openid4vci", "issuer_metadata.json")
	if _, err := os.Stat(path); err != nil {
		return ""
	}

	return path
}

// Bind maps environment variables and defaults to viper keys.
func (c *Configuration) Bind(prefix string, v *viper.Viper) {
	v.SetDefault(prefix+".nonce_type", "paseto")
	v.SetDefault(prefix+".nonce_ttl", 10*time.Minute)
	v.SetDefault(prefix+".credential_ttl", 24*time.Hour)
	v.SetDefault(prefix+".pid_expiry", 24*time.Hour)
	v.SetDefault(prefix+".proof_max_age", 5*time.Minute)
	v.SetDefault(prefix+".issuer_name", "EUDIW PID Issuer")
	v.SetDefault(prefix+".issuer_country", "LV")
	v.SetDefault(prefix+".issuing_authority", "SIA Dativa")
	v.SetDefault(prefix+".wua_verification_enforced", false)
	v.SetDefault(prefix+".tx_code_disabled", false)
	v.SetDefault(prefix+".metadata_path", defaultMetadataPath())

	nonceSecret, _ := corecfg.LoadRemoteSecret("ISSUER_NONCE_SHARED_SECRET")
	v.SetDefault(prefix+".nonce_shared_secret", nonceSecret)

	certificate, _ := corecfg.LoadRemoteSecret("ISSUER_CERTIFICATE")
	v.SetDefault(prefix+".issuer_certificate", certificate)

	password, _ := corecfg.LoadRemoteSecret("ISSUER_CERTIFICATE_PASSWORD")
	v.SetDefault(prefix+".issuer_certificate_password", password)

	_ = v.BindEnv(prefix+".public_url", "ISSUER_PUBLIC_URL")
	_ = v.BindEnv(prefix+".nonce_type", "ISSUER_NONCE_TYPE")
	_ = v.BindEnv(prefix+".nonce_shared_secret", "ISSUER_NONCE_SHARED_SECRET")
	_ = v.BindEnv(prefix+".nonce_ttl", "ISSUER_NONCE_TTL")
	_ = v.BindEnv(prefix+".credential_ttl", "ISSUER_CREDENTIAL_TTL")
	_ = v.BindEnv(prefix+".pid_expiry", "ISSUER_PID_EXPIRY")
	_ = v.BindEnv(prefix+".issuer_certificate", "ISSUER_CERTIFICATE")
	_ = v.BindEnv(prefix+".issuer_certificate_password", "ISSUER_CERTIFICATE_PASSWORD")
	_ = v.BindEnv(prefix+".issuer_name", "ISSUER_NAME")
	_ = v.BindEnv(prefix+".issuer_country", "ISSUER_COUNTRY")
	_ = v.BindEnv(prefix+".authorization_server_url", "ISSUER_AUTHORIZATION_SERVER_URL")
	_ = v.BindEnv(prefix+".proof_max_age", "ISSUER_PROOF_MAX_AGE")
	_ = v.BindEnv(prefix+".issuing_authority", "ISSUER_ISSUING_AUTHORITY")
	_ = v.BindEnv(prefix+".trust_list_uri", "ISSUER_TRUST_LIST_URI")
	_ = v.BindEnv(prefix+".metadata_path", "ISSUER_METADATA_PATH")
	trustedRoots, _ := corecfg.LoadRemoteSecret("ISSUER_TRUSTED_WALLET_PROVIDER_ROOTS")
	v.SetDefault(prefix+".trusted_wallet_provider_roots", trustedRoots)

	_ = v.BindEnv(prefix+".trusted_wallet_provider_roots", "ISSUER_TRUSTED_WALLET_PROVIDER_ROOTS")
	_ = v.BindEnv(prefix+".wua_verification_enforced", "ISSUER_WUA_VERIFICATION_ENFORCED")
	_ = v.BindEnv(prefix+".tx_code_disabled", "ISSUER_TX_CODE_DISABLED")
}

// Validate configuration values.
func (c *Configuration) Validate(valid *validation.Validate) error {
	return valid.Struct(c)
}

// SigningCertificate loads and caches the TLS certificate used for credential signing.
func (c *Configuration) SigningCertificate() (*tls.Certificate, error) {
	if c.signingCertificate != nil {
		return c.signingCertificate, nil
	}

	certbuf, keybuf, err := cert.LoadPEMFromReader(bytes.NewReader([]byte(c.IssuerCertificate)), cert.Password(c.IssuerCertificatePassword))
	if err != nil {
		return nil, err
	}

	tlsCert, err := cert.LoadTLSCertificate(certbuf, keybuf)
	if err != nil {
		return nil, err
	}

	c.signingCertificate = tlsCert

	return c.signingCertificate, nil
}

// TrustedWalletProviderCertPool parses TrustedWalletProviderRoots into a CA
// pool used to verify Wallet Unit Attestation x5c chains. Returns an error
// when unset — deployments must explicitly configure a Trusted List for
// Wallet Providers (fail closed, no implicit trust).
func (c *Configuration) TrustedWalletProviderCertPool() (*x509.CertPool, error) {
	if c.trustedWalletProviderRoots != nil {
		return c.trustedWalletProviderRoots, nil
	}

	if c.TrustedWalletProviderRoots == "" {
		return nil, errors.New("no trusted wallet provider roots configured")
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(c.TrustedWalletProviderRoots)) {
		return nil, errors.New("failed to parse trusted wallet provider roots PEM")
	}

	c.trustedWalletProviderRoots = pool

	return c.trustedWalletProviderRoots, nil
}
