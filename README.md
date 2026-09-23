# api-issuer

Go OpenID4VCI credential issuer service.  
Issues PID credentials in **SD-JWT-VC** and **mso_mdoc** formats via the pre-authorized code flow.

Licensed under [EUPL-1.2](#license).

## Built with Azugo Go Web Framework

This project is built using the [Azugo Go Web Framework](https://azugo.io), a powerful and flexible framework for building modern web applications in Go. Check out the [Azugo GitHub page](https://github.com/azugo) for more information and documentation.

<!-- TOC -->

- [Development](#development)
  - [Prepare dependencies](#prepare-dependencies)
  - [Local development](#local-development)
  - [Before commit](#before-commit)
- [Environment variables](#environment-variables)
  - [Required](#required)
  - [Optional / have defaults](#optional--have-defaults)
- [Generating the signing key](#generating-the-signing-key)
- [HTTP routes](#http-routes)
- [Build & run in Docker](#build--run-in-docker)
- [License](#license)

<!-- /TOC -->

## Development

### Prepare dependencies

```sh
go mod download
go generate ./...
```

### Local development

To build in VS Code use `Ctrl`+`Shift`+`B`.

To debug project in VS Code use `F5`.

### Before commit

> CI requires linted, formatted code

You should run:

```sh
gofmt -s -w ./..
```

or

```sh
gofumpt -w ./..
```

and fix any errors reported by

```sh
golangci-lint run
```

## Environment variables

### Required

| Variable | Description |
|---|---|
| `ISSUER_PUBLIC_URL` | Public HTTPS base URL of this service (e.g. `https://issuer.example.com`) |
| `ISSUER_NONCE_SHARED_SECRET` | Base64-encoded 32-byte PASETO v4 symmetric key — generate with `openssl rand -base64 32` |
| `ISSUER_CERTIFICATE` | PEM bundle containing the EC signing certificate **and** private key (concatenated); the key may be unencrypted or PKCS#8-encrypted (see `ISSUER_CERTIFICATE_PASSWORD`) |
| `POSTGRES_HOST` | Postgres server hostname (used for the `attestation_provider` issuance-tracking store) |
| `POSTGRES_PORT` | Postgres server port (default `5432`) |
| `POSTGRES_USER` | Postgres role used to connect |
| `POSTGRES_PASSWORD` | Postgres role password |
| `POSTGRES_DB` | Postgres database name |
| `IDAUTH_URL` | Internal base URL of the IDAuth service (e.g. `http://idauth:8080`) |
| `IDAUTH_CLIENT_ID` | OAuth2 client ID registered in IDAuth |
| `IDAUTH_CLIENT_SECRET` | OAuth2 client secret registered in IDAuth |
| `STATUS_LIST_API_URL` | Base HTTP URL of the status list service (e.g. `http://statuslist:8080/token_status_list`) |
| `STATUS_LIST_API_KEY` | Secret passed as `X-API-Key` header to the status list service |

### Optional / have defaults

| Variable | Default | Description |
|---|---|---|
| `ISSUER_CERTIFICATE_PASSWORD` | _(empty)_ | Password to decrypt the private key when it is PKCS#8-encrypted; not required for plain unencrypted keys |
| `ISSUER_NONCE_TYPE` | `paseto` | Nonce implementation: `paseto` or `jwe` |
| `ISSUER_NONCE_TTL` | `10m` | How long a minted c_nonce is valid |
| `ISSUER_CREDENTIAL_TTL` | `24h` | Validity period embedded in issued credentials |
| `ISSUER_PID_EXPIRY` | `24h` | Technical validity period of PID credentials |
| `ISSUER_PROOF_MAX_AGE` | `5m` | Maximum allowed age of a proof JWT's `iat` claim (replay protection) |
| `ISSUER_AUTHORIZATION_SERVER_URL` | _(same as `ISSUER_PUBLIC_URL`)_ | Public OAuth 2.0 Authorization Server URL advertised in issuer metadata — set when the token endpoint is on a separate host |
| `ISSUER_NAME` | `EUDIW PID Issuer` | Human-readable issuer name shown in credential displays |
| `ISSUER_COUNTRY` | `LV` | Two-letter ISO country code of the issuing authority |
| `ISSUER_ISSUING_AUTHORITY` | `SIA Dativa` | Human-readable issuing authority name embedded in PIDs — used as fallback when the credential data does not supply `issuing_authority` |
| `ISSUER_TRUST_LIST_URI` | _(empty)_ | URL of the national Trusted List (LoTE) entry for this issuer — when set, published as `trust_list_uri` in issuer metadata (ARF ISSU) |
| `ISSUER_METADATA_PATH` | _(embedded default)_ | Filesystem path to an `issuer_metadata.json` override — when set, replaces the binary's embedded copy without a rebuild |
| `ISSUER_API_URL` | _(alias for `ISSUER_PUBLIC_URL`)_ | Backward-compat alias accepted by api-wallet-digimaks |
| `ISSUER_DPOP_ACCEPTED_HTU` | _(empty)_ | Space-separated list of extra `htu` URL values accepted in DPoP proofs — add the wallet-facing proxy URL(s) that forward `/credential` to this service (e.g. `https://api-wallet.example.com/credential https://api-wallet.example.com/revoke`). The service's own `ISSUER_PUBLIC_URL/credential` and `.../revoke` are always accepted automatically. |
| `ISSUER_TRUSTED_WALLET_PROVIDER_ROOTS` | _(empty)_ | PEM bundle of CA certificates trusted as Wallet Provider roots — an empty value trusts none (fails closed). TS3 (Wallet Unit Attestation spec, v1.5+) dropped the WUA `iss` claim; `ValidateWUA` now verifies the `x5c` header's certificate chain against this Trusted List instead of matching an `iss` URL. Supports the `_FILE` suffix convention (`ISSUER_TRUSTED_WALLET_PROVIDER_ROOTS_FILE`) to load from a mounted file. |
| `ISSUER_WUA_VERIFICATION_ENFORCED` | `false` | When `true`, a failed WUA/key-attestation cryptographic verification (typ, x5c chain of trust, signature, `key_storage` level, revocation status) rejects the request. When `false` (default), a failure is logged only — enable once wallet providers' JWKS publish `use:"sig"` keys. |
| `ISSUER_TX_CODE_DISABLED` | `false` | **Test/dev only.** When `true`, pre-authorized offers are generated without a transaction code: the offer grant omits the `tx_code` object and IDAuth is told (`no_tx_code`) not to store one, so the token call succeeds without it. The tx_code is the user-binding factor of the pre-authorized flow — never enable in production. |
| `STATUS_LIST_COUNTRY_CODE` | `LV` | ISO 3166-1 alpha-2 country code sent with every status list `/take` request |
| `POSTGRES_SSLMODE` | `prefer` | Postgres SSL mode (`disable`, `allow`, `prefer`, `require`, `verify-ca`, `verify-full`) |
| `POSTGRES_POOL_MIN_CONNS` / `POSTGRES_POOL_MAX_CONNS` | `0` / `10` | Connection pool size bounds |
| `POSTGRES_POOL_LIFE_TIME` / `POSTGRES_POOL_IDLE_TIME` | `1h` / `30m` | Maximum connection lifetime / idle time |

Duration values accept Go duration strings (`10m`, `1h`, `30s`).

---

## Generating the signing key

The signing key must be an EC P-256 certificate. Generate a self-signed one for development:

```sh
openssl ecparam -genkey -name prime256v1 -noout -out issuer-key.pem
openssl req -new -x509 -key issuer-key.pem -out issuer-cert.pem -days 3650 \
  -subj "/CN=EUDIW PID Issuer/C=LV"

# Combine into a single PEM bundle for ISSUER_CERTIFICATE:
cat issuer-cert.pem issuer-key.pem > issuer-bundle.pem
export ISSUER_CERTIFICATE="$(cat issuer-bundle.pem)"
```

---

## HTTP routes

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/healthz` | — | Health check |
| `GET` | `/.well-known/openid-credential-issuer` | — | OpenID4VCI issuer metadata |
| `GET` | `/.well-known/openid-configuration` | — | Alias of above |
| `POST` | `/nonce` | — | Fresh c_nonce |
| `POST` | `/credential` | Bearer | Issue a credential |
| `POST` | `/generate_credential_offer` | — | Create credential offer + TX code (called by wallet API) |
| `POST` | `/wua/token` | — | Wallet Unit Attestation token endpoint |
| `POST` | `/revoke` | — | Revoke a credential by holder key ID |
| `GET` | `/status` | — | List all revoked entries |
| `GET` | `/credentials/status/1` | — | W3C BitstringStatusListCredential |

---

## Build & run in Docker

```sh
go build -o publish/server ./cmd/server
docker build -t issuer-go .
docker run --rm \
  -e ISSUER_PUBLIC_URL=https://issuer.example.com \
  -e ISSUER_NONCE_SHARED_SECRET="$(openssl rand -base64 32)" \
  -e ISSUER_CERTIFICATE="$(cat issuer-bundle.pem)" \
  -e IDAUTH_URL=http://idauth:8080 \
  -e IDAUTH_CLIENT_ID=issuer \
  -e IDAUTH_CLIENT_SECRET=secret \
  -e POSTGRES_HOST=postgres \
  -e POSTGRES_USER=issuer \
  -e POSTGRES_PASSWORD=secret \
  -e POSTGRES_DB=issuer \
  -p 8080:8080 issuer-go
```

---

## License

EUPL-1.2 — see [LICENSE](./LICENSE).
