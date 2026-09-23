// SPDX-License-Identifier: EUPL-1.2

//go:generate go run generator/generate.go

// @version 1.0
// @title Auth API
// @description OpenID4VCI credential issuer API for the DigiMaks EUDIW wallet stack. Implements OID4VCI 1.0 Final (pre-authorized code flow) and ARF v2.9.0 PID issuance.
// @contactName SIA Dativa
// @contactEmail digimaks@dativa.lv
// @contactURL https://www.digimaks.lv/
// @server {{SERVER_URL}}
// @security AuthorizationHeader
// @securityScheme AuthorizationHeader http bearer Bearer access token issued by the authorization server. Example: "Authorization: Bearer {access-token}"
package openapi

import (
	_ "embed"
)

//go:embed openapi.json
var OpenAPIDefinition []byte
