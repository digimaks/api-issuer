// SPDX-License-Identifier: EUPL-1.2

// Package idauth provides a minimal HTTP client for the IDAuth authorization service.
// It exposes only the operations required by the credential issuer:
//   - POST /preauth_generate  - create a pre-authorized code + tx_code bound to a session
//   - POST /introspection     - validate a bearer token and retrieve session claims
package idauth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"

	"azugo.io/azugo"
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"
	"github.com/gmb-lib/go-platform-kit/httpclient"
	"github.com/valyala/fasthttp"
)

// Client is the IDAuth API client.
type Client struct {
	config             *Configuration
	preauthEndpoint    string
	introspectEndpoint string
}

// NewClient creates a new IDAuth client.
func NewClient(config *Configuration) (*Client, error) {
	preauthEndpoint, err := url.JoinPath(config.URL, "preauth_generate")
	if err != nil {
		return nil, fmt.Errorf("idauth: invalid preauth endpoint: %w", err)
	}

	introspectEndpoint, err := url.JoinPath(config.URL, "introspection")
	if err != nil {
		return nil, fmt.Errorf("idauth: invalid introspect endpoint: %w", err)
	}

	return &Client{
		config:             config,
		preauthEndpoint:    preauthEndpoint,
		introspectEndpoint: introspectEndpoint,
	}, nil
}

// PreauthRequest is the body sent to IDAuth POST /preauth_generate.
type PreauthRequest struct {
	// Scope is the space-separated list of credential_configuration_ids.
	Scope string

	// SessionID is an optional hint for the IDAuth session (e.g. personal_administrative_number).
	SessionID string

	// GivenName, if known, is stored on the session IDAuth creates for the
	// resulting pre-authorized_code, so a later /introspection call can
	// return it (used e.g. to populate holder_given_name/holder_family_name
	// when tracking credential issuance).
	GivenName string

	// FamilyName, if known, is stored on the session the same way as GivenName.
	FamilyName string

	// NoTXCode asks IDAuth to issue the pre-authorized_code without a
	// transaction code (test/dev offers — see openid4vci config tx_code_disabled).
	NoTXCode bool
}

// PreauthResponse is the response from IDAuth POST /preauth_generate.
type PreauthResponse struct {
	// SessionID is the IDAuth session identifier.
	SessionID string `json:"session_id"`

	// PreauthCode is the pre-authorized_code to embed in the credential offer.
	PreauthCode string `json:"preauth_code"`

	// TXCode is the numeric TX code the holder must supply at /token.
	TXCode int `json:"tx_code"`
}

// GeneratePreauth calls IDAuth to create a pre-authorized code and TX code.
func (c *Client) GeneratePreauth(ctx *azugo.Context, req PreauthRequest) (*PreauthResponse, error) {
	formData := map[string][]string{
		"scope":       {req.Scope},
		"session_id":  {req.SessionID},
		"client_id":   {c.config.ClientID},
		"given_name":  {req.GivenName},
		"family_name": {req.FamilyName},
	}

	if req.NoTXCode {
		formData["no_tx_code"] = []string{"true"}
	}

	body, err := c.postForm(ctx, c.preauthEndpoint, formData, nil)
	if err != nil {
		return nil, fmt.Errorf("idauth preauth_generate: %w", err)
	}

	var resp PreauthResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("idauth preauth_generate: invalid response: %w", err)
	}

	return &resp, nil
}

// Confirmation carries the RFC 9449 confirmation claim for DPoP-bound tokens.
type Confirmation struct {
	JKT string `json:"jkt"`
}

// IntrospectionResponse is the response from IDAuth POST /introspection.
type IntrospectionResponse struct {
	// Active indicates whether the token is currently valid.
	Active bool `json:"active"`

	// Sub is the subject (user identifier).
	Sub string `json:"sub"`

	// Scope is the space-separated token scopes.
	Scope string `json:"scope"`

	// Username is the authenticated user's username.
	Username string `json:"username"`

	// Exp is the expiry as a Unix timestamp.
	Exp int64 `json:"exp"`

	// TokenType is "DPoP" for sender-constrained tokens, else "Bearer".
	TokenType string `json:"token_type,omitempty"`

	// Cnf carries the RFC 9449 confirmation claim for DPoP-bound tokens.
	Cnf *Confirmation `json:"cnf,omitempty"`

	// State is the IDAuth session state (e.g. "authorized").
	State string `json:"state"`

	// Claims contains raw session claims for mapping to credential attributes.
	Claims map[string]any `json:"claims,omitempty"`
}

// Introspect validates a bearer token via IDAuth and returns session info.
func (c *Client) Introspect(ctx *azugo.Context, bearerToken string) (*IntrospectionResponse, error) {
	formData := map[string][]string{
		"token":     {bearerToken},
		"client_id": {c.config.ClientID},
	}

	basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(c.config.ClientID+":"+c.config.ClientSecret))

	body, err := c.postForm(ctx, c.introspectEndpoint, formData, map[string]string{"Authorization": basicAuth})
	if err != nil {
		return nil, fmt.Errorf("idauth introspect: %w", err)
	}

	var resp IntrospectionResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("idauth introspect: invalid response: %w", err)
	}

	return &resp, nil
}

// postForm POSTs form-encoded data to endpoint, propagating the request's
// correlation id and, on a non-2xx response, decoding a downstream
// go-platform-kit Problem body so the returned error carries idauth's code
// and trace_id instead of collapsing the failure into an opaque status code.
// headers overrides the default per-request headers (e.g. Authorization) —
// pass nil to keep the default Bearer client-secret header.
func (c *Client) postForm(ctx *azugo.Context, endpoint string, form map[string][]string, headers map[string]string) ([]byte, error) {
	client := ctx.HTTPClient().WithBaseURL(endpoint)

	req := client.NewRequest()
	defer client.ReleaseRequest(req)

	if err := req.SetRequestURL(""); err != nil {
		return nil, err
	}

	req.Header.SetMethod(fasthttp.MethodPost)
	req.Header.SetContentType("application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+c.config.ClientSecret)

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	httpclient.SetCorrelationHeaders(ctx, &req.Header)

	req.PostArgs().Reset()

	for k, vs := range form {
		for _, v := range vs {
			req.PostArgs().Add(k, v)
		}
	}

	resp := client.NewResponse()
	defer client.ReleaseResponse(resp)

	if err := client.Do(req, resp); err != nil {
		return nil, fmt.Errorf("call failed: %w", err)
	}

	body, err := resp.BodyUncompressed()
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if !resp.Success() {
		if down, ok := pkerrors.ParseProblem(body); ok {
			return nil, fmt.Errorf("request failed: %s (code=%s, trace_id=%s)", down.Title, down.Code, down.TraceID)
		}

		return nil, fmt.Errorf("unexpected response status %d", resp.StatusCode())
	}

	return body, nil
}
