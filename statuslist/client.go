// SPDX-License-Identifier: EUPL-1.2

// Package statuslist provides a client for the IETF Token Status List service
// (unknovs/status-list-go). It is used to allocate revocation slots at credential
// issuance time and to set the revocation status when a credential is revoked.
package statuslist

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"azugo.io/azugo"
	"azugo.io/core/http"
	"github.com/gmb-lib/go-platform-kit/httpclient"
)

// takeSlot is the nested status_list object inside a TakeResponse.
type takeSlot struct {
	URI string `json:"uri"`
	Idx int    `json:"idx"`
}

// TakeResponse is the response returned by the /take endpoint.
// The service returns {"status_list": {"uri": "...", "idx": N}, ...}.
type TakeResponse struct {
	StatusList takeSlot `json:"status_list"`
}

// Client calls the IETF Token Status List HTTP service.
type Client struct {
	cfg *Config
}

// NewClient creates a new status list client.
func NewClient(cfg *Config) *Client {
	return &Client{
		cfg: cfg,
	}
}

// Take allocates a new revocation slot for the given doctype and returns the
// status list URI and the assigned bit index. The caller embeds these values
// into the issued credential's status claim. expiry is the credential expiry date.
func (c *Client) Take(ctx *azugo.Context, doctype string, expiry time.Time) (*TakeResponse, error) {
	client := ctx.HTTPClient().WithBaseURL(c.cfg.BaseURL)

	form := map[string][]string{
		"doctype":     {doctype},
		"country":     {c.cfg.CountryCode},
		"expiry_date": {expiry.UTC().Format("2006-01-02")},
	}

	opts := append([]http.RequestOption{http.WithHeader("X-API-Key", c.cfg.APIKey)}, httpclient.CorrelationOptions(ctx)...)

	body, err := client.PostForm("/take", form, opts...)
	if err != nil {
		return nil, fmt.Errorf("statuslist take: %w", err)
	}

	var result TakeResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("statuslist take: decode response: %w", err)
	}

	if result.StatusList.URI == "" {
		return nil, errors.New("statuslist take: empty uri in response")
	}

	return &result, nil
}

// Set updates the revocation status of the credential at the given URI and index.
// status=1 means revoked; status=0 means valid.
func (c *Client) Set(ctx *azugo.Context, uri string, idx int, status int) error {
	client := ctx.HTTPClient().WithBaseURL(c.cfg.BaseURL)

	body, err := json.Marshal(map[string]any{
		"uri":    uri,
		"idx":    idx,
		"status": status,
	})
	if err != nil {
		return fmt.Errorf("statuslist set: %w", err)
	}

	opts := append([]http.RequestOption{
		http.WithHeader("X-API-Key", c.cfg.APIKey),
		http.WithHeader("Content-Type", "application/json"),
	}, httpclient.CorrelationOptions(ctx)...)

	if _, err := client.Post("/set", body, opts...); err != nil {
		return fmt.Errorf("statuslist set: %w", err)
	}

	return nil
}
