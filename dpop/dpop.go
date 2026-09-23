// SPDX-License-Identifier: EUPL-1.2

// Package dpop validates OAuth 2.0 Demonstrating Proof of Possession
// (RFC 9449) proof JWTs.
package dpop

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const HeaderName = "DPoP"

var (
	ErrInvalidProof = errors.New("dpop: invalid proof")
	ErrReplay       = errors.New("dpop: jti already used")
)

// ReplayChecker reports whether jti was already seen and records it as seen.
type ReplayChecker func(ctx context.Context, jti string) (bool, error)

type Config struct {
	// AcceptedHTUs are exact request URLs (no query/fragment) proofs may be
	// bound to. URLs are grouped by their path component, so a proof bound to
	// one endpoint's URL cannot be replayed at a different endpoint sharing
	// the same Validator.
	AcceptedHTUs []string
	// ExtraHTUs maps local endpoint paths (e.g. "/credential") to additional
	// accepted HTU URLs whose own path component differs — needed when requests
	// are forwarded through a reverse proxy and the client's DPoP proof is
	// bound to the proxy's public URL (RFC 9449 section 4.3).
	ExtraHTUs map[string][]string
	// DynamicHTURoutes are router paths as registered (e.g.
	// "/credential/{id}") that contain path parameters and thus
	// cannot be enumerated in AcceptedHTUs ahead of time. For these routes
	// the accepted htu is computed per-request as PublicURL followed by the
	// literal request path, instead of being matched against a static
	// allowlist — this still enforces RFC 9449's requirement that htu equal
	// the literal target URI, and prevents a proof bound to one resource
	// (e.g. one credential ID) from being replayed against another.
	DynamicHTURoutes []string
	// PublicURL is the externally reachable base URL used together with
	// DynamicHTURoutes to reconstruct the expected htu for a request.
	PublicURL   string
	IATWindow   time.Duration
	ReplayCheck ReplayChecker
}

type Validator struct {
	htus          map[string]map[string]struct{} // router path -> accepted full htu URLs
	dynamicRoutes map[string]struct{}            // router paths validated dynamically against PublicURL+path
	publicURL     string
	iatWindow     time.Duration
	replay        ReplayChecker
}

type proofClaims struct {
	HTM string `json:"htm"`
	HTU string `json:"htu"`
	ATH string `json:"ath"`
	jwt.RegisteredClaims
}

func NewValidator(cfg Config) *Validator {
	htus := make(map[string]map[string]struct{}, len(cfg.AcceptedHTUs))
	for _, u := range cfg.AcceptedHTUs {
		parsed, _ := url.Parse(u)

		if htus[parsed.Path] == nil {
			htus[parsed.Path] = make(map[string]struct{})
		}

		htus[parsed.Path][u] = struct{}{}
	}

	for localPath, urls := range cfg.ExtraHTUs {
		if htus[localPath] == nil {
			htus[localPath] = make(map[string]struct{})
		}

		for _, u := range urls {
			htus[localPath][u] = struct{}{}
		}
	}

	dynamicRoutes := make(map[string]struct{}, len(cfg.DynamicHTURoutes))
	for _, p := range cfg.DynamicHTURoutes {
		dynamicRoutes[p] = struct{}{}
	}

	w := cfg.IATWindow
	if w <= 0 {
		w = time.Minute
	}

	return &Validator{
		htus:          htus,
		dynamicRoutes: dynamicRoutes,
		publicURL:     cfg.PublicURL,
		iatWindow:     w,
		replay:        cfg.ReplayCheck,
	}
}

// Validate checks proof and returns the RFC 7638 thumbprint of the proof key.
// A non-empty accessToken additionally requires a matching ath claim
// (resource-server usage per RFC 9449 section 4.3 step 12). routerPath is
// the route as registered (e.g. "/credential" or "/credential/{id}")
// used to select which accepted-htu rules apply; requestPath is the literal
// incoming request path (e.g. "/credential/abc123") used to
// reconstruct the expected htu for routes registered in DynamicHTURoutes.
func (v *Validator) Validate(ctx context.Context, proof, method, accessToken, routerPath, requestPath string) (string, error) {
	var jkt string

	claims := &proofClaims{}

	_, err := jwt.ParseWithClaims(proof, claims, func(t *jwt.Token) (any, error) {
		if typ, _ := t.Header["typ"].(string); typ != "dpop+jwt" {
			return nil, fmt.Errorf("%w: typ must be dpop+jwt", ErrInvalidProof)
		}

		raw, ok := t.Header["jwk"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%w: missing jwk header", ErrInvalidProof)
		}

		pub, tp, err := parseECJWK(raw)
		if err != nil {
			return nil, err
		}

		jkt = tp

		return pub, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodES256.Name}))
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidProof, err)
	}

	if claims.IssuedAt == nil {
		return "", fmt.Errorf("%w: iat is required", ErrInvalidProof)
	}

	if d := time.Since(claims.IssuedAt.Time); d > v.iatWindow || d < -v.iatWindow {
		return "", fmt.Errorf("%w: iat outside acceptance window", ErrInvalidProof)
	}

	if claims.HTM != method {
		return "", fmt.Errorf("%w: htm mismatch", ErrInvalidProof)
	}

	if _, dynamic := v.dynamicRoutes[routerPath]; dynamic {
		if claims.HTU != v.publicURL+requestPath {
			return "", fmt.Errorf("%w: htu not accepted", ErrInvalidProof)
		}
	} else if _, ok := v.htus[routerPath][claims.HTU]; !ok {
		return "", fmt.Errorf("%w: htu not accepted", ErrInvalidProof)
	}

	if claims.ID == "" {
		return "", fmt.Errorf("%w: jti is required", ErrInvalidProof)
	}

	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		if claims.ATH != base64.RawURLEncoding.EncodeToString(sum[:]) {
			return "", fmt.Errorf("%w: ath mismatch", ErrInvalidProof)
		}
	}

	if v.replay != nil {
		seen, err := v.replay(ctx, claims.ID)
		if err != nil {
			return "", err
		}

		if seen {
			return "", ErrReplay
		}
	}

	return jkt, nil
}
