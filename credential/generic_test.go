// SPDX-License-Identifier: EUPL-1.2

package credential

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/digimaks/api-issuer/openid4vci"

	"github.com/go-quicktest/qt"
)

func TestRegisterGenericFromMetadata(t *testing.T) {
	pidIssueCalled := false

	Register(&Config{
		ID:     "test-pid_vc_sd_jwt",
		Format: "dc+sd-jwt",
		VCT:    "urn:test:pid",
		Issue: func(*ProofResult, *IssuanceContext) (string, error) {
			pidIssueCalled = true

			return "", nil
		},
	})

	t.Cleanup(func() {
		delete(Registry, "test-pid_vc_sd_jwt")
		delete(Registry, "TestCustom_vc+sd-jwt")
	})

	RegisterGenericFromMetadata(map[string]openid4vci.CredentialConfiguration{
		"test-pid_vc_sd_jwt": {Format: "dc+sd-jwt", VCT: "urn:should:not:override"},
		"TestCustom_vc+sd-jwt": {
			Format: "dc+sd-jwt",
			VCT:    "TestCustom",
			CredentialMetadata: &openid4vci.CredentialMetadata{
				Display: []openid4vci.CredentialMetadataDisplay{{Name: "Test Custom", Locale: "en"}},
			},
		},
		"TestMdoc_mdoc": {Format: "mso_mdoc", DocType: "test.mdoc"},
	})

	// mdoc entries are never auto-registered.
	_, hasMdoc := Registry["TestMdoc_mdoc"]
	qt.Check(t, qt.IsFalse(hasMdoc))

	// code-registered types win: original Issue func kept.
	_, _ = Registry["test-pid_vc_sd_jwt"].Issue(nil, nil)
	qt.Check(t, qt.IsTrue(pidIssueCalled))
	qt.Check(t, qt.Equals(Registry["test-pid_vc_sd_jwt"].VCT, "urn:test:pid"))

	custom := Registry["TestCustom_vc+sd-jwt"]
	qt.Assert(t, qt.IsNotNil(custom))
	qt.Check(t, qt.Equals(custom.VCT, "TestCustom"))
	qt.Check(t, qt.Equals(custom.DocType, "TestCustom"))
	qt.Check(t, qt.Equals(custom.DisplayName, "Test Custom"))
	qt.Check(t, qt.Equals(custom.Metadata().VCT, "TestCustom"))
}

func TestRegisterGenericFromMetadata_VCTFallsBackToID(t *testing.T) {
	t.Cleanup(func() { delete(Registry, "NoVCT_vc+sd-jwt") })

	RegisterGenericFromMetadata(map[string]openid4vci.CredentialConfiguration{
		"NoVCT_vc+sd-jwt": {Format: "dc+sd-jwt"},
	})

	qt.Assert(t, qt.IsNotNil(Registry["NoVCT_vc+sd-jwt"]))
	qt.Check(t, qt.Equals(Registry["NoVCT_vc+sd-jwt"].VCT, "NoVCT_vc+sd-jwt"))
}

func TestGenericSDJWTIssue_ClaimsPassThrough(t *testing.T) {
	issue := genericSDJWTIssue("TestCustom")

	result := &ProofResult{
		HolderJWK: map[string]string{"kty": "EC", "crv": "P-256", "x": "eA", "y": "eQ"},
		UserData: map[string]any{
			"name":         "Anna",
			"company_info": map[string]any{"euid": "DE-HRB-123456", "name": "Example GmbH"},
			// reserved / internal keys must not become claims
			"sub":        "session-123",
			"scope":      "whatever",
			"active":     true,
			"status":     map[string]any{"idx": 1},
			"session_id": "s1",
		},
	}

	token, err := issue(result, testIssuanceContext(t))
	qt.Assert(t, qt.IsNil(err))

	names := disclosureClaimNames(t, token)
	qt.Check(t, qt.IsTrue(names["name"]))
	qt.Check(t, qt.IsTrue(names["company_info"]))
	qt.Check(t, qt.IsFalse(names["sub"]))
	qt.Check(t, qt.IsFalse(names["scope"]))
	qt.Check(t, qt.IsFalse(names["active"]))
	qt.Check(t, qt.IsFalse(names["session_id"]))
	qt.Check(t, qt.IsFalse(names["status"]))
}

// testIssuanceContext returns an IssuanceContext with a fresh EC signing key.
func testIssuanceContext(t *testing.T) *IssuanceContext {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))

	return &IssuanceContext{
		PublicURL:     "https://issuer.example.com",
		CredentialTTL: time.Hour,
		SigningKeyFunc: func() (any, string, error) {
			return key, "test-kid", nil
		},
	}
}

// disclosureClaimNames decodes every disclosure of an SD-JWT serialization
// and returns the set of disclosed claim names.
func disclosureClaimNames(t *testing.T, token string) map[string]bool {
	t.Helper()

	parts := strings.Split(token, "~")
	qt.Assert(t, qt.IsTrue(len(parts) > 1))

	names := map[string]bool{}

	for _, d := range parts[1:] {
		if d == "" {
			continue
		}

		raw, err := base64.RawURLEncoding.DecodeString(d)
		qt.Assert(t, qt.IsNil(err))

		var disclosure []any
		qt.Assert(t, qt.IsNil(json.Unmarshal(raw, &disclosure)))
		qt.Assert(t, qt.IsTrue(len(disclosure) >= 3))

		name, _ := disclosure[1].(string)
		names[name] = true
	}

	return names
}
