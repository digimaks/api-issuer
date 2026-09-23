// SPDX-License-Identifier: EUPL-1.2

package issuer

import (
	"testing"

	pkerrors "github.com/gmb-lib/go-platform-kit/errors"

	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

func TestErrorsTaxonomy_RegistersAllCredentialAndMintReasons(t *testing.T) {
	cases := []struct {
		code   string
		status int
	}{
		{"err:credential:missingBearerToken", fasthttp.StatusUnauthorized},
		{"err:credential:invalidRequestBody", fasthttp.StatusBadRequest},
		{"err:credential:proofTypeUnsupported", fasthttp.StatusBadRequest},
		{"err:credential:nonceMintFailed", fasthttp.StatusInternalServerError},
		{"err:credential:tokenExpiredOrNotFound", fasthttp.StatusUnauthorized},
		{"err:credential:configurationUnsupported", fasthttp.StatusBadRequest},
		{"err:credential:proofInvalid", fasthttp.StatusBadRequest},
		{"err:credential:signingCertUnavailable", fasthttp.StatusInternalServerError},
		{"err:credential:slotAllocationFailed", fasthttp.StatusInternalServerError},
		{"err:credential:issuanceMintFailed", fasthttp.StatusInternalServerError},
		{"err:mint:signingKeyLoadFailed", fasthttp.StatusInternalServerError},
		{"err:mint:signingKeyInvalidType", fasthttp.StatusInternalServerError},
		{"err:mint:sdjwtPartMarshalFailed", fasthttp.StatusInternalServerError},
		{"err:mint:mdocNonceGenerationFailed", fasthttp.StatusInternalServerError},
		{"err:mint:mdocClaimEncodingFailed", fasthttp.StatusInternalServerError},
		{"err:mint:mdocMSOBuildFailed", fasthttp.StatusInternalServerError},
		{"err:mint:mdocCertDecodeFailed", fasthttp.StatusInternalServerError},
		{"err:mint:mdocCOSEStructureFailed", fasthttp.StatusInternalServerError},
		{"err:mint:mdocDocumentEncodingFailed", fasthttp.StatusInternalServerError},
		{"err:mint:signatureComputationFailed", fasthttp.StatusInternalServerError},
	}

	for _, c := range cases {
		p := pkerrors.NewProblem(c.code)
		qt.Check(t, qt.Equals(p.Status, c.status), qt.Commentf("status for %s", c.code))
	}
}
