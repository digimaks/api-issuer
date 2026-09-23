// SPDX-License-Identifier: EUPL-1.2

// Package issuer registers issuer-go's error taxonomy reasons - the
// credential and mint domains' fine-grained failure codes - with
// go-platform-kit so pkerrors.NewProblem derives status and title without
// WithStatus at every call site (see routes/credential.go).
package issuer

import (
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"

	"github.com/valyala/fasthttp"
)

func init() {
	pkerrors.RegisterReason("missingBearerToken", pkerrors.ReasonSpec{Status: fasthttp.StatusUnauthorized, Title: "Missing bearer token"})
	pkerrors.RegisterReason("invalidRequestBody", pkerrors.ReasonSpec{Status: fasthttp.StatusBadRequest, Title: "Invalid request body"})
	pkerrors.RegisterReason("proofTypeUnsupported", pkerrors.ReasonSpec{Status: fasthttp.StatusBadRequest, Title: "Unsupported proof type"})
	pkerrors.RegisterReason("nonceMintFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("tokenExpiredOrNotFound", pkerrors.ReasonSpec{Status: fasthttp.StatusUnauthorized, Title: "Token expired or not found"})
	pkerrors.RegisterReason("configurationUnsupported", pkerrors.ReasonSpec{Status: fasthttp.StatusBadRequest, Title: "Unsupported credential configuration"})
	pkerrors.RegisterReason("proofInvalid", pkerrors.ReasonSpec{Status: fasthttp.StatusBadRequest, Title: "Invalid proof"})
	pkerrors.RegisterReason("keyAttestationRequired", pkerrors.ReasonSpec{Status: fasthttp.StatusBadRequest, Title: "Hardware key attestation required"})
	pkerrors.RegisterReason("keyAttestationInvalid", pkerrors.ReasonSpec{Status: fasthttp.StatusBadRequest, Title: "Invalid key attestation"})
	pkerrors.RegisterReason("signingCertUnavailable", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("slotAllocationFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("issuanceMintFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("signingKeyLoadFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("signingKeyInvalidType", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("sdjwtPartMarshalFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("mdocNonceGenerationFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("mdocClaimEncodingFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("mdocMSOBuildFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("mdocCertDecodeFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("mdocCOSEStructureFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("mdocDocumentEncodingFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("signatureComputationFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})

	// Nonce, revocation, credential-offer, and WUA-token domains.
	pkerrors.RegisterReason("mintFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("slotUpdateFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("credentialIDsRequired", pkerrors.ReasonSpec{Status: fasthttp.StatusBadRequest, Title: "credentialIds is required"})
	pkerrors.RegisterReason("preauthGenerationFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("formDataStoreFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("offerMarshalFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("grantTypeUnsupported", pkerrors.ReasonSpec{Status: fasthttp.StatusBadRequest, Title: "Unsupported grant type"})
	pkerrors.RegisterReason("assertionRequired", pkerrors.ReasonSpec{Status: fasthttp.StatusBadRequest, Title: "Missing assertion"})
	pkerrors.RegisterReason("signedAccessTokenRequired", pkerrors.ReasonSpec{Status: fasthttp.StatusBadRequest, Title: "Missing signed access token"})
	pkerrors.RegisterReason("authHeaderInvalid", pkerrors.ReasonSpec{Status: fasthttp.StatusBadRequest, Title: "Invalid authorization header"})
	pkerrors.RegisterReason("assertionExpired", pkerrors.ReasonSpec{Status: fasthttp.StatusBadRequest, Title: "Assertion expired"})
	pkerrors.RegisterReason("verificationFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusBadRequest, Title: "WUA verification failed"})
	pkerrors.RegisterReason("sessionRegistrationFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusInternalServerError, Title: "Internal server error"})
	pkerrors.RegisterReason("introspectionFailed", pkerrors.ReasonSpec{Status: fasthttp.StatusUnauthorized, Title: "Unauthorized"})
}
