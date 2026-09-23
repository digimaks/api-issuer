// SPDX-License-Identifier: EUPL-1.2

package credential

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/go-quicktest/qt"
)

func TestMintSDJWT_SigningKeyLoadFailure(t *testing.T) {
	ctx := &IssuanceContext{
		SigningKeyFunc: func() (any, string, error) {
			return nil, "", errors.New("vault unavailable")
		},
	}

	_, err := MintSDJWT("urn:test:vct", map[string]any{}, &ProofResult{}, ctx, time.Hour)

	qt.Assert(t, qt.ErrorIs(err, ErrSigningKeyLoadFailed))
}

func TestMintSDJWT_SigningKeyWrongType(t *testing.T) {
	ctx := &IssuanceContext{
		SigningKeyFunc: func() (any, string, error) {
			return "not-an-ecdsa-key", "kid", nil
		},
	}

	_, err := MintSDJWT("urn:test:vct", map[string]any{}, &ProofResult{}, ctx, time.Hour)

	qt.Assert(t, qt.ErrorIs(err, ErrSigningKeyInvalidType))
}

func TestMintMDoc_SigningKeyLoadFailure(t *testing.T) {
	ctx := &IssuanceContext{
		SigningKeyFunc: func() (any, string, error) {
			return nil, "", errors.New("vault unavailable")
		},
	}

	_, err := MintMDoc("test_doc_type", map[string]any{}, &ProofResult{HolderJWK: map[string]string{}}, ctx, time.Hour)

	qt.Assert(t, qt.ErrorIs(err, ErrSigningKeyLoadFailed))
}

func TestMintMDoc_CertDecodeFailure(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))

	issuanceCtx := &IssuanceContext{
		SigningKeyFunc: func() (any, string, error) {
			return ecKey, "kid", nil
		},
		X5C: []string{"not-valid-base64!!!"},
	}

	_, err = MintMDoc("test_doc_type", map[string]any{}, &ProofResult{HolderJWK: map[string]string{"x": "", "y": ""}}, issuanceCtx, time.Hour)

	qt.Assert(t, qt.ErrorIs(err, ErrMDocCertDecodeFailed))
}
