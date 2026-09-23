// SPDX-License-Identifier: EUPL-1.2

package openid4vci

import (
	"slices"
	"testing"

	"github.com/go-quicktest/qt"
)

func TestOAuthServerMeta_AdvertisesRefreshTokenGrant(t *testing.T) {
	s := &Service{config: &Configuration{PublicURL: "https://issuer.example.com"}}

	meta := s.OAuthServerMeta(nil)

	qt.Check(t, qt.IsTrue(slices.Contains(meta.GrantTypesSupported, "refresh_token")))
}

func TestOAuthServerMeta_AdvertisesBothGrantTypes(t *testing.T) {
	s := &Service{config: &Configuration{PublicURL: "https://issuer.example.com"}}

	meta := s.OAuthServerMeta(nil)

	qt.Check(t, qt.IsTrue(slices.Contains(meta.GrantTypesSupported, "authorization_code")))
	qt.Check(t, qt.IsTrue(slices.Contains(meta.GrantTypesSupported,
		"urn:ietf:params:oauth:grant-type:pre-authorized_code")))
}
