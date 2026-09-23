// SPDX-License-Identifier: EUPL-1.2

package routes

import (
	"testing"

	"github.com/go-quicktest/qt"
)

func TestBuildExtraHTUs_Empty(t *testing.T) {
	qt.Assert(t, qt.IsNil(buildExtraHTUs(nil)))
}

func TestBuildExtraHTUs_GroupsByLastPathSegment(t *testing.T) {
	extra := buildExtraHTUs([]string{
		"https://proxy.example.com/wallet/credential",
		"https://proxy.example.com/wallet/revoke",
		"https://proxy.example.com/other/credential/",
	})

	qt.Assert(t, qt.DeepEquals(extra, map[string][]string{
		"/credential": {
			"https://proxy.example.com/wallet/credential",
			"https://proxy.example.com/other/credential/",
		},
		"/revoke": {"https://proxy.example.com/wallet/revoke"},
	}))
}

func TestBuildExtraHTUs_SkipsUnparsableURL(t *testing.T) {
	extra := buildExtraHTUs([]string{"://not-a-url", "https://proxy.example.com/wallet/credential"})

	qt.Assert(t, qt.DeepEquals(extra, map[string][]string{
		"/credential": {"https://proxy.example.com/wallet/credential"},
	}))
}
