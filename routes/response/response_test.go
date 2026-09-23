// SPDX-License-Identifier: EUPL-1.2

package response

import (
	"encoding/json"
	"testing"

	"github.com/go-quicktest/qt"
)

func TestCredentialEntry_MarshalsFormatAndExpiry(t *testing.T) {
	entry := CredentialEntry{
		Credential:    "fake-cred",
		Format:        "mso_mdoc",
		ExpiresAt:     "2026-07-06T11:19:11Z",
		StatusListURI: "http://statuslist:8080/token_status_list/LV/eu.europa.ec.eudi.pid.1/abc",
		StatusListIdx: 5905,
	}

	b, err := json.Marshal(entry)
	qt.Assert(t, qt.IsNil(err))

	var got map[string]interface{}
	qt.Assert(t, qt.IsNil(json.Unmarshal(b, &got)))

	qt.Check(t, qt.Equals(got["credential"], "fake-cred"))
	qt.Check(t, qt.Equals(got["format"], "mso_mdoc"))
	qt.Check(t, qt.Equals(got["expires_at"], "2026-07-06T11:19:11Z"))
	qt.Check(t, qt.Equals(got["status_list_uri"], "http://statuslist:8080/token_status_list/LV/eu.europa.ec.eudi.pid.1/abc"))
	qt.Check(t, qt.Equals(got["status_list_idx"].(float64), float64(5905)))
}
