// SPDX-License-Identifier: EUPL-1.2

package openid4vci

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"azugo.io/core"
	"github.com/lx-lib/lx-go-jsondb"
	"github.com/go-quicktest/qt"
)

// fakeStore is a minimal jsondb.Store fake that records the last Exec call
// and lets tests inject either a result payload or an error.
type fakeStore struct {
	method     string
	params     any
	resultJSON string
	execErr    error
}

func (f *fakeStore) Start(context.Context) error { return nil }
func (f *fakeStore) IsReady() bool               { return true }
func (f *fakeStore) Close()                      {}
func (f *fakeStore) AddTask(core.Tasker)         {}
func (f *fakeStore) Ping(context.Context) error  { return nil }

func (f *fakeStore) Begin(context.Context) (*jsondb.Tx, error) {
	return nil, errors.New("fakeStore: Begin not supported")
}

func (f *fakeStore) Exec(_ context.Context, method string, params, data interface{}) error {
	f.method = method
	f.params = params

	if f.execErr != nil {
		return f.execErr
	}

	if data != nil && f.resultJSON != "" {
		return json.Unmarshal([]byte(f.resultJSON), data)
	}

	return nil
}

// paramsAsMap round-trips the captured Exec params through JSON so tests can
// assert on the wire field names/casing actually sent to the database function.
func paramsAsMap(t *testing.T, params any) map[string]any {
	t.Helper()

	raw, err := json.Marshal(params)
	qt.Assert(t, qt.IsNil(err))

	var got map[string]any
	qt.Assert(t, qt.IsNil(json.Unmarshal(raw, &got)))

	return got
}

func TestRecordCredentialIssuance_FieldMapping(t *testing.T) {
	store := &fakeStore{resultJSON: `{"id":"cred-123"}`}

	issuedAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	expiresAt := issuedAt.Add(24 * time.Hour)

	id, err := RecordCredentialIssuance(context.Background(), store, RecordCredentialIssuanceParams{
		CredentialIdentifier: "eu.europa.ec.eudi.pid_digimaks_pid_mdoc",
		Format:               "mso_mdoc",
		DoctypeVct:           "eu.europa.ec.eudi.pid.1",
		IssuedAt:             issuedAt,
		ExpiresAt:            expiresAt,
		HolderIdentifier:     "PNOLV-32001011234",
		HolderGivenName:      "Jane",
		HolderFamilyName:     "Doe",
		WalletProvider:       "https://wallet.example.com",
		StatusListSlots: []StatusList{
			{URI: "https://status.example.com/1", Idx: 5},
			{URI: "https://status.example.com/1", Idx: 6},
		},
		HardwareKeyTag: "tag-abc",
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(id, "cred-123"))
	qt.Assert(t, qt.Equals(store.method, "attestation_provider.record_credential_issuance"))

	got := paramsAsMap(t, store.params)

	qt.Check(t, qt.Equals(got["credential_identifier"], "eu.europa.ec.eudi.pid_digimaks_pid_mdoc"))
	qt.Check(t, qt.Equals(got["format"], "mso_mdoc"))
	qt.Check(t, qt.Equals(got["doctype_vct"], "eu.europa.ec.eudi.pid.1"))
	qt.Check(t, qt.Equals[any](got["issued_at"], issuedAt.Format(time.RFC3339)))
	qt.Check(t, qt.Equals[any](got["expires_at"], expiresAt.Format(time.RFC3339)))
	qt.Check(t, qt.Equals(got["holder_identifier_type"], "PNOLV"))
	qt.Check(t, qt.Equals(got["holder_identifier_value"], "32001011234"))
	qt.Check(t, qt.Equals(got["holder_given_name"], "Jane"))
	qt.Check(t, qt.Equals(got["holder_family_name"], "Doe"))
	qt.Check(t, qt.Equals(got["wallet_provider"], "https://wallet.example.com"))
	qt.Check(t, qt.Equals(got["install_status"], "pending"))
	qt.Check(t, qt.Equals(got["hardware_key_tag"], "tag-abc"))

	// Legacy singular columns duplicate the first slot.
	qt.Check(t, qt.Equals(got["status_list_uri"], "https://status.example.com/1"))
	qt.Check(t, qt.Equals[any](got["status_list_idx"], float64(5)))

	slots, ok := got["status_list_slots"].([]any)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Assert(t, qt.HasLen(slots, 2))
}

func TestRecordCredentialIssuance_PlainIdentifierIsPersonCode(t *testing.T) {
	store := &fakeStore{resultJSON: `{"id":"cred-456"}`}

	_, err := RecordCredentialIssuance(context.Background(), store, RecordCredentialIssuanceParams{
		HolderIdentifier: "32001011234",
	})
	qt.Assert(t, qt.IsNil(err))

	got := paramsAsMap(t, store.params)
	qt.Check(t, qt.Equals(got["holder_identifier_type"], "person_code"))
	qt.Check(t, qt.Equals(got["holder_identifier_value"], "32001011234"))
}

func TestRecordCredentialIssuance_NoStatusListSlots(t *testing.T) {
	store := &fakeStore{resultJSON: `{"id":"cred-789"}`}

	_, err := RecordCredentialIssuance(context.Background(), store, RecordCredentialIssuanceParams{
		HolderIdentifier: "PNOLV-1",
	})
	qt.Assert(t, qt.IsNil(err))

	got := paramsAsMap(t, store.params)
	qt.Check(t, qt.Equals(got["status_list_uri"], ""))
	qt.Check(t, qt.Equals[any](got["status_list_idx"], float64(0)))

	slots, ok := got["status_list_slots"].([]any)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Assert(t, qt.HasLen(slots, 0))
}

func TestRecordCredentialIssuance_StoreErrorIsWrapped(t *testing.T) {
	wantErr := errors.New("db unavailable")
	store := &fakeStore{execErr: wantErr}

	_, err := RecordCredentialIssuance(context.Background(), store, RecordCredentialIssuanceParams{})
	qt.Assert(t, qt.Not(qt.IsNil(err)))
	qt.Check(t, qt.IsTrue(errors.Is(err, wantErr)))
}
