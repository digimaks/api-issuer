// SPDX-License-Identifier: EUPL-1.2

package openid4vci

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/lx-lib/lx-go-jsondb"
)

// StatusList identifies a single revocation slot allocated for one issued
// credential copy. A batch credential request mints one physical credential
// per proof, each with its own status list entry (statuslist.Client.Take
// is called once per proof).
type StatusList struct {
	URI string
	Idx int
}

// RecordCredentialIssuanceParams carries the fields recorded for a single
// issued credential via attestation_provider.record_credential_issuance.
// Field contract mirrors api-wallet-digimaks (routes/issuer/issuer.go
// trackCredentialIssuance) so the same database function serves both callers
// during the issuance-separation transition.
type RecordCredentialIssuanceParams struct {
	// CredentialIdentifier is the credential_configuration_id used to issue this credential.
	CredentialIdentifier string
	// Format is the OpenID4VCI credential format ("mso_mdoc" or "dc+sd-jwt").
	Format string
	// DoctypeVct is the mdoc doctype or SD-JWT-VC vct.
	DoctypeVct string
	// IssuedAt/ExpiresAt are the credential's actual issuance/expiry timestamps.
	IssuedAt  time.Time
	ExpiresAt time.Time
	// HolderIdentifier is the raw eIDAS person identifier (e.g. the
	// personal_administrative_number claim), optionally prefixed with a
	// scheme such as "PNOLV-". Split into holder_identifier_type/value
	// before storage.
	HolderIdentifier string
	HolderGivenName  string
	HolderFamilyName string
	// WalletProvider identifies the wallet instance/provider that requested issuance.
	WalletProvider string
	// StatusListSlots is one entry per issued physical credential copy
	// (batch issuance mints one slot per proof). The first slot's URI/Idx
	// are duplicated under the legacy singular status_list_uri/idx columns.
	StatusListSlots []StatusList
	// HardwareKeyTag is the device-binding tag extracted from the proof's
	// key attestation JWT, if present.
	HardwareKeyTag string
}

// statusListSlotDTO is the wire shape of a single StatusList slot sent to
// attestation_provider.record_credential_issuance.
type statusListSlotDTO struct {
	URI string `json:"uri"`
	Idx int    `json:"idx"`
}

// splitHolderIdentifier parses a raw eIDAS person identifier such as
// "PNOLV-32001011234" into its scheme prefix ("PNOLV") and bare value
// ("32001011234"). Identifiers without a recognized scheme prefix are
// reported as "person_code" with the value unchanged. Ported from
// api-wallet-digimaks routes/issuer/issuer.go trackCredentialIssuance.
func splitHolderIdentifier(identifier string) (identifierType, identifierValue string) {
	identifierType = "person_code"
	identifierValue = identifier

	if strings.HasPrefix(identifier, "PNOLV-") {
		identifierType = "PNOLV"
	}

	if idx := strings.Index(identifierValue, "-"); idx > 0 {
		identifierValue = identifierValue[idx+1:]
	}

	return identifierType, identifierValue
}

// RecordCredentialIssuance records a newly issued credential via
// attestation_provider.record_credential_issuance and returns the generated
// credential ID. Callers (e.g. POST /credential) should treat a non-nil
// error as non-fatal: issuance already succeeded, only tracking failed.
func RecordCredentialIssuance(ctx context.Context, store jsondb.Store, p RecordCredentialIssuanceParams) (string, error) {
	identifierType, identifierValue := splitHolderIdentifier(p.HolderIdentifier)

	slotDTOs := make([]statusListSlotDTO, len(p.StatusListSlots))
	for i, s := range p.StatusListSlots {
		slotDTOs[i] = statusListSlotDTO(s)
	}

	// First-slot values also populate the legacy singular columns so a
	// database function without batch-slot support still records one row
	// exactly as before.
	var (
		legacyURI string
		legacyIdx int
	)

	if len(p.StatusListSlots) > 0 {
		legacyURI = p.StatusListSlots[0].URI
		legacyIdx = p.StatusListSlots[0].Idx
	}

	var result struct {
		ID string `json:"id"`
	}

	err := store.Exec(ctx, "attestation_provider.record_credential_issuance", &struct {
		CredentialIdentifier  string              `json:"credential_identifier"`
		Format                string              `json:"format"`
		DoctypeVct            string              `json:"doctype_vct"`
		IssuedAt              string              `json:"issued_at"`
		ExpiresAt             string              `json:"expires_at"`
		HolderIdentifierType  string              `json:"holder_identifier_type"`
		HolderIdentifierValue string              `json:"holder_identifier_value"`
		HolderGivenName       string              `json:"holder_given_name"`
		HolderFamilyName      string              `json:"holder_family_name"`
		WalletProvider        string              `json:"wallet_provider"`
		InstallStatus         string              `json:"install_status"`
		StatusListURI         string              `json:"status_list_uri"`
		StatusListIdx         int                 `json:"status_list_idx"`
		StatusListSlots       []statusListSlotDTO `json:"status_list_slots"`
		HardwareKeyTag        string              `json:"hardware_key_tag"`
	}{
		CredentialIdentifier:  p.CredentialIdentifier,
		Format:                p.Format,
		DoctypeVct:            p.DoctypeVct,
		IssuedAt:              p.IssuedAt.Format(time.RFC3339),
		ExpiresAt:             p.ExpiresAt.Format(time.RFC3339),
		HolderIdentifierType:  identifierType,
		HolderIdentifierValue: identifierValue,
		HolderGivenName:       p.HolderGivenName,
		HolderFamilyName:      p.HolderFamilyName,
		WalletProvider:        p.WalletProvider,
		InstallStatus:         "pending",
		StatusListURI:         legacyURI,
		StatusListIdx:         legacyIdx,
		StatusListSlots:       slotDTOs,
		HardwareKeyTag:        p.HardwareKeyTag,
	}, &result)
	if err != nil {
		return "", fmt.Errorf("record credential issuance: %w", err)
	}

	return result.ID, nil
}
