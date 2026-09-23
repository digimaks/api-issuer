// SPDX-License-Identifier: EUPL-1.2

package openid4vci

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
)

// SigningCertificateKID derives the key ID from the signing certificate's public key.
func (s *Service) SigningCertificateKID() (string, error) {
	tlsCert, err := s.config.SigningCertificate()
	if err != nil {
		return "", err
	}

	if len(tlsCert.Certificate) == 0 {
		return "", errors.New("no certificate in chain")
	}

	cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return "", err
	}

	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return "", errors.New("signing key is not ECDSA")
	}

	ecdhKey, err := pub.ECDH()
	if err != nil {
		return "", err
	}

	kidBytes := sha256.Sum256(ecdhKey.Bytes())

	return base64.RawURLEncoding.EncodeToString(kidBytes[:]), nil
}

// SigningCertificateX5C returns the base64-encoded DER certificate chain.
func (s *Service) SigningCertificateX5C() ([]string, error) {
	tlsCert, err := s.config.SigningCertificate()
	if err != nil {
		return nil, err
	}

	x5c := make([]string, 0, len(tlsCert.Certificate))
	for _, der := range tlsCert.Certificate {
		x5c = append(x5c, base64.StdEncoding.EncodeToString(der))
	}

	return x5c, nil
}
