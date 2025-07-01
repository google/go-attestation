package certinfo

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"

	"google3/third_party/golang/attestation/oid/oid"
	"google3/third_party/golang/attestation/x509/x509ext"
	cryptobyte_asn1 "google3/third_party/golang/go_crypto/cryptobyte/asn1/asn1"
	"google3/third_party/golang/go_crypto/cryptobyte/cryptobyte"
)

// TODO(bweeks): clean up and move to third_party/golang/attestation/x509

// ParseAKCertificate parses a single certificate from the given ASN.1 DER data.
func ParseAKCertificate(der []byte) (*AKCertificate, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	akCert := &AKCertificate{Certificate: cert}

	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid.SubjectAltName) {
			san, err := x509ext.ParseSubjectAltName(ext)
			if err != nil {
				return nil, err
			}
			if len(san.PermanentIdentifiers) == 1 {
				akCert.PermanentIdentifier = san.PermanentIdentifiers[0]
			} else if len(san.PermanentIdentifiers) > 1 {
				return nil, errors.New("length of PermanentIdentifiers is > 1")
			}
		}
		if ext.Id.Equal(oid.CloudComputeInstanceIdentifier) {
			gceInstanceID, err := parseGCEInstanceID(ext)
			if err != nil {
				return nil, fmt.Errorf("failed to parse GCE Instance Info: %w", err)
			}
			akCert.gceInstanceID = gceInstanceID
		}
		if ext.Id.Equal(oid.ChromeOSAttestedDeviceID) {
			value, bytes := cryptobyte.String(ext.Value), cryptobyte.String{}
			if !value.ReadASN1(&bytes, cryptobyte_asn1.OCTET_STRING) {
				return nil, fmt.Errorf("invalid ADID extension: %w", err)
			}
			adid := string(bytes)
			akCert.adid = &adid
		}
	}

	if len(cert.UnhandledCriticalExtensions) == 1 && cert.UnhandledCriticalExtensions[0].Equal(oid.SubjectAltName) {
		cert.UnhandledCriticalExtensions = []asn1.ObjectIdentifier{}
	}
	return akCert, nil
}

// AKCertificate extends x509.certificate with helper methods for working with
// TCG AKCertificates.
type AKCertificate struct {
	*x509.Certificate
	PermanentIdentifier x509ext.PermanentIdentifier
	gceInstanceID       *GCEInstanceID
	adid                *string
}

// Fingerprint returns a unique representation of an AK certificate.
func (c AKCertificate) Fingerprint() string {
	b := sha256.Sum256(c.Raw)
	return hex.EncodeToString(b[:])
}

// GCEInstanceID returns the GCE instance ID, if included in the certificate.
func (c AKCertificate) GCEInstanceID() (id *GCEInstanceID, ok bool) {
	if c.gceInstanceID == nil {
		return nil, false
	}
	return c.gceInstanceID, true
}

// ADID returns the Chrome OS ADID, if included in the certificate.
func (c AKCertificate) ADID() (*string, bool) {

	if c.adid == nil {
		return nil, false
	}
	return c.adid, true
}

// ToPEM returns the AK certificate PEM encoded.
func (c AKCertificate) ToPEM() string {
	return ToPEM(c.Raw)
}
