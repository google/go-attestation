package x509ext

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/google/go-attestation/oid"
)

var (
	// The DER encoding of an empty SEQUENCE is 0x30 0x00.
	emptyASN1Subject         = []byte{0x30, 0}
	oidAuthorityInfoAccess   = []int{1, 3, 6, 1, 5, 5, 7, 1, 1}
	oidBasicConstraints      = []int{2, 5, 29, 19}
	oidSubjectKeyIdentifier  = []int{2, 5, 29, 14}
	oidKeyUsage              = []int{2, 5, 29, 15}
	oidCRLDistributionPoints = []int{2, 5, 29, 31}
	oidAuthorityKeyID        = []int{2, 5, 29, 35}
	oidExtendedKeyUsage      = []int{2, 5, 29, 37}
	mustHaveExtensions       = []asn1.ObjectIdentifier{
		oid.SubjectAltName,
		oidBasicConstraints,
		oidKeyUsage,
		oidAuthorityKeyID,
	}
	oidToExtNameMap = map[string]string{
		(asn1.ObjectIdentifier)(oid.SubjectAltName).String():  "SubjectAltName",
		(asn1.ObjectIdentifier)(oidBasicConstraints).String(): "BasicConstraints",
		(asn1.ObjectIdentifier)(oidKeyUsage).String():         "Key Usage",
		(asn1.ObjectIdentifier)(oidAuthorityKeyID).String():   "Authority Key Identifier",
	}
)

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

// TpmSpecification represents the TPM specification of an EK certificate.
type TpmSpecification struct {
	Family   string
	Level    int
	Revision int
}

// EKCertificate extends x509.certificate with helper methods for working with
// TCG EK Certificates.
type EKCertificate struct {
	*x509.Certificate
	TpmManufacturer, TpmModel, TpmVersion string
	TpmSpecification                      TpmSpecification
	// If the certificate contains a tcg-kp-EKCertificate (2.23.133.8.1) in the
	// Extended Key Usage, this will be true.
	HasEkcExtendedKeyUsage bool
}

// ParseEKCertificate parses a single certificate from the given ASN.1 DER data.
func ParseEKCertificate(der []byte) (*EKCertificate, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return ToEKCertificate(cert)
}

// ToEKCertificate converts a x509 certificate to an EKCertificate. It also
// validates the EK cert according to Section 3.2 of
// https://trustedcomputinggroup.org/wp-content/uploads/TCG-EK-Credential-Profile-for-TPM-Family-2.0-Level-0-Version-2.6_pub.pdf
//
// Extensions handled by this function will be removed from
// `cert.UnhandledCriticalExtensions` in place if present.
func ToEKCertificate(cert *x509.Certificate) (*EKCertificate, error) {
	// Some older EK certificates have RSA-OAEP public keys, which are not
	// parsed by crypto/x509, resulting in PublicKey being nil.
	if cert.PublicKey == nil {
		return nil, errors.New("PublicKey is nil")
	}

	var spec TpmSpecification
	var tpmManufacturer, tpmModel, tpmVersion string
	var hasEKCExtendedKeyUsage bool
	extPresent := make(map[string]bool)

	// Version must be 3.
	if cert.Version != 3 {
		return nil, fmt.Errorf("Invalid version of EK certificate: %d", cert.Version)
	}

	// SerialNumber must be a positive integer and not nil.
	if err := validateSerialNumber(cert.SerialNumber); err != nil {
		return nil, err
	}

	// Issuer must be present.
	if bytes.Equal(cert.RawIssuer, emptyASN1Subject) {
		return nil, errors.New("Issuer is empty")
	}

	isSubjectEmpty := bytes.Equal(cert.RawSubject, emptyASN1Subject)

	// Basic Constraints must be valid and the certificate must not be a CA.
	if !cert.BasicConstraintsValid || cert.IsCA {
		return nil, errors.New("Basic Constraints are not valid or it is a CA certificate")
	}

	for _, ext := range cert.Extensions {
		switch {
		case ext.Id.Equal(oid.SubjectAltName):
			if isSubjectEmpty {
				if !ext.Critical {
					return nil, errors.New("SubjectAltName extension must be critical when Subject is not present")
				}
			}
			san, err := ParseSubjectAltName(ext)
			if err != nil {
				return nil, err
			}
			if len(san.DirectoryNames) != 1 {
				return nil, errors.New("only a single DirectoryName is supported")
			}
			tpmManufacturer, tpmModel, tpmVersion, err = parseName(san.DirectoryNames[0])
			if err != nil {
				return nil, err
			}
		case ext.Id.Equal(oid.SubjectDirectoryAttributes):
			subjectDirectoryAttributes, err := parseSubjectDirectoryAttributes(ext)
			if err != nil {
				return nil, err
			}
			if spec, err = parseTPMSpecification(subjectDirectoryAttributes); err != nil {
				return nil, err
			}
		case ext.Id.Equal(oidBasicConstraints):
			if !ext.Critical {
				return nil, errors.New("Extension \"Basic Constraints\" is not critical, supposed to be critical")
			}
		case ext.Id.Equal(oidKeyUsage):
			if !ext.Critical {
				return nil, errors.New("Extension \"Key Usage\" is not critical, supposed to be critical")
			}
		case ext.Id.Equal(oidAuthorityKeyID):
			if ext.Critical {
				return nil, errors.New("Extension \"Authority Key Identifier\" is critical, supposed to be non-critical")
			}
		case ext.Id.Equal(oid.CertificatePolicies):
			if len(cert.PolicyIdentifiers) == 0 {
				return nil, errors.New("Certificate Policies should contain at least 1 policy identifier if the extension is present")
			}
		case ext.Id.Equal(oidAuthorityInfoAccess):
			if ext.Critical {
				return nil, errors.New("Extension \"Authority Info Access\" is critical, supposed to be non-critical")
			}
		case ext.Id.Equal(oidCRLDistributionPoints):
			if ext.Critical {
				return nil, errors.New("Extension \"CRL Distribution Points\" is critical, supposed to be non-critical")
			}
		case ext.Id.Equal(oidExtendedKeyUsage):
			if ext.Critical {
				return nil, errors.New("Extension \"Extended Key Usage\" is critical, supposed to be non-critical")
			}
		case ext.Id.Equal(oidSubjectKeyIdentifier):
			if ext.Critical {
				return nil, errors.New("Extension \"Subject Key Identifier\" is critical, supposed to be non-critical")
			}
		}

		extPresent[ext.Id.String()] = true
	}

	// Check that all must-have extensions are present.
	for _, extOID := range mustHaveExtensions {
		if !extPresent[extOID.String()] {
			return nil, fmt.Errorf("Extension %v is missing", oidToExtNameMap[extOID.String()])
		}
	}

	// Authority Key ID must be present and non-empty.
	if len(cert.AuthorityKeyId) == 0 {
		return nil, errors.New("Authority Key ID is missing")
	}

	// KeyUsage must be set and correctly set for the public key type.
	if err := validateKeyUsage(cert.PublicKeyAlgorithm, cert.KeyUsage); err != nil {
		return nil, err
	}

	// Iterate through unknown/custom ExtKeyUsage OIDs
	for _, eku := range cert.UnknownExtKeyUsage {
		if eku.Equal(oid.EKCertificate) {
			hasEKCExtendedKeyUsage = true
		}
	}

	for i, ext := range cert.UnhandledCriticalExtensions {
		if ext.Equal(oid.SubjectAltName) {
			length := len(cert.UnhandledCriticalExtensions)
			// Remove the extension from the list of unhandled critical extensions.
			cert.UnhandledCriticalExtensions[i] = cert.UnhandledCriticalExtensions[length-1]
			cert.UnhandledCriticalExtensions = cert.UnhandledCriticalExtensions[:length-1]
			break
		}
	}

	return &EKCertificate{
		Certificate:            cert,
		TpmManufacturer:        tpmManufacturer,
		TpmModel:               tpmModel,
		TpmVersion:             tpmVersion,
		TpmSpecification:       spec,
		HasEkcExtendedKeyUsage: hasEKCExtendedKeyUsage,
	}, nil
}

func validateSerialNumber(serialNumber *big.Int) error {
	if serialNumber == nil {
		return errors.New("SerialNumber is nil, expected a positive integer")
	}
	if serialNumber.Cmp(big.NewInt(0)) <= 0 {
		return errors.New("SerialNumber is not a positive integer")
	}
	return nil
}

func parseSubjectDirectoryAttributes(ext pkix.Extension) ([]attribute, error) {
	var attrs []attribute
	rest, err := asn1.Unmarshal(ext.Value, &attrs)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("trailing data after X.509 extension")
	}
	return attrs, nil
}

func parseTPMSpecification(subjectDirectoryAttributes []attribute) (TpmSpecification, error) {
	for _, attr := range subjectDirectoryAttributes {
		if attr.Type.Equal(oid.TPMSpecification) {
			if len(attr.Values) != 1 {
				return TpmSpecification{}, errors.New("expected SET size of 1")
			}
			value := attr.Values[0]
			var spec TpmSpecification
			rest, err := asn1.Unmarshal(value.FullBytes, &spec)
			if err != nil {
				return TpmSpecification{}, err
			}
			if len(rest) != 0 {
				return TpmSpecification{}, errors.New("trailing data after TPMSpecification")
			}
			return spec, nil
		}
	}
	return TpmSpecification{}, errors.New("TPMSpecification not present")
}

func parseName(name pkix.Name) (string, string, string, error) {
	var tpmManufacturer, tpmModel, tpmVersion string
	for _, attr := range name.Names {
		if attr.Type.Equal(oid.TPMManufacturer) {
			tpmManufacturer = fmt.Sprintf("%v", attr.Value)
			continue
		}
		if attr.Type.Equal(oid.TPMModel) {
			tpmModel = fmt.Sprintf("%v", attr.Value)
			continue
		}
		if attr.Type.Equal(oid.TPMVersion) {
			tpmVersion = fmt.Sprintf("%v", attr.Value)
			continue
		}
		return "", "", "", fmt.Errorf("unknown attribute type: %v", attr.Type)
	}
	if tpmManufacturer == "" {
		return "", "", "", fmt.Errorf("TPM Manufacturer not present")
	}
	if tpmModel == "" {
		return "", "", "", fmt.Errorf("TPM Model not present")
	}
	if tpmVersion == "" {
		return "", "", "", fmt.Errorf("TPM Version not present")
	}
	return tpmManufacturer, tpmModel, tpmVersion, nil
}

func validateKeyUsage(certType x509.PublicKeyAlgorithm, keyUsage x509.KeyUsage) error {
	if keyUsage == 0 {
		return fmt.Errorf("KeyUsage field is not set")
	}
	switch certType {
	case x509.RSA:
		if keyUsage&x509.KeyUsageKeyEncipherment == 0 {
			return fmt.Errorf("KeyUsageKeyEncipherment is not set for RSA public key type")
		}
	case x509.ECDSA:
		if keyUsage&x509.KeyUsageKeyAgreement == 0 {
			return fmt.Errorf("KeyUsageKeyAgreement is not set for ECDSA public key type")
		}
	default:
		return fmt.Errorf("Unsupported public key type: %v", certType)
	}
	return nil
}
