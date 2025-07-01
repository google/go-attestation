// Package certinfo parses TCG Attestation Key and Endorsement Key certificates.
package certinfo

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"

	"google3/third_party/golang/attestation/oid/oid"
	"google3/third_party/golang/attestation/x509/x509ext"
	cryptobyte_asn1 "google3/third_party/golang/go_crypto/cryptobyte/asn1/asn1"
	"google3/third_party/golang/go_crypto/cryptobyte/cryptobyte"
	"google3/third_party/golang/go_exp/slices/slices"
)

// TODO(bweeks): clean up and move to third_party/golang/attestation/x509

var (
	// OID for tcg-kp-EKCertificate (2.23.133.8.1)
	// https://oidref.com/2.23.133.8.1
	// This may be present in the Extended Key Usage of the EK Certificate.
	// See 3.2.16 of TCG EK Credential Profile
	// https://trustedcomputinggroup.org/wp-content/uploads/EK-Credential-Profile-For-TPM-Family-2.0-Level-0-V2.5-R1.0_28March2022.pdf
	eKCertificateOID = asn1.ObjectIdentifier{2, 23, 133, 8, 1}

	versionRE         = regexp.MustCompile("^id:[0-9a-fA-F]{8}$")
	infineonVersionRE = regexp.MustCompile("^id:[0-9a-fA-F]{4}$")
	nuvotonVersionRE  = regexp.MustCompile("^id:[0-9a-fA-F]{2}$")
	kunetiCAIssuers   = []pkix.Name{
		{
			Organization: []string{"Google"},
			CommonName:   "Kuneti EK CA Intermediate",
		},
		// Dev clusters have 'Dev' appended to the Common Name.
		{
			Organization: []string{"Google"},
			CommonName:   "Kuneti EK CA Intermediate Dev",
		},
	}
	privateCAContentRE = regexp.MustCompile(`http://privateca-content-.*\.storage\.googleapis\.com/.*/ca\.crt`)
)

// ParseEKCertificate parses a single certificate from the given ASN.1 DER data.
func ParseEKCertificate(der []byte) (*EKCertificate, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return ToEKCertificate(cert)
}

// ToEKCertificate converts an x509 certificate to an EKCertificate.
func ToEKCertificate(cert *x509.Certificate) (*EKCertificate, error) {
	// Some older EK certificates have RSA-OAEP public keys, which are not
	// parsed by crypto/x509, resulting in PublicKey being nil.
	if cert.PublicKey == nil {
		return nil, errors.New("PublicKey is nil")
	}

	var spec tpmSpecification
	var tpmManufacturer, tpmModel, tpmVersion string
	var gceInstanceID *GCEInstanceID
	var adid *string
	var ekcFound bool
	var err error

	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid.SubjectAltName) {
			san, err := x509ext.ParseSubjectAltName(ext)
			if err != nil {
				return nil, err
			}
			// TODO(bweeks): support multiple directory names.
			if len(san.DirectoryNames) != 1 {
				return nil, errors.New("only a single DirectoryName is supported")
			}
			tpmManufacturer, tpmModel, tpmVersion, err = parseName(san.DirectoryNames[0])
			if err != nil {
				return nil, err
			}
		}

		if ext.Id.Equal(oid.SubjectDirectoryAttributes) {
			subjectDirectoryAttributes, err := parseSubjectDirectoryAttributes(ext)
			if err != nil {
				return nil, err
			}
			if spec, err = parseTPMSpecification(subjectDirectoryAttributes); err != nil {
				return nil, err
			}
		}

		if ext.Id.Equal(oid.CloudComputeInstanceIdentifier) {
			if gceInstanceID, err = parseGCEInstanceID(ext); err != nil {
				return nil, err
			}
		}

		if ext.Id.Equal(oid.ChromeOSAttestedDeviceID) {
			value, bytes := cryptobyte.String(ext.Value), cryptobyte.String{}
			if !value.ReadASN1(&bytes, cryptobyte_asn1.OCTET_STRING) {
				return nil, fmt.Errorf("invalid ADID extension: %w", err)
			}
			a := string(bytes)
			adid = &a
		}
	}
	var unhandled []asn1.ObjectIdentifier
	for _, ext := range cert.UnhandledCriticalExtensions {
		if ext.Equal(oid.SubjectAltName) {
			// Ignore unhandled SAN.
			continue
		}
		if ext.Equal(oid.CloudComputeInstanceIdentifier) {
			// Ignore unhandled GCE.
			continue
		}
		unhandled = append(unhandled, ext)
	}
	cert.UnhandledCriticalExtensions = unhandled

	if tpmVersion != "" && !versionRE.MatchString(tpmVersion) {
		return nil, fmt.Errorf("invalid TPM version %q", tpmVersion)
	}

	// Iterate through unknown/custom ExtKeyUsage OIDs
	for _, oid := range cert.UnknownExtKeyUsage {
		if oid.Equal(eKCertificateOID) {
			ekcFound = true
		}
	}

	// Detect if the certificate is for a Kuneti Device.
	// b/417582309
	isKuneti, archboardID := isKunetiCertificate(cert)
	// For Kuneti, the Extended Key Usage must include the EK Certificate OID.
	isKuneti = isKuneti && ekcFound

	return &EKCertificate{
		Certificate:      cert,
		tpmManufacturer:  tpmManufacturer,
		tpmModel:         tpmModel,
		tpmVersion:       tpmVersion,
		tpmSpecification: spec,
		gceInstanceID:    gceInstanceID,
		adid:             adid,
		isKuneti:         isKuneti,
		archboardID:      archboardID,
		ekcFound:         ekcFound,
	}, nil
}

// isKunetiCertificate checks if the certificate is issued for a Kuneti host.
// Returns true if the certificate is a Kuneti certificate, along with the Archboard ID.
func isKunetiCertificate(cert *x509.Certificate) (bool, string) {

	if cert.Subject.Organization == nil || len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != "Kuneti" {
		return false, ""
	}
	if !isKunetiIssuer(cert.Issuer) {
		return false, ""
	}
	if cert.AuthorityKeyId == nil {
		return false, ""
	}
	found := false
	for _, uri := range cert.IssuingCertificateURL {
		if privateCAContentRE.MatchString(uri) {
			found = true
			break
		}
	}
	if !found {
		return false, ""
	}
	archboardID := cert.Subject.CommonName
	return true, archboardID
}

func parseName(name pkix.Name) (string, string, string, error) {
	var tpmManufacturer, tpmModel, tpmVersion string
	var err error
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
			if tpmVersion, err = versionFix(fmt.Sprintf("%v", attr.Value)); err != nil {
				return tpmManufacturer, tpmModel, tpmVersion, err
			}
			continue
		}
		return tpmManufacturer, tpmModel, tpmVersion, fmt.Errorf("unknown attribute type: %v", attr.Type)
	}
	return tpmManufacturer, tpmModel, tpmVersion, nil
}

func versionFix(tpmVersion string) (string, error) {
	if infineonVersionRE.MatchString(tpmVersion) {
		major, err := hex.DecodeString(tpmVersion[3:5])
		if err != nil {
			return "", err
		}
		minor, err := hex.DecodeString(tpmVersion[5:7])
		if err != nil {
			return "", err
		}
		tpmVersion = fmt.Sprintf("id:%04X%04X", major, minor)
	}
	if nuvotonVersionRE.MatchString(tpmVersion) {
		major, err := hex.DecodeString(tpmVersion[3:5])
		if err != nil {
			return "", err
		}
		tpmVersion = fmt.Sprintf("id:%04X0000", major)
	}
	return tpmVersion, nil
}

func parseGCEInstanceID(ext pkix.Extension) (*GCEInstanceID, error) {
	var out GCEInstanceID
	if _, err := asn1.Unmarshal(ext.Value, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func parseTPMSpecification(subjectDirectoryAttributes []attribute) (tpmSpecification, error) {
	for _, attr := range subjectDirectoryAttributes {
		if attr.Type.Equal(oid.TPMSpecification) {
			if len(attr.Values) != 1 {
				return tpmSpecification{}, errors.New("expected SET size of 1")
			}
			value := attr.Values[0]
			var spec tpmSpecification
			rest, err := asn1.Unmarshal(value.FullBytes, &spec)
			if err != nil {
				return tpmSpecification{}, err
			}
			if len(rest) != 0 {
				return tpmSpecification{}, errors.New("trailing data after TPMSpecification")
			}
			return spec, nil
		}
	}
	return tpmSpecification{}, errors.New("TPMSpecification not present")
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

func isKunetiIssuer(issuer pkix.Name) bool {
	for _, kunetiCAIssuer := range kunetiCAIssuers {
		if slices.Equal(issuer.Organization, kunetiCAIssuer.Organization) && issuer.CommonName == kunetiCAIssuer.CommonName {
			return true
		}
	}
	return false
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

type tpmSpecification struct {
	Family   string
	Level    int
	Revision int
}

// GCEInstanceID corresponds to the CloudComputeInstanceIdentifier ASN.1 sequence.
// http://google3/security/ca/lib/processor/x509.cc?l=343&rcl=334642330
type GCEInstanceID struct {
	Zone          string
	ProjectNumber *big.Int
	ProjectID     string
	InstanceID    *big.Int
	InstanceName  string
	// The SecurityProperties field was added in cl/312350612, so we make this
	// field optional to avoid parsing errors when it is missing.
	SecurityProperties GCESecurityProperties `asn1:"tag:0,explicit,optional"`
}

// GCESecurityProperties is used in `GCEInstanceID`. See `GCEInstanceID` for
// details. Note that we don't set default values in the asn1 tag because
// the asn1 lib does not seem to do anything with them, but that is fine because
// the golang default values match what we want.
type GCESecurityProperties struct {
	SecurityVersion             *big.Int `asn1:"tag:0,explicit,optional"`
	IsProduction                bool     `asn1:"tag:1,explicit,optional"`
	TpmDataAlwaysEncrypted      bool     `asn1:"tag:2,explicit,optional"`
	SuspendResumeAlwaysDisabled bool     `asn1:"tag:3,explicit,optional"`
	VmtdAlwaysDisabled          bool     `asn1:"tag:4,explicit,optional"`
	AlwaysInYarn                bool     `asn1:"tag:5,explicit,optional"`
}

// EKCertificate extends x509.certificate with helper methods for working with
// TCG EK Certificates.
type EKCertificate struct {
	*x509.Certificate
	tpmManufacturer, tpmModel, tpmVersion string
	tpmSpecification                      tpmSpecification
	gceInstanceID                         *GCEInstanceID
	adid                                  *string
	isKuneti                              bool
	archboardID                           string
	// If the certificate contains a tcg-kp-EKCertificate (2.23.133.8.1) in the
	// Extended Key Usage, this will be true.
	ekcFound bool
}

// Holder returns a string which matches the Holder of a
// corresponding platform cert.
func (e EKCertificate) Holder() string {
	return e.SerialNumber.String() + "/" + strings.TrimSpace(e.Issuer.CommonName)
}

// Fingerprint returns a unique representation of a certificate.
func Fingerprint(cert *x509.Certificate) string {
	b := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(b[:])
}

// Fingerprint returns a unique representation of an EK certificate.
func (e EKCertificate) Fingerprint() string {
	return Fingerprint(e.Certificate)
}

// Manufacturer returns the TPM manufacturer.
func (e EKCertificate) Manufacturer() string {
	return e.tpmManufacturer
}

// Model returns the TPM model.
func (e EKCertificate) Model() string {
	return e.tpmModel
}

// Version returns the TPM firmware version.
func (e EKCertificate) Version() string {
	return e.tpmVersion
}

// SpecificationFamily returns the TPM specification family.
func (e EKCertificate) SpecificationFamily() string {
	return e.tpmSpecification.Family
}

// SpecificationLevel returns the TPM specification level.
func (e EKCertificate) SpecificationLevel() int {
	return e.tpmSpecification.Level
}

// SpecificationRevision returns the TPM specification revision.
func (e EKCertificate) SpecificationRevision() int {
	return e.tpmSpecification.Revision
}

// GCEInstanceID returns the GCE instance ID, if included in the certificate.
func (e EKCertificate) GCEInstanceID() (id *GCEInstanceID, ok bool) {
	if e.gceInstanceID == nil {
		return nil, false
	}
	return e.gceInstanceID, true
}

// ADID returns the Chrome OS ADID, if included in the certificate.
func (e EKCertificate) ADID() (*string, bool) {
	if e.adid == nil {
		return nil, false
	}
	return e.adid, true
}

// IsKuneti returns true if the EK Certificate is for a Kuneti Device.
func (e EKCertificate) IsKuneti() bool {
	return e.isKuneti
}

// ArchboardID returns the Archboard ID, if included in the certificate.
func (e EKCertificate) ArchboardID() string {
	return e.archboardID
}

// ToPEM returns the EK certificate PEM encoded.
func (e EKCertificate) ToPEM() string {
	return ToPEM(e.Raw)
}

// ToPEM returns an x509 certificate PEM encoded.
func ToPEM(cert []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "X509 CERTIFICATE", Bytes: cert}))
}
