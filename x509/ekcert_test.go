package x509ext

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/google/go-attestation/oid"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

var (
	SAN = &SubjectAltName{
		DirectoryNames: []pkix.Name{
			{
				ExtraNames: []pkix.AttributeTypeAndValue{
					{Type: oid.TPMManufacturer, Value: "id:12345"},
					{Type: oid.TPMModel, Value: "vTPM"},
					{Type: oid.TPMVersion, Value: "id:246810"},
				},
			},
		},
	}
	tpmSpec = TpmSpecification{
		Family:   "2.0",
		Level:    1,
		Revision: 48,
	}

	keySize = 2048
)

func generateRSAPrivateKey(t *testing.T) crypto.Signer {
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		t.Fatalf("failed to generate RSA private key: %v", err)
	}

	return privateKey
}

// selfSignedCert creates a self-signed certificate.
func selfSignedCert(t *testing.T, signer crypto.Signer) *x509.Certificate {
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		IsCA:                  true,
		NotBefore:             time.Date(2024, 01, 01, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2034, 01, 01, 0, 0, 0, 0, time.UTC),
		Subject:               pkix.Name{CommonName: "Test Signer"},
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(nil, template, template, signer.Public(), signer)
	if err != nil {
		t.Fatalf("x509.CreateCertificate() failed: %v", err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("x509.ParseCertificate() failed: %v", err)
	}
	return cert
}

// setupTestCert creates a new x509.Certificate for each test.
func setupTestCert(t *testing.T, modifyCertTemplate func(*testing.T, *x509.Certificate)) *x509.Certificate {
	t.Helper()
	privateKey := generateRSAPrivateKey(t)
	parentCert := selfSignedCert(t, privateKey)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1234),
		Version:      3,
		Issuer: pkix.Name{
			CommonName: "Test CA",
		},
		Subject: pkix.Name{
			CommonName: "test-common-name",
		},
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
		BasicConstraintsValid: true,
		IsCA:                  false,
		ExtraExtensions: []pkix.Extension{
			createSubjectAltNameExtension(t, SAN, false),
			createSubjectDirectoryAttributesExtension(t, tpmSpec, false),
		},
		AuthorityKeyId:     []byte("test-authority-key-id"),
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{oid.EKCertificate},
	}

	if modifyCertTemplate != nil {
		modifyCertTemplate(t, template)
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parentCert, generateRSAPrivateKey(t).Public(), privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("Failed to parse created certificate: %v", err)
	}

	return cert
}

// createSubjectAltNameExtension creates a new pkix.Extension for the SubjectAltName extension.
func createSubjectAltNameExtension(t *testing.T, san *SubjectAltName, critical bool) pkix.Extension {
	t.Helper()
	marshalledSAN, err := MarshalSubjectAltName(san, critical)
	if err != nil {
		t.Fatalf("Failed to marshal SubjectAltName: %v", err)
	}
	return pkix.Extension{
		Id:       oid.SubjectAltName,
		Critical: critical,
		Value:    marshalledSAN.Value,
	}
}

// createSubjectDirectoryAttributesExtension creates a new pkix.Extension for the SubjectDirectoryAttributes extension.
func createSubjectDirectoryAttributesExtension(t *testing.T, tpmSpec TpmSpecification, critical bool) pkix.Extension {
	t.Helper()
	tpmSpecBytes, err := asn1.Marshal(tpmSpec)
	if err != nil {
		t.Fatalf("Failed to marshal TpmSpecification: %v", err)
	}
	subjectDirectoryAttributes := []attribute{
		{
			Type: oid.TPMSpecification,
			Values: []asn1.RawValue{
				{FullBytes: tpmSpecBytes},
			},
		},
	}
	subjectDirectoryAttributesBytes, err := asn1.Marshal(subjectDirectoryAttributes)
	if err != nil {
		t.Fatalf("Failed to marshal subjectDirectoryAttributes: %v", err)
	}
	return pkix.Extension{
		Id:       oid.SubjectDirectoryAttributes,
		Critical: critical,
		Value:    subjectDirectoryAttributesBytes,
	}
}

// modifyExtension ensures that an extension with the given OID is present with the specified criticality. If not, it is added.
func modifyExtension(t *testing.T, cert *x509.Certificate, oid asn1.ObjectIdentifier, value []byte, critical bool) {
	t.Helper()
	for i, ext := range cert.Extensions {
		if ext.Id.Equal(oid) {
			cert.Extensions[i].Critical = critical
			cert.Extensions[i].Value = value
			return
		}
	}

	// Extension not found, so add it.
	ext := pkix.Extension{
		Id:       oid,
		Critical: critical,
		Value:    value,
	}
	cert.Extensions = append(cert.Extensions, ext)
}

func TestToEKCertificate_Success(t *testing.T) {
	tests := []struct {
		name                                string
		modifyCertTemplate                  func(*testing.T, *x509.Certificate)
		wantHasEkcExtendedKeyUsage          bool
		wantUnhandledCriticalExtensionsOIDs []asn1.ObjectIdentifier
	}{
		{
			name: "HasEkcExtendedKeyUsage is true",
			modifyCertTemplate: func(t *testing.T, cert *x509.Certificate) {
				cert.UnknownExtKeyUsage = []asn1.ObjectIdentifier{oid.EKCertificate}
			},
			wantHasEkcExtendedKeyUsage: true,
		},
		{
			name: "HasEkcExtendedKeyUsage is false",
			modifyCertTemplate: func(t *testing.T, cert *x509.Certificate) {
				cert.UnknownExtKeyUsage = []asn1.ObjectIdentifier{}
			},
			wantHasEkcExtendedKeyUsage: false,
		},
		{
			name: "Unhandled critical extension",
			modifyCertTemplate: func(t *testing.T, cert *x509.Certificate) {
				// Use empty subject, make the SubjectAltName extension critical, and
				// add an unhandled critical extension.
				cert.Subject = pkix.Name{}
				for i, ext := range cert.ExtraExtensions {
					if ext.Id.Equal(oid.SubjectAltName) {
						cert.ExtraExtensions[i].Critical = true
					}
				}
				cert.ExtraExtensions = append(cert.ExtraExtensions, pkix.Extension{
					Id:       asn1.ObjectIdentifier{1, 2, 3, 4, 5},
					Critical: true,
					Value:    []byte("test"),
				})
			},
			wantHasEkcExtendedKeyUsage:          true,
			wantUnhandledCriticalExtensionsOIDs: []asn1.ObjectIdentifier{{1, 2, 3, 4, 5}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cert := setupTestCert(t, test.modifyCertTemplate)
			ekCert, err := ToEKCertificate(cert)
			if err != nil {
				t.Fatalf("ToEKCertificate() returned an unexpected error: %v", err)
			}

			if ekCert.Certificate != cert {
				t.Errorf("ToEKCertificate() Certificate = %v, want: %v", ekCert.Certificate, cert)
			}

			if ekCert.TpmManufacturer != SAN.DirectoryNames[0].ExtraNames[0].Value {
				t.Errorf("ToEKCertificate() TPMManufacturer = %v, want: %v", ekCert.TpmManufacturer, SAN.DirectoryNames[0].ExtraNames[0].Value)
			}

			if ekCert.TpmModel != SAN.DirectoryNames[0].ExtraNames[1].Value {
				t.Errorf("ToEKCertificate() TPMModel = %v, want: %v", ekCert.TpmModel, SAN.DirectoryNames[0].ExtraNames[1].Value)
			}

			if ekCert.TpmVersion != SAN.DirectoryNames[0].ExtraNames[2].Value {
				t.Errorf("ToEKCertificate() TPMVersion = %v, want: %v", ekCert.TpmVersion, SAN.DirectoryNames[0].ExtraNames[2].Value)
			}

			if ekCert.TpmSpecification != (tpmSpec) {
				t.Errorf("ToEKCertificate() TpmSpecification is %v, want %v", ekCert.TpmSpecification, tpmSpec)
			}

			if test.wantHasEkcExtendedKeyUsage != ekCert.HasEkcExtendedKeyUsage {
				t.Errorf("ToEKCertificate() HasEkcExtendedKeyUsage = %v, want: %v", ekCert.HasEkcExtendedKeyUsage, test.wantHasEkcExtendedKeyUsage)
			}

			sortOIDs := cmpopts.SortSlices(func(a, b asn1.ObjectIdentifier) bool { return a.String() < b.String() })
			if diff := cmp.Diff(test.wantUnhandledCriticalExtensionsOIDs, ekCert.UnhandledCriticalExtensions, cmpopts.EquateEmpty(), sortOIDs); diff != "" {
				t.Errorf("ToEKCertificate() UnhandledCriticalExtensions differs (-want +got):\n%s", diff)
			}
		})
	}
}

func TestToEKCertificate_FailuresTests(t *testing.T) {
	tests := []struct {
		name       string
		modifyCert func(*testing.T, *x509.Certificate)
		wantErr    error
	}{
		{
			name: "Version is 2 (failure)",
			modifyCert: func(t *testing.T, cert *x509.Certificate) {
				cert.Version = 2
			},
			wantErr: errors.New("Invalid version of EK certificate: 2"),
		},
		{
			name: "SerialNumber is zero (failure)",
			modifyCert: func(t *testing.T, cert *x509.Certificate) {
				cert.SerialNumber = big.NewInt(0)
			},
			wantErr: errors.New("SerialNumber is not a positive integer"),
		},
		{
			name: "SerialNumber negative (failure)",
			modifyCert: func(t *testing.T, cert *x509.Certificate) {
				cert.SerialNumber = big.NewInt(-1)
			},
			wantErr: errors.New("SerialNumber is not a positive integer"),
		},
		{
			name: "SerialNumber nil (failure)",
			modifyCert: func(t *testing.T, cert *x509.Certificate) {
				cert.SerialNumber = nil
			},
			wantErr: errors.New("SerialNumber is nil, expected a positive integer"),
		},
		{
			name: "Issuer is empty (failure)",
			modifyCert: func(t *testing.T, cert *x509.Certificate) {
				cert.RawIssuer = []byte{0x30, 0x00}
			},
			wantErr: errors.New("Issuer is empty"),
		},
		{
			name: "BasicConstraints not set (failure)",
			modifyCert: func(t *testing.T, cert *x509.Certificate) {
				cert.BasicConstraintsValid = false
				cert.IsCA = false
			},
			wantErr: errors.New("Basic Constraints are not valid or it is a CA certificate"),
		},
		{
			name: "BasicConstraints is set but cert is a CA (failure)",
			modifyCert: func(t *testing.T, cert *x509.Certificate) {
				cert.BasicConstraintsValid = true
				cert.IsCA = true
			},
			wantErr: errors.New("Basic Constraints are not valid or it is a CA certificate"),
		},
		{
			name: "BasicConstraints is not critical (failure)",
			modifyCert: func(t *testing.T, cert *x509.Certificate) {
				for i, ext := range cert.Extensions {
					if ext.Id.Equal(oidBasicConstraints) {
						cert.Extensions[i].Critical = false
					}
				}
			},
			wantErr: errors.New("Extension \"Basic Constraints\" is not critical, supposed to be critical"),
		},
		{
			name: "SAN is not critical when Subject is empty (failure)",
			modifyCert: func(t *testing.T, cert *x509.Certificate) {
				cert.RawSubject = []byte{0x30, 0x00}
				for i, ext := range cert.Extensions {
					if ext.Id.Equal(oid.SubjectAltName) {
						cert.Extensions[i].Critical = false
					}
				}
			},
			wantErr: errors.New("SubjectAltName extension must be critical when Subject is not present"),
		},
		{
			name: "MUST extension is missing (failure)",
			modifyCert: func(t *testing.T, cert *x509.Certificate) {
				cert.Extensions = []pkix.Extension{}
			},
			wantErr: errors.New("Extension SubjectAltName is missing"),
		},
		{
			name: "AuthorityKeyId empty (failure)",
			modifyCert: func(t *testing.T, cert *x509.Certificate) {
				cert.AuthorityKeyId = []byte{}
			},
			wantErr: errors.New("Authority Key ID is missing"),
		},
		{
			name: "Authority Key Identifier is critical (failure)",
			modifyCert: func(t *testing.T, cert *x509.Certificate) {
				modifyExtension(t, cert, oidAuthorityKeyID, []byte{0x30, 0x00}, true)
			},
			wantErr: errors.New("Extension \"Authority Key Identifier\" is critical, supposed to be non-critical"),
		},
		{
			name: "KeyUsage not set (failure)",
			modifyCert: func(t *testing.T, cert *x509.Certificate) {
				cert.PublicKeyAlgorithm = x509.RSA
				cert.KeyUsage = 0
			},
			wantErr: errors.New("KeyUsage field is not set"),
		},
		{
			name: "KeyUsageKeyEncipherment not set for RSA (failure)",
			modifyCert: func(t *testing.T, cert *x509.Certificate) {
				cert.PublicKeyAlgorithm = x509.RSA
				cert.KeyUsage = x509.KeyUsageKeyAgreement
			},
			wantErr: errors.New("KeyUsageKeyEncipherment is not set for RSA public key type"),
		},
		{
			name: "KeyUsageKeyAgreement not set for ECDSA (failure)",
			modifyCert: func(t *testing.T, cert *x509.Certificate) {
				cert.PublicKeyAlgorithm = x509.ECDSA
				cert.KeyUsage = x509.KeyUsageKeyEncipherment
			},
			wantErr: errors.New("KeyUsageKeyAgreement is not set for ECDSA public key type"),
		},
		{
			name: "Key Usage is not critical (failure)",
			modifyCert: func(t *testing.T, cert *x509.Certificate) {
				for i, ext := range cert.Extensions {
					if ext.Id.Equal(oidKeyUsage) {
						cert.Extensions[i].Critical = false
					}
				}
			},
			wantErr: errors.New("Extension \"Key Usage\" is not critical, supposed to be critical"),
		},
		{
			name: "CertificatePolicies present but empty PolicyIdentifiers (failure)",
			modifyCert: func(t *testing.T, cert *x509.Certificate) {
				modifyExtension(t, cert, oid.CertificatePolicies, []byte{0x30, 0x00}, true)
				cert.PolicyIdentifiers = []asn1.ObjectIdentifier{}
			},
			wantErr: errors.New("Certificate Policies should contain at least 1 policy identifier if the extension is present"),
		},
		{
			name: "AuthorityInfoAccess is critical (failure)",
			modifyCert: func(t *testing.T, cert *x509.Certificate) {
				modifyExtension(t, cert, oidAuthorityInfoAccess, []byte{0x30, 0x00}, true)
			},
			wantErr: errors.New("Extension \"Authority Info Access\" is critical, supposed to be non-critical"),
		},
		{
			name: "CRLDistributionPoints is critical (failure)",
			modifyCert: func(t *testing.T, cert *x509.Certificate) {
				modifyExtension(t, cert, oidCRLDistributionPoints, []byte{0x30, 0x00}, true)
			},
			wantErr: errors.New("Extension \"CRL Distribution Points\" is critical, supposed to be non-critical"),
		},
		{
			name: "ExtendedKeyUsage is critical (failure)",
			modifyCert: func(t *testing.T, cert *x509.Certificate) {
				modifyExtension(t, cert, oidExtendedKeyUsage, []byte{0x30, 0x00}, true)
			},
			wantErr: errors.New("Extension \"Extended Key Usage\" is critical, supposed to be non-critical"),
		},
		{
			name: "SubjectKeyIdentifier is critical (failure)",
			modifyCert: func(t *testing.T, cert *x509.Certificate) {
				modifyExtension(t, cert, oidSubjectKeyIdentifier, []byte{0x30, 0x00}, true)
			},
			wantErr: errors.New("Extension \"Subject Key Identifier\" is critical, supposed to be non-critical"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cert := setupTestCert(t, nil)
			test.modifyCert(t, cert)
			_, err := ToEKCertificate(cert)

			if err == nil {
				t.Fatalf("ToEKCertificate() succeeded unexpectedly, want error: %v", test.wantErr)
			}

			if err.Error() != test.wantErr.Error() {
				t.Fatalf("ToEKCertificate() error = %v, want error: %v", err, test.wantErr)
			}
		})
	}
}
