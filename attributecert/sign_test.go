package attributecert

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func bigIntComparer(x, y *big.Int) bool {
	if x == nil || y == nil {
		return x == y
	}
	return x.Cmp(y) == 0
}

// createKeyAndCert creates a key and self-signed certificate for the given template.
func createKeyAndCert(t *testing.T, template *x509.Certificate, parentTemplate *x509.Certificate) (crypto.Signer, *x509.Certificate) {
	t.Helper()
	// Generate a certificate for the attribute cert signer
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() failed: %v", err)
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parentTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate() failed: %v", err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("x509.ParseCertificate() failed: %v", err)
	}
	return key, cert
}

// signCert creates a certificate for the given template signed by the parent template.
func signCert(t *testing.T, template *x509.Certificate, parentTemplate *x509.Certificate, signer any) (crypto.Signer, *x509.Certificate) {
	t.Helper()
	// Generate a certificate for the attribute cert signer
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() failed: %v", err)
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parentTemplate, &key.PublicKey, signer)
	if err != nil {
		t.Fatalf("x509.CreateCertificate() failed: %v", err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("x509.ParseCertificate() failed: %v", err)
	}
	return key, cert
}

func TestCreateAttributeCertificate(t *testing.T) {
	// Generate a certificate for the attribute cert signer
	ACSignerCertTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Attribute Cert Signer",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	ACSignerKey, ACSignerCert := createKeyAndCert(t, ACSignerCertTemplate, ACSignerCertTemplate)

	// Generate a certificate for the EK cert signer
	EKSignerCertTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test EK Signer",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	EKSignerKey, EKSignerCert := createKeyAndCert(t, EKSignerCertTemplate, EKSignerCertTemplate)

	testCases := []struct {
		name          string
		subjectCert   *x509.Certificate
		signer        crypto.Signer
		expectError   bool
		addAttributes bool
	}{
		{
			name: "Basic Test",
			subjectCert: &x509.Certificate{
				SerialNumber: big.NewInt(2),
				Subject: pkix.Name{
					CommonName:   "Test EK",
					Organization: []string{"Test Org"},
				},
				NotBefore: time.Now().Add(-time.Hour),
				NotAfter:  time.Now().Add(time.Hour),
			},
			signer:      ACSignerKey,
			expectError: false,
		},
		{
			name: "Invalid Signer",
			subjectCert: &x509.Certificate{
				SerialNumber: big.NewInt(4),
				Subject: pkix.Name{
					CommonName:   "Test EK",
					Organization: []string{"Test Org"},
				},
				NotBefore: time.Now().Add(-time.Hour),
				NotAfter:  time.Now().Add(time.Hour),
			},
			signer:      nil,
			expectError: true,
		},
		{
			name: "Invalid Subject Cert",
			subjectCert: &x509.Certificate{
				SerialNumber: big.NewInt(0),
			},
			signer:      ACSignerKey,
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			// Generate a certificate for the test case
			_, subjectCert := signCert(t, tc.subjectCert, EKSignerCert, EKSignerKey)

			notBefore := time.Now().Add(-time.Hour)
			notAfter := time.Now().Add(time.Hour)
			attributeCertBytes, err := CreateAttributeCertificateFor(subjectCert, notBefore, notAfter, ACSignerCert, tc.signer)
			if tc.expectError {
				if err == nil {
					t.Fatalf("CreateAttributeCertificate expected an error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("CreateAttributeCertificate failed: %v", err)
			}

			parsedCert, err := ParseAttributeCertificate(attributeCertBytes)
			if err != nil {
				t.Fatalf("ParseAttributeCertificate failed: %v", err)
			}

			if parsedCert.SerialNumber.Cmp(big.NewInt(0)) == 0 {
				t.Errorf("Parsed certificate serial number is 0")
			}
			if !parsedCert.NotBefore.Before(time.Now()) {
				t.Errorf("Parsed certificate not before is in the past")
			}
			if !parsedCert.NotAfter.After(time.Now()) {
				t.Errorf("Parsed certificate not after is in the future")
			}
			if diff := cmp.Diff(parsedCert.Holder.Issuer, EKSignerCert.Subject); diff != "" {
				t.Errorf("Holder Issuer mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(parsedCert.Holder.Serial, tc.subjectCert.SerialNumber, cmp.Comparer(bigIntComparer)); diff != "" {
				t.Errorf("Holder Serial mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(parsedCert.Issuer, ACSignerCert.Subject); diff != "" {
				t.Errorf("Issuer mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
