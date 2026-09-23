package tpmsim

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// TestSigner bundles a CA private key (crypto.Signer) and its corresponding X.509 Certificate.
type TestSigner struct {
	Signer crypto.Signer
	Cert   *x509.Certificate
}

// PublicKey returns the public key associated with the TestSigner.
func (ts TestSigner) PublicKey() crypto.PublicKey {
	if ts.Signer == nil {
		return nil
	}
	return ts.Signer.Public()
}

var (
	staticRSASignerOnce sync.Once
	staticRSASignerVal  TestSigner

	staticEC256SignerOnce sync.Once
	staticEC256SignerVal  TestSigner
)

// DefaultTestSigner returns a reusable, fast RSA self-signed TestSigner.
func DefaultTestSigner() TestSigner {
	staticRSASignerOnce.Do(func() {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic("failed to generate static test RSA key: " + err.Error())
		}
		ts, err := NewTestSignerRSA("TPM Simulator Default RSA Test CA", priv)
		if err != nil {
			panic("failed to create default RSA test signer: " + err.Error())
		}
		staticRSASignerVal = ts
	})
	return staticRSASignerVal
}

// DefaultECTestSigner returns a reusable, fast ECDSA P-256 self-signed TestSigner.
func DefaultECTestSigner() TestSigner {
	staticEC256SignerOnce.Do(func() {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic("failed to generate static test P-256 key: " + err.Error())
		}
		ts, err := NewTestSignerEC("TPM Simulator Default ECDSA P256 Test CA", elliptic.P256(), priv)
		if err != nil {
			panic("failed to create default ECDSA test signer: " + err.Error())
		}
		staticEC256SignerVal = ts
	})
	return staticEC256SignerVal
}

// SelfSignedCATemplate constructs an x509.Certificate template for a CA certificate.
func SelfSignedCATemplate(commonName string) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"TPM Simulator Test CA"},
		},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

// NewTestSignerRSA constructs a TestSigner backed by an RSA key.
// If privKey is nil, a 2048-bit RSA key is generated.
func NewTestSignerRSA(commonName string, privKey *rsa.PrivateKey) (TestSigner, error) {
	var err error
	if privKey == nil {
		privKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return TestSigner{}, fmt.Errorf("rsa.GenerateKey: %w", err)
		}
	}
	tmpl := SelfSignedCATemplate(commonName)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, privKey.Public(), privKey)
	if err != nil {
		return TestSigner{}, fmt.Errorf("CreateCertificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return TestSigner{}, fmt.Errorf("ParseCertificate: %w", err)
	}
	return TestSigner{Signer: privKey, Cert: cert}, nil
}

// NewTestSignerEC constructs a TestSigner backed by an ECDSA key.
// If privKey is nil, a key for curve is generated. If curve is nil, P-256 is used.
func NewTestSignerEC(commonName string, curve elliptic.Curve, privKey *ecdsa.PrivateKey) (TestSigner, error) {
	var err error
	if curve == nil {
		curve = elliptic.P256()
	}
	if privKey == nil {
		privKey, err = ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return TestSigner{}, fmt.Errorf("ecdsa.GenerateKey: %w", err)
		}
	}
	tmpl := SelfSignedCATemplate(commonName)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, privKey.Public(), privKey)
	if err != nil {
		return TestSigner{}, fmt.Errorf("CreateCertificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return TestSigner{}, fmt.Errorf("ParseCertificate: %w", err)
	}
	return TestSigner{Signer: privKey, Cert: cert}, nil
}
