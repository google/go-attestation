package attributecert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"
)

// signingParamsForKey returns the signature algorithm and its Algorithm
// Identifier to use for signing, based on the key type.
// Shamelessly adapted from stdlib x509.go
func signingParamsForKey(key crypto.Signer) (*signatureAlgorithmDetail, error) {
	var pubType x509.PublicKeyAlgorithm
	var sigAlgo x509.SignatureAlgorithm

	switch pub := key.Public().(type) {
	case *rsa.PublicKey:
		pubType = x509.RSA
		sigAlgo = x509.SHA256WithRSA

	case *ecdsa.PublicKey:
		pubType = x509.ECDSA
		switch pub.Curve {
		case elliptic.P224(), elliptic.P256():
			sigAlgo = x509.ECDSAWithSHA256
		case elliptic.P384():
			sigAlgo = x509.ECDSAWithSHA384
		case elliptic.P521():
			sigAlgo = x509.ECDSAWithSHA512
		default:
			return nil, errors.New("x509: unsupported elliptic curve")
		}

	case ed25519.PublicKey:
		pubType = x509.Ed25519
		sigAlgo = x509.PureEd25519

	default:
		return nil, errors.New("x509: only RSA, ECDSA and Ed25519 keys supported")
	}

	for _, details := range signatureAlgorithmDetails {
		if details.algo == sigAlgo {
			if details.pubKeyAlgo != pubType {
				return nil, errors.New("x509: requested SignatureAlgorithm does not match private key type")
			}
			if details.hash == crypto.MD5 {
				return nil, errors.New("x509: signing with MD5 is not supported")
			}

			return &details, nil
		}
	}

	return nil, errors.New("x509: unknown SignatureAlgorithm")
}

// Based on signTBS() from stdlib x509.go
func signTBS(tbs []byte, key crypto.Signer, sigDetails signatureAlgorithmDetail, rand io.Reader) ([]byte, error) {
	hashFunc := sigDetails.hash.HashFunc()

	var opts crypto.SignerOpts = hashFunc
	if sigDetails.isRSAPSS {
		opts = &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       hashFunc,
		}
	}

	if hashFunc != 0 {
		h := hashFunc.New()
		if _, err := h.Write(tbs); err != nil {
			return nil, err
		}
		tbs = h.Sum(nil)
	}
	return key.Sign(rand, tbs, opts)
}

// nameToGeneralNames converts a x509 Name (as raw bytes) to a GeneralNames (as
// a asn1.RawValue).
func nameToGeneralNames(name []byte) (*asn1.RawValue, error) {
	gn := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        4,
		IsCompound: true,
		Bytes:      name,
	}
	gnBytes, err := asn1.Marshal(gn)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal general name: %w", err)
	}

	issuer := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      gnBytes,
	}
	return &issuer, nil
}

// CreateAttributeCertificate creates a new attribute certificate.
// `holderIssuerName` is the DER encoded x509 Name of the holder issuer.
//
// Currently this only supports creating an attribute certificate with the bare minimum
// fields to get it to parse and pass tests, it doesn't populate any attributes or extensions.
func CreateAttributeCertificate(holderIssuerName []byte, holderSerial *big.Int, notBefore, notAfter time.Time, signingCert *x509.Certificate, priv any) ([]byte, error) {
	if len(holderIssuerName) == 0 {
		return nil, errors.New("holder issuer name cannot be empty")
	}
	if holderSerial == nil || holderSerial.Cmp(big.NewInt(0)) == 0 {
		return nil, errors.New("subject certificate serial number cannot be nil")
	}
	if priv == nil {
		return nil, errors.New("signer cannot be nil")
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, errors.New("x509: certificate private key does not implement crypto.Signer")
	}
	if signingCert == nil {
		return nil, errors.New("signing certificate cannot be nil")
	}
	var serialNumber *big.Int
	// Generate a serial number following RFC 5280, Section 4.1.2.2 if one
	// is not provided. The serial number must be positive and at most 20
	// octets *when encoded*.
	serialBytes := make([]byte, 20)
	if _, err := io.ReadFull(rand.Reader, serialBytes); err != nil {
		return nil, fmt.Errorf("failed to generate random serial number: %w", err)
	}
	// If the top bit is set, the serial will be padded with a leading zero
	// byte during encoding, so that it's not interpreted as a negative
	// integer. This padding would make the serial 21 octets so we clear the
	// top bit to ensure the correct length in all cases.
	serialBytes[0] &= 0b0111_1111
	serialNumber = new(big.Int).SetBytes(serialBytes)

	// Determine the signature algorithm
	sigDetails, err := signingParamsForKey(signer)
	if err != nil {
		return nil, fmt.Errorf("failed to determine signature algorithm: %w", err)
	}
	algID := pkix.AlgorithmIdentifier{
		Algorithm:  sigDetails.oid,
		Parameters: sigDetails.params,
	}

	holderIssuer, err := nameToGeneralNames(holderIssuerName)
	if err != nil {
		return nil, fmt.Errorf("failed to create holder issuer: %w", err)
	}

	issuer, err := nameToGeneralNames(signingCert.RawSubject)
	if err != nil {
		return nil, fmt.Errorf("failed to create issuer: %w", err)
	}

	tbsCert := tbsAttributeCertificate{
		Version:            1, // v2
		SerialNumber:       serialNumber,
		SignatureAlgorithm: algID,
		Holder: holder{
			BaseCertificateID: issuerSerial{
				Issuer: *holderIssuer,
				Serial: holderSerial,
			},
		},
		Issuer: attCertIssuer{
			IssuerName: *issuer,
		},
		Validity: validity{
			NotBefore: notBefore,
			NotAfter:  notAfter,
		},
		Attributes: []attribute{},
		Extensions: []pkix.Extension{},
	}

	// Marshal the tbsCertificate
	tbsCertBytes, err := asn1.Marshal(tbsCert)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal tbsCertificate: %w", err)
	}
	// Sign the tbsCertificate
	signature, err := signTBS(tbsCertBytes, signer, *sigDetails, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to sign tbsCertificate: %w", err)
	}
	// Assemble the full attribute certificate
	attributeCert := attributeCertificate{
		TBSAttributeCertificate: tbsCert,
		SignatureAlgorithm:      algID,
		SignatureValue:          asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	}

	// Marshal the full attribute certificate
	certBytes, err := asn1.Marshal(attributeCert)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal attribute certificate: %w", err)
	}
	return certBytes, nil
}

// CreateAttributeCertificateFor creates a new attribute certificate for the
// given subject certificate. See CreateAttributeCertificate for more details.
func CreateAttributeCertificateFor(subjectCert *x509.Certificate, notBefore, notAfter time.Time, signingCert *x509.Certificate, priv any) ([]byte, error) {
	if subjectCert == nil {
		return nil, errors.New("subject certificate cannot be nil")
	}

	return CreateAttributeCertificate(subjectCert.RawIssuer, subjectCert.SerialNumber, notBefore, notAfter, signingCert, priv)
}
