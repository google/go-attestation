// Copyright 2026 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

package attest

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"

	"github.com/google/go-tpm/tpm2"
)

// HMAC represents a SHA-256 HMAC digest, strictly bound to the SHA-256 output size (32 bytes).
type HMAC [sha256.Size]byte

func generateRestrictedHMACKey() (tpm2.TPMTPublic, tpm2.TPMTSensitive, HMAC) {
	var hmacKeyBytes HMAC
	rand.Read(hmacKeyBytes[:])

	obfuscate := make([]byte, 32)
	rand.Read(obfuscate)

	h := sha256.New()
	h.Write(obfuscate)
	h.Write(hmacKeyBytes[:])

	hmacPub := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			UserWithAuth: true,
			NoDA:         true,
			Restricted:   true,
			SignEncrypt:  true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash,
			&tpm2.TPMSKeyedHashParms{
				Scheme: tpm2.TPMTKeyedHashScheme{
					Scheme: tpm2.TPMAlgHMAC,
					Details: tpm2.NewTPMUSchemeKeyedHash(tpm2.TPMAlgHMAC,
						&tpm2.TPMSSchemeHMAC{
							HashAlg: tpm2.TPMAlgSHA256,
						}),
				},
			}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgKeyedHash, &tpm2.TPM2BDigest{Buffer: h.Sum(nil)}),
	}

	sensitive := tpm2.TPMTSensitive{
		SensitiveType: tpm2.TPMAlgKeyedHash,
		SeedValue: tpm2.TPM2BDigest{
			Buffer: obfuscate,
		},
		Sensitive: tpm2.NewTPMUSensitiveComposite(tpm2.TPMAlgKeyedHash, &tpm2.TPM2BSensitiveData{
			Buffer: hmacKeyBytes[:],
		}),
	}

	return hmacPub, sensitive, hmacKeyBytes
}

// GenerateEkChallenge generates a challenge that can only be solved by a TPM
// possessing the private key corresponding to the provided Endorsement Key (EK).
//
// It generates an ephemeral restricted HMAC key, duplicates it under the EK's
// public key.
//
// The returned DecryptionEkChallenge should be sent to the client. The returned
// HMAC key bytes (32 bytes) must be retained by the challenger (CA) to verify
// // the client's response later.
func GenerateEkChallenge(ekPublic crypto.PublicKey) (*DecryptionEkChallenge, *HMAC, error) {
	// Reconstruct EK public area in v0/tpm2 format from pub (crypto.PublicKey)
	var ekPubContents tpm2.TPMTPublic

	switch ekPub := ekPublic.(type) {
	case *rsa.PublicKey:
		u := tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: ekPub.N.Bytes(),
			},
		)
		ekPubContents = tpm2.RSAEKTemplate
		ekPubContents.Unique = u

	case *ecdsa.PublicKey:
		var size int
		var curveID tpm2.TPMECCCurve
		switch ekPub.Curve {
		case elliptic.P256():
			size = 32
			curveID = tpm2.TPMECCNistP256
		case elliptic.P384():
			size = 48
			curveID = tpm2.TPMECCNistP384
		case elliptic.P521():
			size = 66
			curveID = tpm2.TPMECCNistP521
		default:
			return nil, nil, fmt.Errorf("unsupported ECC curve: %v", ekPub.Curve.Params().Name)
		}
		xBytes := make([]byte, size)
		yBytes := make([]byte, size)
		ekPub.X.FillBytes(xBytes)
		ekPub.Y.FillBytes(yBytes)

		u := tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{Buffer: xBytes},
				Y: tpm2.TPM2BECCParameter{Buffer: yBytes},
			},
		)
		ekPubContents = tpm2.ECCEKTemplate
		ekPubContents.Parameters = tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					KeyBits: tpm2.NewTPMUSymKeyBits(
						tpm2.TPMAlgAES,
						tpm2.TPMKeyBits(128),
					),
					Mode: tpm2.NewTPMUSymMode(
						tpm2.TPMAlgAES,
						tpm2.TPMAlgCFB,
					),
				},
				CurveID: curveID,
			},
		)
		ekPubContents.Unique = u

	default:
		return nil, nil, fmt.Errorf("unsupported EK public key type: %T", ekPublic)
	}

	// Import EK public key as encapsulation key
	encap, err := tpm2.ImportEncapsulationKey(&ekPubContents)
	if err != nil {
		return nil, nil, fmt.Errorf("ImportEncapsulationKey() failed: %v", err)
	}

	hmacPub, sensitive, hmacKeyBytes := generateRestrictedHMACKey()

	hmacName, err := tpm2.ObjectName(&hmacPub)
	if err != nil {
		return nil, nil, fmt.Errorf("ObjectName() failed: %v", err)
	}

	// Duplicate the HMAC key under EK
	duplicate, inSymSeed, err := tpm2.CreateDuplicate(rand.Reader, encap, hmacName.Buffer, tpm2.Marshal(sensitive))
	if err != nil {
		return nil, nil, fmt.Errorf("CreateDuplicate() failed: %v", err)
	}

	challenge := &DecryptionEkChallenge{
		ObjectPublic: tpm2.Marshal(hmacPub),
		Duplicate:    duplicate,
		InSymSeed:    inSymSeed,
	}
	return challenge, &hmacKeyBytes, nil
}

// VerifySolvedDecryptionEkChallenge verifies that the client has successfully solved the EK
// decryption challenge and certified the correct Attestation Key (AK).
//
// It unmarshals the AK public area, verifies the HMAC signature over the attestation data using
// the challenge HMAC key, and checks that the certified name matches the AK's name.
//
// akPubData is the marshaled TPMT_PUBLIC representation of the AK.
// certParams contains the attestation data and signature returned by the client.
// challengeHMACKey is the raw 32-byte HMAC key generated by GenerateEkChallenge.
func VerifySolvedDecryptionEkChallenge(akPubData []byte, certParams *CertificationParameters, challengeHMACKey HMAC) error {
	if certParams == nil {
		return fmt.Errorf("certParams is nil")
	}
	akPub, err := tpm2.Unmarshal[tpm2.TPMTPublic](akPubData)
	if err != nil {
		return fmt.Errorf("failed to unmarshal AK public area: %v", err)
	}

	akName, err := tpm2.ObjectName(akPub)
	if err != nil {
		return fmt.Errorf("failed to get AK name: %v", err)
	}

	signature, err := tpm2.Unmarshal[tpm2.TPMTSignature](certParams.CreateSignature)
	if err != nil {
		return fmt.Errorf("failed to unmarshal signature: %v", err)
	}

	hmac, err := signature.Signature.HMAC()
	if err != nil {
		return fmt.Errorf("failed to get signature: %v", err)
	}

	if err := verifyHMAC(certParams.CreateAttestation, hmac, challengeHMACKey); err != nil {
		return fmt.Errorf("failed to verify HMAC: %v", err)
	}

	attest, err := tpm2.Unmarshal[tpm2.TPMSAttest](certParams.CreateAttestation)
	if err != nil {
		return fmt.Errorf("failed to unmarshal attestation: %v", err)
	}

	if err := verifyAttest(attest); err != nil {
		return fmt.Errorf("failed to verify attestation: %v", err)
	}

	certify, err := attest.Attested.Certify()
	if err != nil {
		return fmt.Errorf("failed to certify: %v", err)
	}

	if err := verifyCertify(akName, certify); err != nil {
		return fmt.Errorf("failed to certify: %v", err)
	}
	return nil
}

func verifyHMAC(message []byte, ha *tpm2.TPMTHA, challengeHMACKey HMAC) error {
	if ha.HashAlg != tpm2.TPMAlgSHA256 {
		return fmt.Errorf("%v (expected SHA256)", ha.HashAlg)
	}

	if len(message) == 0 {
		return fmt.Errorf("message is empty")
	}
	// The HMAC is over SHA256(message).
	digest := sha256.Sum256(message)

	h := hmac.New(sha256.New, challengeHMACKey[:])
	h.Write(digest[:])
	if subtle.ConstantTimeCompare(ha.Digest, h.Sum(nil)) != 1 {
		return fmt.Errorf("invalid HMAC")
	}
	return nil
}

// verifyAttest checks that the attestation structure has valid data
func verifyAttest(attest *tpm2.TPMSAttest) error {
	if attest.Magic != tpm2.TPMGeneratedValue {
		return fmt.Errorf("unexpected prefix %0x", attest.Magic)
	}
	if attest.Type != tpm2.TPMSTAttestCertify {
		return fmt.Errorf("unexpected type %0x", attest.Type)
	}
	return nil
}

func verifyCertify(name *tpm2.TPM2BName, certifyInfo *tpm2.TPMSCertifyInfo) error {
	// Check that the certified Name is the same as we expected.
	if !bytes.Equal(name.Buffer, certifyInfo.Name.Buffer) {
		return fmt.Errorf("expected Name %x, certified Name was %x", name.Buffer, certifyInfo.Name.Buffer)
	}

	// We can't really check the QualifiedName here, since we don't have any
	// information about the object's parent. As a paranoid consistency check,
	// just make sure that QualifiedName doesn't match Name for some reason.
	if bytes.Equal(certifyInfo.QualifiedName.Buffer, certifyInfo.Name.Buffer) {
		return fmt.Errorf("QualifiedName unexpectedly matched Name")
	}

	return nil
}
