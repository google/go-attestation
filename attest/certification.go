// Copyright 2021 Google Inc.
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
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/legacy/tpm2/credactivation"
	"github.com/google/go-tpm/tpmutil"
)

// secureCurves represents a set of secure elliptic curves. For now,
// the selection is based on the key size only.
var secureCurves = map[tpm2.EllipticCurve]bool{
	tpm2.CurveNISTP256: true,
	tpm2.CurveNISTP384: true,
	tpm2.CurveNISTP521: true,
	tpm2.CurveBNP256:   true,
	tpm2.CurveBNP638:   true,
}

// CertificationParameters encapsulates the inputs for certifying an application key.
// Only TPM 2.0 is supported at this point.
type CertificationParameters struct {
	// Public represents the key's canonical encoding (a TPMT_PUBLIC structure).
	// It includes the public key and signing parameters.
	Public []byte
	// CreateData represents the properties of a TPM 2.0 key. It is encoded
	// as a TPMS_CREATION_DATA structure.
	CreateData []byte
	// CreateAttestation represents an assertion as to the details of the key.
	// It is encoded as a TPMS_ATTEST structure.
	CreateAttestation []byte
	// CreateSignature represents a signature of the CreateAttestation structure.
	// It is encoded as a TPMT_SIGNATURE structure.
	CreateSignature []byte
}

// VerifyOpts specifies options for the key certification's verification.
type VerifyOpts struct {
	// Public is the public key used to verify key ceritification.
	Public crypto.PublicKey
	// Hash is the hash function used for signature verification. It can be
	// extracted from the properties of the certifying key.
	Hash crypto.Hash
}

// ActivateOpts specifies options for the key certification's challenge generation.
type ActivateOpts struct {
	// EK, the endorsement key, describes an asymmetric key whose
	// private key is permanently bound to the TPM.
	//
	// Activation will verify that the provided EK is held on the same
	// TPM as the key we're certifying. However, it is the caller's responsibility to
	// ensure the EK they provide corresponds to the the device which
	// they are trying to associate the certified key with.
	EK crypto.PublicKey
	// VerifierKeyNameDigest is the name digest of the public key we're using to
	// verify the certification of the tpm-generated key being activated.
	// The verifier key (usually the AK) that owns this digest should be the same
	// key used in VerifyOpts.Public.
	// Use tpm2.Public.Name() to produce the digest for a provided key.
	VerifierKeyNameDigest *tpm2.HashValue
}

// NewActivateOpts creates options for use in generating an activation challenge for a certified key.
// The computed hash is the name digest of the public key used to verify the certification of our key.
func NewActivateOpts(verifierPubKey tpm2.Public, ek crypto.PublicKey) (*ActivateOpts, error) {
	pubName, err := verifierPubKey.Name()
	if err != nil {
		return nil, fmt.Errorf("unable to resolve a tpm2.Public Name struct from the given public key struct: %v", err)
	}

	return &ActivateOpts{
		EK:                    ek,
		VerifierKeyNameDigest: pubName.Digest,
	}, nil
}

// Verify verifies the TPM2-produced certification parameters checking whether:
// - the key length is secure
// - the attestation parameters matched the attested key
// - the key was TPM-generated and resides within TPM
// - the key can sign/decrypt outside-TPM objects
// - the signature is successfuly verified against the passed public key
// For now, it accepts only RSA verification keys.
func (p *CertificationParameters) Verify(opts VerifyOpts) error {
	pub, err := tpm2.DecodePublic(p.Public)
	if err != nil {
		return fmt.Errorf("DecodePublic() failed: %v", err)
	}
	att, err := tpm2.DecodeAttestationData(p.CreateAttestation)
	if err != nil {
		return fmt.Errorf("DecodeAttestationData() failed: %v", err)
	}
	if att.Type != tpm2.TagAttestCertify {
		return fmt.Errorf("attestation does not apply to certification data, got tag %x", att.Type)
	}

	switch pub.Type {
	case tpm2.AlgRSA:
		if pub.RSAParameters.KeyBits < minRSABits {
			return fmt.Errorf("attested key too small: must be at least %d bits but was %d bits", minRSABits, pub.RSAParameters.KeyBits)
		}
	case tpm2.AlgECC:
		if !secureCurves[pub.ECCParameters.CurveID] {
			return fmt.Errorf("attested key uses insecure curve")
		}
	default:
		return fmt.Errorf("public key of alg 0x%x not supported", pub.Type)
	}

	// Make sure the key has sane parameters (e.g., attestation can be faked if an AK
	// can be used for arbitrary signatures).
	// We verify the following:
	// - Key is TPM backed.
	// - Key is TPM generated.
	// - Key is not restricted (means it can do arbitrary signing/decrypt ops).
	// - Key cannot be duplicated.
	// - Key was generated by a call to TPM_Create*.
	if att.Magic != tpm20GeneratedMagic {
		return errors.New("creation attestation was not produced by a TPM")
	}
	if (pub.Attributes & tpm2.FlagFixedTPM) == 0 {
		return errors.New("provided key is exportable")
	}
	if (pub.Attributes & tpm2.FlagRestricted) != 0 {
		return errors.New("provided key is restricted")
	}
	if (pub.Attributes & tpm2.FlagFixedParent) == 0 {
		return errors.New("provided key can be duplicated to a different parent")
	}
	if (pub.Attributes & tpm2.FlagSensitiveDataOrigin) == 0 {
		return errors.New("provided key is not created by TPM")
	}

	// Verify the attested creation name matches what is computed from
	// the public key.
	match, err := att.AttestedCertifyInfo.Name.MatchesPublic(pub)
	if err != nil {
		return err
	}
	if !match {
		return errors.New("certification refers to a different key")
	}

	// Check the signature over the attestation data verifies correctly.
	// TODO: Support ECC certifying keys
	pk, ok := opts.Public.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("only RSA verification keys are supported")
	}
	if !opts.Hash.Available() {
		return fmt.Errorf("hash function is unavailable")
	}
	hsh := opts.Hash.New()
	hsh.Write(p.CreateAttestation)

	if len(p.CreateSignature) < 8 {
		return fmt.Errorf("signature invalid: length of %d is shorter than 8", len(p.CreateSignature))
	}

	sig, err := tpm2.DecodeSignature(bytes.NewBuffer(p.CreateSignature))
	if err != nil {
		return fmt.Errorf("DecodeSignature() failed: %v", err)
	}

	if err := rsa.VerifyPKCS1v15(pk, opts.Hash, hsh.Sum(nil), sig.RSA.Signature); err != nil {
		return fmt.Errorf("could not verify attestation: %v", err)
	}

	return nil
}

// Generate returns a credential activation challenge, which can be provided
// to the TPM to verify the AK parameters given are authentic & the AK
// is present on the same TPM as the EK.
//
// The caller is expected to verify the secret returned from the TPM as
// as result of calling ActivateCredential() matches the secret returned here.
// The caller should use subtle.ConstantTimeCompare to avoid potential
// timing attack vectors.
func (p *CertificationParameters) Generate(rnd io.Reader, verifyOpts VerifyOpts, activateOpts ActivateOpts) (secret []byte, ec *EncryptedCredential, err error) {
	if err := p.Verify(verifyOpts); err != nil {
		return nil, nil, err
	}

	if activateOpts.EK == nil {
		return nil, nil, errors.New("no EK provided")
	}

	secret = make([]byte, activationSecretLen)
	if rnd == nil {
		rnd = rand.Reader
	}
	if _, err = io.ReadFull(rnd, secret); err != nil {
		return nil, nil, fmt.Errorf("error generating activation secret: %v", err)
	}

	att, err := tpm2.DecodeAttestationData(p.CreateAttestation)
	if err != nil {
		return nil, nil, fmt.Errorf("DecodeAttestationData() failed: %v", err)
	}

	if att.Type != tpm2.TagAttestCertify {
		return nil, nil, fmt.Errorf("attestation does not apply to certify data, got %x", att.Type)
	}

	cred, encSecret, err := credactivation.Generate(activateOpts.VerifierKeyNameDigest, activateOpts.EK, symBlockSize, secret)
	if err != nil {
		return nil, nil, fmt.Errorf("credactivation.Generate() failed: %v", err)
	}

	return secret, &EncryptedCredential{
		Credential: cred,
		Secret:     encSecret,
	}, nil
}

// certify uses AK's handle and the passed signature scheme to certify the key
// with the `hnd` handle.
func certify(tpm io.ReadWriteCloser, hnd, akHnd tpmutil.Handle, qualifyingData []byte, scheme tpm2.SigScheme) (*CertificationParameters, error) {
	pub, _, _, err := tpm2.ReadPublic(tpm, hnd)
	if err != nil {
		return nil, fmt.Errorf("tpm2.ReadPublic() failed: %v", err)
	}
	public, err := pub.Encode()
	if err != nil {
		return nil, fmt.Errorf("could not encode public key: %v", err)
	}
	att, sig, err := tpm2.CertifyEx(tpm, "", "", hnd, akHnd, qualifyingData, scheme)
	if err != nil {
		return nil, fmt.Errorf("tpm2.Certify() failed: %v", err)
	}
	return &CertificationParameters{
		Public:            public,
		CreateAttestation: att,
		CreateSignature:   sig,
	}, nil
}
