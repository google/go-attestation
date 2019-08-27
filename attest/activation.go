package attest

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"

	tpm1 "github.com/google/go-tpm/tpm"
	"github.com/google/go-tpm/tpm2"

	// TODO(jsonp): Move activation generation code to internal package.
	"github.com/google/go-tpm/tpm2/credactivation"
	"github.com/google/go-tspi/verification"
)

const (
	// minRSABits is the minimum accepted bit size of an RSA key.
	minRSABits = 2048
	// activationSecretLen is the size in bytes of the generated secret
	// which is generated for credential activation.
	activationSecretLen = 32
	// symBlockSize is the block size used for symmetric ciphers used
	// when generating the credential activation challenge.
	symBlockSize = 16
	// tpm20GeneratedMagic is a magic tag when can only be present on a
	// TPM structure if the structure was generated wholly by the TPM.
	tpm20GeneratedMagic = 0xff544347
)

func cryptoHash(h tpm2.Algorithm) (crypto.Hash, error) {
	switch h {
	case tpm2.AlgSHA1:
		return crypto.SHA1, nil
	case tpm2.AlgSHA256:
		return crypto.SHA256, nil
	case tpm2.AlgSHA384:
		return crypto.SHA384, nil
	case tpm2.AlgSHA512:
		return crypto.SHA512, nil
	default:
		return crypto.Hash(0), fmt.Errorf("unsupported signature digest: %v", h)
	}
}

// ActivationParameters encapsulates the inputs for activating an AIK.
type ActivationParameters struct {
	// TPMVersion holds the version of the TPM, either 1.2 or 2.0.
	TPMVersion TPMVersion

	// EK, the endorsement key, describes an asymmetric key who's
	// private key is permenantly bound to the TPM.
	//
	// Activation will verify that the provided EK is held on the same
	// TPM as the AIK. However, it is the callers responsibility to
	// ensure the EK they provide corresponds to the the device which
	// they are trying to associate the AIK with.
	EK crypto.PublicKey

	// AIK, the Attestation Identity Key, describes the properties of
	// an asymmetric key (managed by the TPM) which signs attestation
	// structures.
	// The values from this structure can be obtained by calling
	// Parameters() on an attest.AIK.
	AIK AttestationParameters

	// Rand is a source of randomness to generate a seed and secret for the
	// challenge.
	//
	// If nil, this defaults to crypto.Rand.
	Rand io.Reader
}

// checkAIKParameters examines properties of an AIK and a creation
// attestation, to determine if it is suitable for use as an attestation key.
func (p *ActivationParameters) checkAIKParameters() error {
	switch p.TPMVersion {
	case TPMVersion12:
		return p.checkTPM12AIKParameters()

	case TPMVersion20:
		return p.checkTPM20AIKParameters()

	default:
		return fmt.Errorf("TPM version %d not supported", p.TPMVersion)
	}
}

func (p *ActivationParameters) checkTPM12AIKParameters() error {
	// TODO(jsonp): Implement helper to parse public blobs, ie:
	//   func ParsePublic(publicBlob []byte) (crypto.Public, error)

	pub, err := tpm1.UnmarshalPubRSAPublicKey(p.AIK.Public)
	if err != nil {
		return fmt.Errorf("unmarshalling public key: %v", err)
	}
	if bits := pub.Size() * 8; bits < minRSABits {
		return fmt.Errorf("attestation key too small: must be at least %d bits but was %d bits", minRSABits, bits)
	}
	return nil
}

func (p *ActivationParameters) checkTPM20AIKParameters() error {
	if len(p.AIK.CreateSignature) < 8 {
		return fmt.Errorf("signature is too short to be valid: only %d bytes", len(p.AIK.CreateSignature))
	}

	pub, err := tpm2.DecodePublic(p.AIK.Public)
	if err != nil {
		return fmt.Errorf("DecodePublic() failed: %v", err)
	}
	_, err = tpm2.DecodeCreationData(p.AIK.CreateData)
	if err != nil {
		return fmt.Errorf("DecodeCreationData() failed: %v", err)
	}
	att, err := tpm2.DecodeAttestationData(p.AIK.CreateAttestation)
	if err != nil {
		return fmt.Errorf("DecodeAttestationData() failed: %v", err)
	}
	if att.Type != tpm2.TagAttestCreation {
		return fmt.Errorf("attestation does not apply to creation data, got tag %x", att.Type)
	}

	// TODO: Support ECC AIKs.
	switch pub.Type {
	case tpm2.AlgRSA:
		if pub.RSAParameters.KeyBits < minRSABits {
			return fmt.Errorf("attestation key too small: must be at least %d bits but was %d bits", minRSABits, pub.RSAParameters.KeyBits)
		}
	default:
		return fmt.Errorf("public key of alg 0x%x not supported", pub.Type)
	}

	// Compute & verify that the creation data matches the digest in the
	// attestation structure.
	nameHashConstructor, err := pub.NameAlg.HashConstructor()
	if err != nil {
		return fmt.Errorf("HashConstructor() failed: %v", err)
	}
	h := nameHashConstructor()
	h.Write(p.AIK.CreateData)
	if !bytes.Equal(att.AttestedCreationInfo.OpaqueDigest, h.Sum(nil)) {
		return errors.New("attestation refers to different public key")
	}

	// Make sure the AIK has sane key parameters (Attestation can be faked if an AIK
	// can be used for arbitrary signatures).
	// We verify the following:
	// - Key is TPM backed.
	// - Key is TPM generated.
	// - Key is a restricted key (means it cannot do arbitrary signing/decrypt ops).
	// - Key cannot be duplicated.
	// - Key was generated by a call to TPM_Create*.
	if att.Magic != tpm20GeneratedMagic {
		return errors.New("creation attestation was not produced by a TPM")
	}
	if (pub.Attributes & tpm2.FlagFixedTPM) == 0 {
		return errors.New("AIK is exportable")
	}
	if ((pub.Attributes & tpm2.FlagRestricted) == 0) || ((pub.Attributes & tpm2.FlagFixedParent) == 0) || ((pub.Attributes & tpm2.FlagSensitiveDataOrigin) == 0) {
		return errors.New("provided key is not limited to attestation")
	}

	// Verify the attested creation name matches what is computed from
	// the public key.
	match, err := att.AttestedCreationInfo.Name.MatchesPublic(pub)
	if err != nil {
		return err
	}
	if !match {
		return errors.New("creation attestation refers to a different key")
	}

	// Check the signature over the attestation data verifies correctly.
	pk := rsa.PublicKey{E: int(pub.RSAParameters.Exponent()), N: pub.RSAParameters.Modulus()}
	signHashConstructor, err := pub.RSAParameters.Sign.Hash.HashConstructor()
	if err != nil {
		return err
	}
	hsh := signHashConstructor()
	hsh.Write(p.AIK.CreateAttestation)
	verifyHash, err := cryptoHash(pub.RSAParameters.Sign.Hash)
	if err != nil {
		return err
	}

	if len(p.AIK.CreateSignature) < 8 {
		return fmt.Errorf("signature invalid: length of %d is shorter than 8", len(p.AIK.CreateSignature))
	}

	sig, err := tpm2.DecodeSignature(bytes.NewBuffer(p.AIK.CreateSignature))
	if err != nil {
		return fmt.Errorf("DecodeSignature() failed: %v", err)
	}

	if err := rsa.VerifyPKCS1v15(&pk, verifyHash, hsh.Sum(nil), sig.RSA.Signature); err != nil {
		return fmt.Errorf("could not verify attestation: %v", err)
	}

	return nil
}

// Generate returns a credential activation challenge, which can be provided
// to the TPM to verify the AIK parameters given are authentic & the AIK
// is present on the same TPM as the EK.
//
// The caller is expected to verify the secret returned from the TPM as
// as result of calling ActivateCredential() matches the secret returned here.
// The caller should use subtle.ConstantTimeCompare to avoid potential
// timing attack vectors.
func (p *ActivationParameters) Generate() (secret []byte, ec *EncryptedCredential, err error) {
	if err := p.checkAIKParameters(); err != nil {
		return nil, nil, err
	}

	if p.EK == nil {
		return nil, nil, errors.New("no EK provided")
	}

	rnd, secret := p.Rand, make([]byte, activationSecretLen)
	if rnd == nil {
		rnd = rand.Reader
	}
	if _, err = io.ReadFull(rnd, secret); err != nil {
		return nil, nil, fmt.Errorf("error generating activation secret: %v", err)
	}

	switch p.TPMVersion {
	case TPMVersion12:
		ec, err = p.generateChallengeTPM12(rnd, secret)
	case TPMVersion20:
		ec, err = p.generateChallengeTPM20(secret)
	default:
		return nil, nil, fmt.Errorf("unrecognised TPM version: %v", p.TPMVersion)
	}

	if err != nil {
		return nil, nil, err
	}
	return secret, ec, nil
}

func (p *ActivationParameters) generateChallengeTPM20(secret []byte) (*EncryptedCredential, error) {
	att, err := tpm2.DecodeAttestationData(p.AIK.CreateAttestation)
	if err != nil {
		return nil, fmt.Errorf("DecodeAttestationData() failed: %v", err)
	}
	cred, encSecret, err := credactivation.Generate(att.AttestedCreationInfo.Name.Digest, p.EK, symBlockSize, secret)
	if err != nil {
		return nil, fmt.Errorf("credactivation.Generate() failed: %v", err)
	}

	return &EncryptedCredential{
		Credential: cred,
		Secret:     encSecret,
	}, nil
}

func (p *ActivationParameters) generateChallengeTPM12(rand io.Reader, secret []byte) (*EncryptedCredential, error) {
	pk, ok := p.EK.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("got EK of type %T, want an RSA key", p.EK)
	}

	var (
		cred, encSecret []byte
		err             error
	)
	if p.AIK.UseTCSDActivationFormat {
		cred, encSecret, err = verification.GenerateChallengeEx(pk, p.AIK.Public, secret)
	} else {
		cred, encSecret, err = generateChallenge12(rand, pk, p.AIK.Public, secret)
	}

	if err != nil {
		return nil, fmt.Errorf("challenge generation failed: %v", err)
	}
	return &EncryptedCredential{
		Credential: cred,
		Secret:     encSecret,
	}, nil
}
