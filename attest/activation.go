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

// secureCurves represents a set of secure elliptic curves. For now,
// the selection is based on the key size only.
var secureCurves = map[tpm2.EllipticCurve]bool{
	tpm2.CurveNISTP256: true,
	tpm2.CurveNISTP384: true,
	tpm2.CurveNISTP521: true,
	tpm2.CurveBNP256:   true,
	tpm2.CurveBNP638:   true,
}

// ActivationParameters encapsulates the inputs for activating an AK.
type ActivationParameters struct {
	// TPMVersion holds the version of the TPM, either 1.2 or 2.0.
	TPMVersion TPMVersion

	// EK, the endorsement key, describes an asymmetric key who's
	// private key is permenantly bound to the TPM.
	//
	// Activation will verify that the provided EK is held on the same
	// TPM as the AK. However, it is the callers responsibility to
	// ensure the EK they provide corresponds to the the device which
	// they are trying to associate the AK with.
	EK crypto.PublicKey

	// AK, the Attestation Key, describes the properties of
	// an asymmetric key (managed by the TPM) which signs attestation
	// structures.
	// The values from this structure can be obtained by calling
	// Parameters() on an attest.AK.
	AK AttestationParameters

	// Rand is a source of randomness to generate a seed and secret for the
	// challenge.
	//
	// If nil, this defaults to crypto.Rand.
	Rand io.Reader
}

// checkAKParameters examines properties of an AK and a creation
// attestation, to determine if it is suitable for use as an attestation key.
func (p *ActivationParameters) checkAKParameters() error {
	switch p.TPMVersion {
	case TPMVersion12:
		return p.checkTPM12AKParameters()

	case TPMVersion20:
		return p.checkTPM20AKParameters()

	default:
		return fmt.Errorf("TPM version %d not supported", p.TPMVersion)
	}
}

func (p *ActivationParameters) checkTPM12AKParameters() error {
	// TODO(jsonp): Implement helper to parse public blobs, ie:
	//   func ParsePublic(publicBlob []byte) (crypto.Public, error)

	pub, err := tpm1.UnmarshalPubRSAPublicKey(p.AK.Public)
	if err != nil {
		return fmt.Errorf("unmarshalling public key: %v", err)
	}
	if bits := pub.Size() * 8; bits < minRSABits {
		return fmt.Errorf("attestation key too small: must be at least %d bits but was %d bits", minRSABits, bits)
	}
	return nil
}

// VerifyOpts specifies options passed to (*AttestationParameters).Verify()
type VerifyOpts struct {
	// SelfAttested set to true ensures that the attestation is self-signed,
	// set to false ensures that the attestation is not self-signed.
	SelfAttested bool
	// Restricted set to true ensures that the verified key was created by TPM
	// with the restricted flag; set to false ensures that the flag was not set.
	Restricted bool
}

func (p *ActivationParameters) checkTPM20AKParameters() error {
	// AK must be restricted and its attestation is self-signed
	opts := VerifyOpts{
		SelfAttested: true,
		Restricted:   true,
	}
	return p.AK.Verify(opts)
}

// Verify verifies the TPM2-produced attestation parameters checking whether:
// - the attestation is self-signed (specified by opts)
// - the key length is secure
// - the attestation parameters matched the attested key
// - the key was TPM-generated and resides within TPM
// - the key can or cannot sing outside TPM-objects (specified via opts)
// - the signature is correct
func (p *AttestationParameters) Verify(opts VerifyOpts) error {
	if opts.SelfAttested && !bytes.Equal(p.Public, p.CertifyingKey) {
		return fmt.Errorf("not self-signed attestation")
	}
	if !opts.SelfAttested && bytes.Equal(p.Public, p.CertifyingKey) {
		return fmt.Errorf("self-signed attestation")
	}

	pub, err := tpm2.DecodePublic(p.Public)
	if err != nil {
		return fmt.Errorf("DecodePublic() failed: %v", err)
	}
	vrfy, err := tpm2.DecodePublic(p.CertifyingKey)
	if err != nil {
		return fmt.Errorf("DecodePublic() failed: %v", err)
	}
	_, err = tpm2.DecodeCreationData(p.CreateData)
	if err != nil {
		return fmt.Errorf("DecodeCreationData() failed: %v", err)
	}
	att, err := tpm2.DecodeAttestationData(p.CreateAttestation)
	if err != nil {
		return fmt.Errorf("DecodeAttestationData() failed: %v", err)
	}
	if att.Type != tpm2.TagAttestCreation {
		return fmt.Errorf("attestation does not apply to creation data, got tag %x", att.Type)
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

	// Compute & verify that the creation data matches the digest in the
	// attestation structure.
	nameHash, err := pub.NameAlg.Hash()
	if err != nil {
		return fmt.Errorf("HashConstructor() failed: %v", err)
	}
	h := nameHash.New()
	h.Write(p.CreateData)
	if !bytes.Equal(att.AttestedCreationInfo.OpaqueDigest, h.Sum(nil)) {
		return errors.New("attestation refers to different public key")
	}

	// Make sure the key has sane parameters (e.g., attestation can be faked if an AK
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
		return errors.New("provided key is exportable")
	}
	if opts.Restricted && ((pub.Attributes & tpm2.FlagRestricted) == 0) {
		return errors.New("provided key is not restricted")
	}
	if !opts.Restricted && ((pub.Attributes & tpm2.FlagRestricted) != 0) {
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
	match, err := att.AttestedCreationInfo.Name.MatchesPublic(pub)
	if err != nil {
		return err
	}
	if !match {
		return errors.New("creation attestation refers to a different key")
	}

	// Check the signature over the attestation data verifies correctly.
	// TODO: Support ECC certifying keys
	pk := rsa.PublicKey{E: int(vrfy.RSAParameters.Exponent()), N: vrfy.RSAParameters.Modulus()}
	signHash, err := vrfy.RSAParameters.Sign.Hash.Hash()
	if err != nil {
		return err
	}
	hsh := signHash.New()
	hsh.Write(p.CreateAttestation)

	if len(p.CreateSignature) < 8 {
		return fmt.Errorf("signature invalid: length of %d is shorter than 8", len(p.CreateSignature))
	}

	sig, err := tpm2.DecodeSignature(bytes.NewBuffer(p.CreateSignature))
	if err != nil {
		return fmt.Errorf("DecodeSignature() failed: %v", err)
	}

	if err := rsa.VerifyPKCS1v15(&pk, signHash, hsh.Sum(nil), sig.RSA.Signature); err != nil {
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
func (p *ActivationParameters) Generate() (secret []byte, ec *EncryptedCredential, err error) {
	if err := p.checkAKParameters(); err != nil {
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
	att, err := tpm2.DecodeAttestationData(p.AK.CreateAttestation)
	if err != nil {
		return nil, fmt.Errorf("DecodeAttestationData() failed: %v", err)
	}
	if att.AttestedCreationInfo == nil {
		return nil, fmt.Errorf("attestation was not for a creation event")
	}
	if att.AttestedCreationInfo.Name.Digest == nil {
		return nil, fmt.Errorf("attestation creation info name has no digest")
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
	if p.AK.UseTCSDActivationFormat {
		cred, encSecret, err = verification.GenerateChallengeEx(pk, p.AK.Public, secret)
	} else {
		cred, encSecret, err = generateChallenge12(rand, pk, p.AK.Public, secret)
	}

	if err != nil {
		return nil, fmt.Errorf("challenge generation failed: %v", err)
	}
	return &EncryptedCredential{
		Credential: cred,
		Secret:     encSecret,
	}, nil
}
