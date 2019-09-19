// Copyright 2019 Google Inc.
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

// Package attest abstracts TPM attestation operations.
package attest

import (
	"crypto"
	"errors"
	"fmt"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/go-tpm/tpm"
	"github.com/google/go-tpm/tpm2"
)

// TPMVersion is used to configure a preference in
// which TPM to use, if multiple are available.
type TPMVersion uint8

// TPM versions
const (
	TPMVersionAgnostic TPMVersion = iota
	TPMVersion12
	TPMVersion20
)

// TPMInterface indicates how the client communicates
// with the TPM.
type TPMInterface uint8

// TPM interfaces
const (
	TPMInterfaceDirect TPMInterface = iota
	TPMInterfaceKernelManaged
	TPMInterfaceDaemonManaged
)

// OpenConfig encapsulates settings passed to OpenTPM().
type OpenConfig struct {
	// TPMVersion indicates which TPM version the library should
	// attempt to use. If the specified version is not available,
	// ErrTPMNotAvailable is returned. Defaults to TPMVersionAgnostic.
	TPMVersion TPMVersion
}

// keyEncoding indicates how an exported TPM key is represented.
type keyEncoding uint8

func (e keyEncoding) String() string {
	switch e {
	case keyEncodingInvalid:
		return "invalid"
	case keyEncodingOSManaged:
		return "os-managed"
	case keyEncodingEncrypted:
		return "encrypted"
	case keyEncodingParameterized:
		return "parameterized"
	default:
		return fmt.Sprintf("keyEncoding<%d>", int(e))
	}
}

// Key encodings
const (
	keyEncodingInvalid keyEncoding = iota
	// Managed by the OS but loadable by name.
	keyEncodingOSManaged
	// Key fully represented but in encrypted form.
	keyEncodingEncrypted
	// Parameters stored, but key must be regenerated before use.
	keyEncodingParameterized
)

type aik interface {
	close(*platformTPM) error
	marshal() ([]byte, error)
	activateCredential(tpm *platformTPM, in EncryptedCredential) ([]byte, error)
	quote(t *platformTPM, nonce []byte, alg HashAlg) (*Quote, error)
	attestationParameters() AttestationParameters
}

// AIK represents a key which can be used for attestation.
type AIK struct {
	aik aik
}

// Close unloads the AIK from the system.
func (k *AIK) Close(t *TPM) error {
	return k.aik.close(t.tpm)
}

// Marshal encodes the AIK in a format that can be reloaded with tpm.LoadAIK().
// This method exists to allow consumers to store the key persistently and load
// it as a later time. Users SHOULD NOT attempt to interpret or extract values
// from this blob.
func (k *AIK) Marshal() ([]byte, error) {
	return k.aik.marshal()
}

// ActivateCredential decrypts the secret using the key to prove that the AIK
// was generated on the same TPM as the EK.
//
// This operation is synonymous with TPM2_ActivateCredential.
func (k *AIK) ActivateCredential(tpm *TPM, in EncryptedCredential) (secret []byte, err error) {
	return k.aik.activateCredential(tpm.tpm, in)
}

// Quote returns a quote over the platform state, signed by the AIK.
func (k *AIK) Quote(tpm *TPM, nonce []byte, alg HashAlg) (*Quote, error) {
	return k.aik.quote(tpm.tpm, nonce, alg)
}

// Parameters returns information about the AIK, typically used to generate
// a credential activation challenge.
func (k *AIK) AttestationParameters() AttestationParameters {
	return k.aik.attestationParameters()
}

// AIKConfig encapsulates parameters for minting keys. This type is defined
// now (despite being empty) for future interface compatibility.
type AIKConfig struct {
}

// EncryptedCredential represents encrypted parameters which must be activated
// against a key.
type EncryptedCredential struct {
	Credential []byte
	Secret     []byte
}

// Quote encapsulates the results of a Quote operation against the TPM,
// using an attestation key.
type Quote struct {
	Version   TPMVersion
	Quote     []byte
	Signature []byte
}

// PCR encapsulates the value of a PCR at a point in time.
type PCR struct {
	Index     int
	Digest    []byte
	DigestAlg crypto.Hash
}

// EK is a burned-in endorcement key bound to a TPM. This optionally contains
// a certificate that can chain to the TPM manufacturer.
type EK struct {
	// Public key of the EK.
	Public crypto.PublicKey

	// Certificate is the EK certificate for TPMs that provide it.
	Certificate *x509.Certificate

	// For Intel TPMs, Intel hosts certificates at a public URL derived from the
	// Public key. Clients or servers can perform an HTTP GET to this URL, and
	// use ParseEKCertificate on the response body.
	CertificateURL string
}

// AttestationParameters describes information about a key which is necessary
// for verifying its properties remotely.
type AttestationParameters struct {
	// Public represents the AIK's canonical encoding. This blob includes the
	// public key, as well as signing parameters such as the hash algorithm
	// used to generate quotes.
	//
	// Use ParseAIKPublic to access the key's data.
	Public []byte
	// For TPM 2.0 devices, Public is encoded as a TPMT_PUBLIC structure.
	// For TPM 1.2 devices, Public is a TPM_PUBKEY structure, as defined in
	// the TPM Part 2 Structures specification, available at
	// https://trustedcomputinggroup.org/wp-content/uploads/TPM-Main-Part-2-TPM-Structures_v1.2_rev116_01032011.pdf

	// UseTCSDActivationFormat is set when tcsd (trousers daemon) is operating
	// as an intermediary between this library and the TPM. A value of true
	// indicates that activation challenges should use the TCSD-specific format.
	UseTCSDActivationFormat bool

	// Subsequent fields are only populated for AIKs generated on a TPM
	// implementing version 2.0 of the specification. The specific structures
	// referenced for each field are defined in the TPM Revision 2, Part 2 -
	// Structures specification, available here:
	// https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf

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

// AIKPublic holds structured information about an AIK's public key.
type AIKPublic struct {
	// Public is the public part of the AIK. This can either be an *rsa.PublicKey or
	// and *ecdsa.PublicKey.
	Public crypto.PublicKey
	// Hash is the hashing algorithm the AIK will use when signing quotes.
	Hash crypto.Hash
}

// ParseAIKPublic parses the Public blob from the AttestationParameters,
// returning the public key and signing parameters for the key.
func ParseAIKPublic(version TPMVersion, public []byte) (*AIKPublic, error) {
	switch version {
	case TPMVersion12:
		rsaPub, err := tpm.UnmarshalPubRSAPublicKey(public)
		if err != nil {
			return nil, fmt.Errorf("parsing public key: %v", err)
		}
		return &AIKPublic{Public: rsaPub, Hash: crypto.SHA1}, nil
	case TPMVersion20:
		pub, err := tpm2.DecodePublic(public)
		if err != nil {
			return nil, fmt.Errorf("parsing TPM public key structure: %v", err)
		}
		pubKey, err := pub.Key()
		if err != nil {
			return nil, fmt.Errorf("parsing public key: %v", err)
		}
		var h crypto.Hash
		switch pub.Type {
		case tpm2.AlgRSA:
			h, err = cryptoHash(pub.RSAParameters.Sign.Hash)
		case tpm2.AlgECC:
			h, err = cryptoHash(pub.ECCParameters.Sign.Hash)
		default:
			return nil, fmt.Errorf("unsupported public key type 0x%x", pub.Type)
		}
		if err != nil {
			return nil, fmt.Errorf("invalid public key hash: %v", err)
		}
		return &AIKPublic{Public: pubKey, Hash: h}, nil
	default:
		return nil, fmt.Errorf("unknown tpm version 0x%x", version)
	}
}

// Verify is used to prove authenticity of the PCR measurements. It ensures that
// the quote was signed by the AIK, and that its contents matches the PCR and
// nonce combination.
//
// The nonce is used to prevent replays of Quote and PCRs and is signed by the
// quote. Some TPMs don't support nonces longer than 20 bytes, and if the
// nonce is used to tie additional data to the quote, the additional data should be
// hashed to construct the nonce.
func (a *AIKPublic) Verify(quote Quote, pcrs []PCR, nonce []byte) error {
	switch quote.Version {
	case TPMVersion12:
		return a.validate12Quote(quote, pcrs, nonce)
	case TPMVersion20:
		return a.validate20Quote(quote, pcrs, nonce)
	default:
		return fmt.Errorf("quote used unknown tpm version 0x%x", quote.Version)
	}
}

// HashAlg identifies a hashing Algorithm.
type HashAlg uint8

// Valid hash algorithms.
var (
	HashSHA1   = HashAlg(tpm2.AlgSHA1)
	HashSHA256 = HashAlg(tpm2.AlgSHA256)
)

func (a HashAlg) cryptoHash() crypto.Hash {
	switch a {
	case HashSHA1:
		return crypto.SHA1
	case HashSHA256:
		return crypto.SHA256
	}
	return 0
}

func (a HashAlg) goTPMAlg() tpm2.Algorithm {
	switch a {
	case HashSHA1:
		return tpm2.AlgSHA1
	case HashSHA256:
		return tpm2.AlgSHA256
	}
	return 0
}

var (
	defaultOpenConfig = &OpenConfig{}

	// ErrTPMNotAvailable is returned in response to OpenTPM() when
	// either no TPM is available, or a TPM of the requested version
	// is not available (if TPMVersion was set in the provided config).
	ErrTPMNotAvailable = errors.New("TPM device not available")
	// ErrTPM12NotImplemented is returned in response to methods which
	// need to interact with the TPM1.2 device in ways that have not
	// yet been implemented.
	ErrTPM12NotImplemented = errors.New("TPM 1.2 support not yet implemented")
)

// TPMInfo contains information about the version & interface
// of an open TPM.
type TPMInfo struct {
	Version      TPMVersion
	Interface    TPMInterface
	VendorInfo   string
	Manufacturer TCGVendorID

	// FirmwareVersionMajor and FirmwareVersionMinor describe
	// the firmware version of the TPM, but are only available
	// for TPM 2.0 devices.
	FirmwareVersionMajor int
	FirmwareVersionMinor int
}

// probedTPM identifies a TPM device on the system, which
// is a candidate for being used.
type probedTPM struct {
	Version TPMVersion
	Path    string
}

// MatchesConfig returns true if the TPM satisfies the constraints
// specified by the given config.
func (t *probedTPM) MatchesConfig(config OpenConfig) bool {
	return config.TPMVersion == TPMVersionAgnostic || t.Version == config.TPMVersion
}

// OpenTPM initializes access to the TPM based on the
// config provided.
func OpenTPM(config *OpenConfig) (*TPM, error) {
	if config == nil {
		config = defaultOpenConfig
	}
	candidateTPMs, err := probeSystemTPMs()
	if err != nil {
		return nil, err
	}

	for _, tpm := range candidateTPMs {
		if tpm.MatchesConfig(*config) {
			return openTPM(tpm)
		}
	}

	return nil, ErrTPMNotAvailable
}

// AvailableTPMs returns information about available TPMs matching
// the given config, without opening the devices.
func AvailableTPMs(config *OpenConfig) ([]TPMInfo, error) {
	if config == nil {
		config = defaultOpenConfig
	}

	candidateTPMs, err := probeSystemTPMs()
	if err != nil {
		return nil, err
	}

	var out []TPMInfo

	for _, tpm := range candidateTPMs {
		if tpm.MatchesConfig(*config) {
			t, err := openTPM(tpm)
			if err != nil {
				return nil, err
			}
			defer t.Close()
			i, err := t.Info()
			if err != nil {
				return nil, err
			}
			out = append(out, *i)
		}
	}

	return out, nil
}
