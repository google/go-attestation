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
	Close(*TPM) error
	Marshal() ([]byte, error)
	ActivateCredential(tpm *TPM, in EncryptedCredential) ([]byte, error)
	Quote(t *TPM, nonce []byte, alg HashAlg) (*Quote, error)
	AttestationParameters() AttestationParameters
	Public() crypto.PublicKey
}

// AIK represents a key which can be used for attestation.
type AIK struct {
	aik aik
}

// Close unloads the AIK from the system.
func (k *AIK) Close(t *TPM) error {
	return k.aik.Close(t)
}

// Marshal encodes the AIK in a format that can be reloaded with tpm.LoadAIK().
// This method exists to allow consumers to store the key persistently and load
// it as a later time. Users SHOULD NOT attempt to interpret or extract values
// from this blob.
func (k *AIK) Marshal() ([]byte, error) {
	return k.aik.Marshal()
}

// ActivateCredential decrypts the secret using the key to prove that the AIK
// was generated on the same TPM as the EK.
//
// This operation is synonymous with TPM2_ActivateCredential.
func (k *AIK) ActivateCredential(tpm *TPM, in EncryptedCredential) (secret []byte, err error) {
	return k.aik.ActivateCredential(tpm, in)
}

// Quote returns a quote over the platform state, signed by the AIK.
func (k *AIK) Quote(tpm *TPM, nonce []byte, alg HashAlg) (*Quote, error) {
	return k.aik.Quote(tpm, nonce, alg)
}

// Parameters returns information about the AIK, typically used to generate
// a credential activation challenge.
func (k *AIK) AttestationParameters() AttestationParameters {
	return k.aik.AttestationParameters()
}

// Public returns the public part of the AIK.
func (k *AIK) Public() crypto.PublicKey {
	return k.aik.Public()
}

// MintOptions encapsulates parameters for minting keys. This type is defined
// now (despite being empty) for future interface compatibility.
type MintOptions struct {
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

// PlatformEK represents a burned-in Endorsement Key, and its
// corrresponding EKCert (where present).
type PlatformEK struct {
	Cert   *x509.Certificate
	Public crypto.PublicKey
}

// AttestationParameters describes information about a key which is necessary
// for verifying its properties remotely.
type AttestationParameters struct {
	// Public represents the public key in a TPM-version specific encoding.
	// For TPM 2.0 devices, this is encoded as a TPMT_PUBLIC structure.
	// For TPM 1.2 devices, this is a TPM_PUBKEY structure, as defined in
	// the TPM Part 2 Structures specification, available at
	// https://trustedcomputinggroup.org/wp-content/uploads/TPM-Main-Part-2-TPM-Structures_v1.2_rev116_01032011.pdf
	Public []byte

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

// HashAlg identifies a hashing Algorithm.
type HashAlg uint8

// Valid hash algorithms.
var (
	HashSHA1   = HashAlg(tpm2.AlgSHA1)
	HashSHA256 = HashAlg(tpm2.AlgSHA256)
)

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
