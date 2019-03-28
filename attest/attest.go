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

	"github.com/google/certificate-transparency-go/x509"
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

// KeyEncoding indicates how an exported TPM key is represented.
type KeyEncoding uint8

// Key encodings
const (
	KeyEncodingInvalid KeyEncoding = iota
	// Managed by the OS but loadable by name.
	KeyEncodingOSManaged
	// Key fully represented but in encrypted form.
	KeyEncodingEncrypted
	// Parameters stored, but key must be regenerated before use.
	KeyEncodingParameterized
)

// KeyPurpose indicates the intended use of the key. It is implied that
// the key was created with usage restrictions to constrain its use
// to the given purpose.
type KeyPurpose uint8

// Key purposes.
const (
	AttestationKey KeyPurpose = iota
	StorageKey
)

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
