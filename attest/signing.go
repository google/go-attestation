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
	"crypto"
	"io"
)

type sk interface {
	close(tpmBase) error
	marshal() ([]byte, error)
	attestationParameters() AttestationParameters
	sign(tpmBase, []byte) ([]byte, error)
}

// SK represents a key which can be used for signing outside-TPM objects
type SK struct {
	sk  sk
	pub crypto.PublicKey
	tpm tpmBase
}

// SKConfig encapsulates parameters for minting keys. This type is defined
// now (despite being empty) for future interface compatibility.
type SKConfig struct {
}

// Public returns the public key corresponding to the private signing key.
func (s *SK) Public() crypto.PublicKey {
	return s.pub
}

// Sign signs digest with the TPM-stored private signing key.
func (s *SK) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.sk.sign(s.tpm, digest)
}

// Close unloads the SK from the system.
func (s *SK) Close() error {
	return s.sk.close(s.tpm)
}

// Marshal encodes the SK in a format that can be reloaded with tpm.LoadSK().
// This method exists to allow consumers to store the key persistently and load
// it as a later time. Users SHOULD NOT attempt to interpret or extract values
// from this blob.
func (s *SK) Marshal() ([]byte, error) {
	return s.sk.marshal()
}

// AttestationParameters returns information about the SK, typically used to
// prove key certification.
func (s *SK) AttestationParameters() AttestationParameters {
	return s.sk.attestationParameters()
}

// VerifySKAttestation uses verifyingKey to verify attested key certification.
func (p *AttestationParameters) VerifySKAttestation() error {
	return p.checkTPM20AttestationParameters(false)
}
