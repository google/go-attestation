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
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// SKSigner implements crypto.Signer
type SKSigner struct {
	tpm io.ReadWriter
	h   tpmutil.Handle
	pub crypto.PublicKey
}

// Public returns the public key corresponding to the private signing key.
func (s *SKSigner) Public() crypto.PublicKey {
	return s.pub
}

// Sign signs digest with the TPM-stored private signing key.
func (s *SKSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	sig, err := tpm2.Sign(s.tpm, s.h, "", digest, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("signing data: %v", err)
	}
	if sig.RSA != nil {
		return sig.RSA.Signature, nil
	}
	if sig.ECC != nil {
		return asn1.Marshal(struct {
			R *big.Int
			S *big.Int
		}{sig.ECC.R, sig.ECC.S})
	}
	return nil, fmt.Errorf("unsupported signature type: %v", sig.Alg)
}

// NewSKSigner creates a new Signer instance for the TPM-stored signing key.
func NewSKSigner(tpm io.ReadWriter, h tpmutil.Handle) (*SKSigner, error) {
	tpmPub, _, _, err := tpm2.ReadPublic(tpm, h)
	if err != nil {
		return nil, fmt.Errorf("read public blob: %v", err)
	}
	pub, err := tpmPub.Key()
	if err != nil {
		return nil, fmt.Errorf("decode public key: %v", err)
	}
	return &SKSigner{tpm, h, pub}, nil
}

type sk interface {
	close(tpmBase) error
	marshal() ([]byte, error)
	attestationParameters() AttestationParameters
}

// SK represents a key which can be used for signing outside-TPM objects
type SK struct {
	sk     sk
	signer crypto.Signer
}

// SKConfig encapsulates parameters for minting keys. This type is defined
// now (despite being empty) for future interface compatibility.
type SKConfig struct {
}

// Close unloads the SK from the system.
func (k *SK) Close(t *TPM) error {
	return k.sk.close(t.tpm)
}

// Marshal encodes the SK in a format that can be reloaded with tpm.LoadSK().
// This method exists to allow consumers to store the key persistently and load
// it as a later time. Users SHOULD NOT attempt to interpret or extract values
// from this blob.
func (k *SK) Marshal() ([]byte, error) {
	return k.sk.marshal()
}

// Signer returns the signer corresponding to the key.
func (k *SK) Signer() crypto.Signer {
	return k.signer
}

// AttestationParameters returns information about the SK, typically used to
// prove key certification.
func (k *SK) AttestationParameters() AttestationParameters {
	return k.sk.attestationParameters()
}

// VerifySKAttestation uses verifyingKey to verify attested key certification.
func (p *AttestationParameters) VerifySKAttestation(verifyingKey []byte) error {
	return p.checkTPM20AttestationParameters(verifyingKey, false)
}
