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
	"fmt"

	"github.com/google/go-tpm-tools/tpm2tools"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// SK represents a key which can be used for signing outside-TPM objects
type SK AK

// SKConfig encapsulates parameters for minting keys. This type is defined
// now (despite being empty) for future interface compatibility.
type SKConfig struct {
}

// Close unloads the SK from the system.
func (k *SK) Close(t *TPM) error {
	return k.ak.close(t.tpm)
}

// Marshal encodes the SK in a format that can be reloaded with tpm.LoadSK().
// This method exists to allow consumers to store the key persistently and load
// it as a later time. Users SHOULD NOT attempt to interpret or extract values
// from this blob.
func (k *SK) Marshal() ([]byte, error) {
	return k.ak.marshal()
}

// SKPublic holds structured information about an SK's public key.
type SKPublic AKPublic

// ParseSKPublic parses the Public blob from the AttestationParameters,
// returning the public key and signing parameters for the key.
func ParseSKPublic(version TPMVersion, public []byte) (*SKPublic, error) {
	pub, err := ParseAKPublic(version, public)
	if err != nil || pub == nil {
		return nil, err
	}
	return &SKPublic{Public: pub.Public, Hash: pub.Hash}, nil
}

func (t *wrappedTPM20) newSK(ak *AK, opts *SKConfig) (*SK, crypto.Signer, error) {
	// TODO(szp): TODO(jsonp): Abstract choice of hierarchy & parent.
	certifierHandle, err := ak.ak.handle()
	if err != nil {
		return nil, nil, fmt.Errorf("cannot get AK's handle: %v", err)
	}

	srk, _, err := t.getPrimaryKeyHandle(commonSrkEquivalentHandle)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get SRK handle: %v", err)
	}

	blob, pub, creationData, creationHash, tix, err := tpm2.CreateKey(t.rwc, srk, tpm2.PCRSelection{}, "", "", eccSKTemplate)
	if err != nil {
		return nil, nil, fmt.Errorf("CreateKey() failed: %v", err)
	}
	keyHandle, _, err := tpm2.Load(t.rwc, srk, "", pub, blob)
	if err != nil {
		return nil, nil, fmt.Errorf("Load() failed: %v", err)
	}
	// If any errors occur, free the handle.
	defer func() {
		if err != nil {
			tpm2.FlushContext(t.rwc, keyHandle)
		}
	}()

	// Certify SK by AK
	attestation, sig, err := tpm2.CertifyCreation(t.rwc, "", keyHandle, certifierHandle, nil, creationHash, tpm2.SigScheme{tpm2.AlgRSASSA, tpm2.AlgSHA256, 0}, tix)
	if err != nil {
		return nil, nil, fmt.Errorf("CertifyCreation failed: %v", err)
	}
	// Pack the raw structure into a TPMU_SIGNATURE.
	signature, err := tpmutil.Pack(tpm2.AlgRSASSA, tpm2.AlgSHA256, tpmutil.U16Bytes(sig))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to pack TPMT_SIGNATURE: %v", err)
	}

	// Create signer
	key, err := tpm2tools.NewKeyFromValues(t.rwc, keyHandle, pub)
	if err != nil {
		return nil, nil, fmt.Errorf("NewKeyFromValues: %v", err)
	}
	signer, err := key.GetSigner()
	if err != nil {
		return nil, nil, fmt.Errorf("cannot create signer for SK: %v", err)
	}

	return &SK{ak: newWrappedKey20(keyHandle, blob, pub, creationData, attestation, signature)}, signer, nil
}

func (t *wrappedTPM20) loadSK(opaqueBlob []byte) (*SK, crypto.Signer, error) {
	k, err := t.loadAK(opaqueBlob)
	if err != nil || k == nil {
		return nil, nil, err
	}
	handle, err := k.ak.handle()
	if err != nil {
		return nil, nil, fmt.Errorf("cannot get key handle: %v", err)
	}
	key, err := tpm2tools.NewKeyFromValues(t.rwc, handle, k.AttestationParameters().Public)
	if err != nil {
		return nil, nil, fmt.Errorf("NewKeyFromValues: %v", err)
	}
	signer, err := key.GetSigner()
	if err != nil {
		return nil, nil, fmt.Errorf("cannot create signer for SK: %v", err)
	}
	return &SK{ak: k.ak}, signer, err
}

// AttestationParameters returns information about the SK, typically used to
// prove key certification.
func (k *SK) AttestationParameters() AttestationParameters {
	return k.ak.attestationParameters()
}

// VerifySKAttestation uses verifyingKey to verify attested key certification.
func (p *AttestationParameters) VerifySKAttestation(verifyingKey []byte) error {
	return p.checkTPM20AttestationParameters(verifyingKey, false)
}
