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

// +build windows

package attest

import (
	"fmt"

	tpm1 "github.com/google/go-tpm/tpm"
)

// platformKey12 represents a Windows-managed key on a TPM1.2 TPM.
type platformKey12 struct {
	hnd        uintptr
	pcpKeyName string
	public     []byte
}

func newPlatformKey12(hnd uintptr, pcpKeyName string, public []byte) ak {
	return &platformKey12{
		hnd:        hnd,
		pcpKeyName: pcpKeyName,
		public:     public,
	}
}

func (k *platformKey12) marshal() ([]byte, error) {
	out := serializedKey{
		Encoding:   keyEncodingOSManaged,
		TPMVersion: TPMVersion12,
		Name:       k.pcpKeyName,
		Public:     k.public,
	}
	return out.Serialize()
}

func (k *platformKey12) activateCredential(t interface{}, in EncryptedCredential) ([]byte, error) {
	tpm, _ := t.(*platformTPM)
	secretKey, err := tpm.pcp.ActivateCredential(k.hnd, in.Credential)
	if err != nil {
		return nil, err
	}
	return decryptCredential(secretKey, in.Secret)
}

func (k *platformKey12) quote(t interface{}, nonce []byte, alg HashAlg) (*Quote, error) {
	tpm, _ := t.(*platformTPM)
	if alg != HashSHA1 {
		return nil, fmt.Errorf("only SHA1 algorithms supported on TPM 1.2, not %v", alg)
	}

	tpmKeyHnd, err := tpm.pcp.TPMKeyHandle(k.hnd)
	if err != nil {
		return nil, fmt.Errorf("TPMKeyHandle() failed: %v", err)
	}

	tpmCI, err := tpm.pcp.TPMCommandInterface()
	if err != nil {
		return nil, fmt.Errorf("TPMCommandInterface() failed: %v", err)
	}

	selectedPCRs := make([]int, 24)
	for pcr, _ := range selectedPCRs {
		selectedPCRs[pcr] = pcr
	}

	sig, pcrc, err := tpm1.Quote(tpmCI, tpmKeyHnd, nonce, selectedPCRs[:], wellKnownAuth[:])
	if err != nil {
		return nil, fmt.Errorf("Quote() failed: %v", err)
	}
	// Construct and return TPM_QUOTE_INFO
	// Returning TPM_QUOTE_INFO allows us to verify the Quote at a higher resolution
	// and matches what go-tspi returns.
	quote, err := tpm1.NewQuoteInfo(nonce, selectedPCRs[:], pcrc)
	if err != nil {
		return nil, fmt.Errorf("failed to construct Quote Info: %v", err)
	}
	return &Quote{
		Version:   TPMVersion12,
		Quote:     quote,
		Signature: sig,
	}, nil
}

func (k *platformKey12) close(t interface{}) error {
	return closeNCryptObject(k.hnd)
}

func (k *platformKey12) attestationParameters() AttestationParameters {
	return AttestationParameters{
		Public: k.public,
	}
}

// platformKey20 represents a key bound to a TPM 2.0.
type platformKey20 struct {
	hnd uintptr

	pcpKeyName        string
	public            []byte
	createData        []byte
	createAttestation []byte
	createSignature   []byte
}

func newPlatformKey20(hnd uintptr, pcpKeyName string, public, createData, createAttest, createSig []byte) ak {
	return &platformKey20{
		hnd:               hnd,
		pcpKeyName:        pcpKeyName,
		public:            public,
		createData:        createData,
		createAttestation: createAttest,
		createSignature:   createSig,
	}
}

func (k *platformKey20) marshal() ([]byte, error) {
	out := serializedKey{
		Encoding:   keyEncodingOSManaged,
		TPMVersion: TPMVersion20,
		Name:       k.pcpKeyName,

		Public:            k.public,
		CreateData:        k.createData,
		CreateAttestation: k.createAttestation,
		CreateSignature:   k.createSignature,
	}
	return out.Serialize()
}

func (k *platformKey20) activateCredential(t interface{}, in EncryptedCredential) ([]byte, error) {
	tpm, _ := t.(*platformTPM)
	return tpm.pcp.ActivateCredential(k.hnd, append(in.Credential, in.Secret...))
}

func (k *platformKey20) quote(t interface{}, nonce []byte, alg HashAlg) (*Quote, error) {
	tpm, _ := t.(*platformTPM)
	tpmKeyHnd, err := tpm.pcp.TPMKeyHandle(k.hnd)
	if err != nil {
		return nil, fmt.Errorf("TPMKeyHandle() failed: %v", err)
	}

	tpmCI, err := tpm.pcp.TPMCommandInterface()
	if err != nil {
		return nil, fmt.Errorf("TPMCommandInterface() failed: %v", err)
	}
	return quote20(tpmCI, tpmKeyHnd, alg.goTPMAlg(), nonce)
}

func (k *platformKey20) close(t interface{}) error {
	return closeNCryptObject(k.hnd)
}

func (k *platformKey20) attestationParameters() AttestationParameters {
	return AttestationParameters{
		Public:            k.public,
		CreateData:        k.createData,
		CreateAttestation: k.createAttestation,
		CreateSignature:   k.createSignature,
	}
}
