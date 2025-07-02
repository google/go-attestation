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

//go:build windows
// +build windows

package attest

import (
	"crypto"
	"fmt"

	"github.com/google/go-tpm/legacy/tpm2"
)

// windowsKey20 represents a key bound to a TPM 2.0.
type windowsKey20 struct {
	hnd uintptr

	pcpKeyName        string
	public            []byte
	createData        []byte
	createAttestation []byte
	createSignature   []byte
}

func newWindowsKey20(hnd uintptr, pcpKeyName string, public, createData, createAttest, createSig []byte) ak {
	return &windowsKey20{
		hnd:               hnd,
		pcpKeyName:        pcpKeyName,
		public:            public,
		createData:        createData,
		createAttestation: createAttest,
		createSignature:   createSig,
	}
}

func (k *windowsKey20) marshal() ([]byte, error) {
	out := serializedKey{
		Encoding:   keyEncodingOSManaged,
		TPMVersion: 2,
		Name:       k.pcpKeyName,

		Public:            k.public,
		CreateData:        k.createData,
		CreateAttestation: k.createAttestation,
		CreateSignature:   k.createSignature,
	}
	return out.Serialize()
}

func (k *windowsKey20) activateCredential(t tpmBase, in EncryptedCredential, ek *EK) ([]byte, error) {
	tpm, ok := t.(*windowsTPM)
	if !ok {
		return nil, fmt.Errorf("expected *windowsTPM, got %T", t)
	}
	return tpm.pcp.ActivateCredential(k.hnd, append(in.Credential, in.Secret...))
}

func (k *windowsKey20) quote(tb tpmBase, nonce []byte, alg HashAlg, selectedPCRs []int) (*Quote, error) {
	t, ok := tb.(*windowsTPM)
	if !ok {
		return nil, fmt.Errorf("expected *windowsTPM, got %T", tb)
	}
	tpmKeyHnd, err := t.pcp.TPMKeyHandle(k.hnd)
	if err != nil {
		return nil, fmt.Errorf("TPMKeyHandle() failed: %v", err)
	}

	tpm, err := t.pcp.TPMCommandInterface()
	if err != nil {
		return nil, fmt.Errorf("TPMCommandInterface() failed: %v", err)
	}
	return quote20(tpm, tpmKeyHnd, alg.goTPMAlg(), nonce, selectedPCRs)
}

func (k *windowsKey20) close(tpm tpmBase) error {
	return closeNCryptObject(k.hnd)
}

func (k *windowsKey20) attestationParameters() AttestationParameters {
	return AttestationParameters{
		Public:            k.public,
		CreateData:        k.createData,
		CreateAttestation: k.createAttestation,
		CreateSignature:   k.createSignature,
	}
}

func (k *windowsKey20) certify(tb tpmBase, handle any, _ CertifyOpts) (*CertificationParameters, error) {
	t, ok := tb.(*windowsTPM)
	if !ok {
		return nil, fmt.Errorf("expected *windowsTPM, got %T", tb)
	}
	h, ok := handle.(uintptr)
	if !ok {
		return nil, fmt.Errorf("expected uinptr, got %T", handle)
	}
	hnd, err := t.pcp.TPMKeyHandle(h)
	if err != nil {
		return nil, fmt.Errorf("TPMKeyHandle() failed: %v", err)
	}
	akHnd, err := t.pcp.TPMKeyHandle(k.hnd)
	if err != nil {
		return nil, fmt.Errorf("TPMKeyHandle() failed: %v", err)
	}
	tpm, err := t.pcp.TPMCommandInterface()
	if err != nil {
		return nil, fmt.Errorf("TPMCommandInterface() failed: %v", err)
	}
	scheme := tpm2.SigScheme{
		Alg:  tpm2.AlgRSASSA,
		Hash: tpm2.AlgSHA1, // PCP-created AK uses SHA1
	}
	return certify(tpm, hnd, akHnd, nil, scheme)
}

func (k *windowsKey20) signMsg(tb tpmBase, msg []byte, pub crypto.PublicKey, opts crypto.SignerOpts) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}
