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
	"crypto"
	"fmt"

	tpm1 "github.com/google/go-tpm/tpm"
	"github.com/google/go-tpm/tpm2"
)

// key12 represents a Windows-managed key on a TPM1.2 TPM.
type key12 struct {
	hnd        uintptr
	pcpKeyName string
	public     []byte

	publicKey crypto.PublicKey
}

func newKey12(hnd uintptr, pcpKeyName string, public []byte) (aik, error) {
	rsaPub, err := tpm1.UnmarshalPubRSAPublicKey(public)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %v", err)
	}
	return &key12{
		hnd:        hnd,
		pcpKeyName: pcpKeyName,
		public:     public,
		publicKey:  rsaPub,
	}, nil
}

func (k *key12) Public() crypto.PublicKey {
	return k.publicKey
}

// Marshal represents the key in a persistent format which may be
// loaded at a later time using tpm.LoadKey().
func (k *key12) Marshal() ([]byte, error) {
	out := serializedKey{
		Encoding:   keyEncodingOSManaged,
		TPMVersion: TPMVersion12,
		Name:       k.pcpKeyName,
		Public:     k.public,
	}
	return out.Serialize()
}

// ActivateCredential decrypts the specified credential using key.
// This operation is synonymous with TPM_ActivateIdentity for TPM1.2.
func (k *key12) ActivateCredential(tpm *TPM, in EncryptedCredential) ([]byte, error) {
	secretKey, err := tpm.pcp.ActivateCredential(k.hnd, in.Credential)
	if err != nil {
		return nil, err
	}
	return decryptCredential(secretKey, in.Secret)
}

// Quote returns a quote over the platform state, signed by the key.
func (k *key12) Quote(t *TPM, nonce []byte, alg HashAlg) (*Quote, error) {
	tpmKeyHnd, err := t.pcp.TPMKeyHandle(k.hnd)
	if err != nil {
		return nil, fmt.Errorf("TPMKeyHandle() failed: %v", err)
	}

	tpm, err := t.pcp.TPMCommandInterface()
	if err != nil {
		return nil, fmt.Errorf("TPMCommandInterface() failed: %v", err)
	}

	selectedPCRs := make([]int, 24)
	for pcr, _ := range selectedPCRs {
		selectedPCRs[pcr] = pcr
	}

	sig, pcrc, err := tpm1.Quote(tpm, tpmKeyHnd, nonce, selectedPCRs[:], wellKnownAuth[:])
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
		Quote:     quote,
		Signature: sig,
	}, nil
}

// Close frees any resources associated with the key.
func (k *key12) Close(tpm *TPM) error {
	return closeNCryptObject(k.hnd)
}

// Parameters returns information about the AIK.
func (k *key12) Parameters() AIKParameters {
	return AIKParameters{
		Public: k.public,
	}
}

// key20 represents a key bound to a TPM 2.0.
type key20 struct {
	hnd uintptr

	pcpKeyName        string
	public            []byte
	createData        []byte
	createAttestation []byte
	createSignature   []byte

	publicKey crypto.PublicKey
}

func newKey20(hnd uintptr, pcpKeyName string, public, createData, createAttest, createSig []byte) (aik, error) {
	pub, err := tpm2.DecodePublic(public)
	if err != nil {
		return nil, fmt.Errorf("parsing TPM public key structure: %v", err)
	}
	pubKey, err := pub.Key()
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %v", err)
	}
	return &key20{
		hnd:               hnd,
		pcpKeyName:        pcpKeyName,
		public:            public,
		createData:        createData,
		createAttestation: createAttest,
		createSignature:   createSig,
		publicKey:         pubKey,
	}, nil
}

func (k *key20) Public() crypto.PublicKey {
	return k.publicKey
}

// Marshal represents the key in a persistent format which may be
// loaded at a later time using tpm.LoadKey().
func (k *key20) Marshal() ([]byte, error) {
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

// ActivateCredential decrypts the specified credential using the key.
// This operation is synonymous with TPM2_ActivateCredential.
func (k *key20) ActivateCredential(tpm *TPM, in EncryptedCredential) ([]byte, error) {
	return tpm.pcp.ActivateCredential(k.hnd, append(in.Credential, in.Secret...))
}

// Quote returns a quote over the platform state, signed by the key.
func (k *key20) Quote(t *TPM, nonce []byte, alg HashAlg) (*Quote, error) {
	tpmKeyHnd, err := t.pcp.TPMKeyHandle(k.hnd)
	if err != nil {
		return nil, fmt.Errorf("TPMKeyHandle() failed: %v", err)
	}

	tpm, err := t.pcp.TPMCommandInterface()
	if err != nil {
		return nil, fmt.Errorf("TPMCommandInterface() failed: %v", err)
	}
	return quote20(tpm, tpmKeyHnd, tpm2.Algorithm(alg), nonce)
}

// Close frees any resources associated with the key.
func (k *key20) Close(tpm *TPM) error {
	return closeNCryptObject(k.hnd)
}

// Delete permenantly removes the key from the system. This method
// invalidates Key and any further method invocations are invalid.
func (k *key20) Delete(tpm *TPM) error {
	return tpm.pcp.DeleteKey(k.hnd)
}

// Parameters returns information about the AIK.
func (k *key20) Parameters() AIKParameters {
	return AIKParameters{
		Public:            k.public,
		CreateData:        k.createData,
		CreateAttestation: k.createAttestation,
		CreateSignature:   k.createSignature,
	}
}
