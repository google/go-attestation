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
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/google/go-tpm/legacy/tpm2"
	tpm1 "github.com/google/go-tpm/tpm"
)

// windowsAK12 represents a Windows-managed key on a TPM1.2 TPM.
type windowsAK12 struct {
	hnd        uintptr
	pcpKeyName string
	public     []byte
}

func newWindowsAK12(hnd uintptr, pcpKeyName string, public []byte) ak {
	return &windowsAK12{
		hnd:        hnd,
		pcpKeyName: pcpKeyName,
		public:     public,
	}
}

func (k *windowsAK12) marshal() ([]byte, error) {
	out := serializedKey{
		Encoding:   keyEncodingOSManaged,
		TPMVersion: TPMVersion12,
		Name:       k.pcpKeyName,
		Public:     k.public,
	}
	return out.Serialize()
}

func (k *windowsAK12) activateCredential(t tpmBase, in EncryptedCredential, ek *EK) ([]byte, error) {
	tpm, ok := t.(*windowsTPM)
	if !ok {
		return nil, fmt.Errorf("expected *windowsTPM, got %T", t)
	}
	secretKey, err := tpm.pcp.ActivateCredential(k.hnd, in.Credential)
	if err != nil {
		return nil, err
	}
	return decryptCredential(secretKey, in.Secret)
}

func (k *windowsAK12) quote(tb tpmBase, nonce []byte, alg HashAlg, selectedPCRs []int) (*Quote, error) {
	if alg != HashSHA1 {
		return nil, fmt.Errorf("only SHA1 algorithms supported on TPM 1.2, not %v", alg)
	}
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
		Version:   TPMVersion12,
		Quote:     quote,
		Signature: sig,
	}, nil
}

func (k *windowsAK12) close(tpm tpmBase) error {
	return closeNCryptObject(k.hnd)
}

func (k *windowsAK12) attestationParameters() AttestationParameters {
	return AttestationParameters{
		Public: k.public,
	}
}
func (k *windowsAK12) certify(tb tpmBase, handle interface{}) (*CertificationParameters, error) {
	return nil, fmt.Errorf("not implemented")
}

// windowsAK20 represents a key bound to a TPM 2.0.
type windowsAK20 struct {
	hnd uintptr

	pcpKeyName        string
	public            []byte
	createData        []byte
	createAttestation []byte
	createSignature   []byte
}

func newWindowsAK20(hnd uintptr, pcpKeyName string, public, createData, createAttest, createSig []byte) ak {
	return &windowsAK20{
		hnd:               hnd,
		pcpKeyName:        pcpKeyName,
		public:            public,
		createData:        createData,
		createAttestation: createAttest,
		createSignature:   createSig,
	}
}

func (k *windowsAK20) marshal() ([]byte, error) {
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

func (k *windowsAK20) activateCredential(t tpmBase, in EncryptedCredential, ek *EK) ([]byte, error) {
	tpm, ok := t.(*windowsTPM)
	if !ok {
		return nil, fmt.Errorf("expected *windowsTPM, got %T", t)
	}
	return tpm.pcp.ActivateCredential(k.hnd, append(in.Credential, in.Secret...))
}

func (k *windowsAK20) quote(tb tpmBase, nonce []byte, alg HashAlg, selectedPCRs []int) (*Quote, error) {
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

func (k *windowsAK20) close(tpm tpmBase) error {
	return closeNCryptObject(k.hnd)
}

func (k *windowsAK20) attestationParameters() AttestationParameters {
	return AttestationParameters{
		Public:            k.public,
		CreateData:        k.createData,
		CreateAttestation: k.createAttestation,
		CreateSignature:   k.createSignature,
	}
}

func (k *windowsAK20) certify(tb tpmBase, handle interface{}) (*CertificationParameters, error) {
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
	return certify(tpm, hnd, akHnd, scheme)
}

// newWindowsKey20 returns a pointer to a windowsAK20, conforming to the key interface. This
// allows the resulting windowsAK20 to be used as a signing key.
func newWindowsKey20(hnd uintptr, pcpKeyName string, public, createData, createAttest, createSig []byte) key {
	return &windowsAK20{
		hnd:               hnd,
		pcpKeyName:        pcpKeyName,
		public:            public,
		createData:        createData,
		createAttestation: createAttest,
		createSignature:   createSig,
	}
}

func (k *windowsAK20) blobs() ([]byte, []byte, error) {
	return nil, nil, errors.New("not implemented")
}

func (k *windowsAK20) certificationParameters() CertificationParameters {
	return CertificationParameters{
		Public:            k.public,
		CreateAttestation: k.createAttestation,
		CreateSignature:   k.createSignature,
	}
}

func (k *windowsAK20) decrypt(tpmBase, []byte) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (k *windowsAK20) sign(tb tpmBase, digest []byte, pub crypto.PublicKey, opts crypto.SignerOpts) ([]byte, error) {

	t, ok := tb.(*windowsTPM)
	if !ok {
		return nil, fmt.Errorf("expected *windowsTPM, got %T", tb)
	}

	rw, err := t.pcp.TPMCommandInterface()
	if err != nil {
		return nil, fmt.Errorf("error getting TPM command interface: %w", err)
	}

	hnd, err := t.pcp.TPMKeyHandle(k.hnd)
	if err != nil {
		return nil, fmt.Errorf("TPMKeyHandle() failed: %v", err)
	}

	switch p := pub.(type) {
	case *ecdsa.PublicKey:
		return signECDSA(rw, hnd, digest, p.Curve, opts)
	case *rsa.PublicKey:
		return signRSA(rw, hnd, digest, opts)
	}

	return nil, fmt.Errorf("unsupported signing key type: %T", pub)
}
