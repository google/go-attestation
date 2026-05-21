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
	"fmt"
	"io"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
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

func newWindowsAK20(hnd uintptr, pcpKeyName string, public, createData, createAttest, createSig []byte) ak {
	return &windowsKey20{
		hnd:               hnd,
		pcpKeyName:        pcpKeyName,
		public:            public,
		createData:        createData,
		createAttestation: createAttest,
		createSignature:   createSig,
	}
}

// newWindowsKey20 returns a pointer to a windowsKey20, conforming to the key interface.
func newWindowsKey20(hnd uintptr, pcpKeyName string, pub, createData, createAttest, createSig []byte) key {
	return &windowsKey20{
		hnd:               hnd,
		pcpKeyName:        pcpKeyName,
		public:            pub,
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

func (k *windowsKey20) certify(tb tpmBase, handle any, opts CertifyOpts) (*CertificationParameters, error) {
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
	return certify(tpm, hnd, akHnd, opts.QualifyingData, scheme)
}

func getWindowsEndorsementKeyHandle(rwc io.ReadWriter, ek *EK) (tpmutil.Handle, error) {
	hnd, _, err := getEndorsementKeyHandle(rwc, ek)
	return hnd, err
}

func (k *windowsKey20) certifyWithDecryptionEk(tb tpmBase, ek *EK, challenge DecryptionEkChallenge) (*CertificationParameters, error) {
	t, ok := tb.(*windowsTPM)
	if !ok {
		return nil, fmt.Errorf("expected *windowsTPM, got %T", tb)
	}
	if ek == nil {
		return nil, fmt.Errorf("ek is nil")
	}
	rwc, err := t.pcp.TPMCommandInterface()
	if err != nil {
		return nil, fmt.Errorf("TPMCommandInterface() failed: %v", err)
	}
	ekHnd, err := getWindowsEndorsementKeyHandle(rwc, ek)
	if err != nil {
		return nil, fmt.Errorf("failed to get EK handle: %v", err)
	}
	akHnd, err := t.pcp.TPMKeyHandle(k.hnd)
	if err != nil {
		return nil, fmt.Errorf("TPMKeyHandle() failed: %v", err)
	}

	return certifyAKWithDecryptionEk(rwc, ekHnd, akHnd, k.public, challenge)
}

func (k *windowsKey20) signMsg(tb tpmBase, msg []byte, pub crypto.PublicKey, opts crypto.SignerOpts) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

func (k *windowsKey20) certificationParameters() CertificationParameters {
	return CertificationParameters{
		Public:            k.public,
		CreateAttestation: k.createAttestation,
		CreateSignature:   k.createSignature,
	}
}

func (k *windowsKey20) sign(tb tpmBase, digest []byte, pub crypto.PublicKey, opts crypto.SignerOpts) ([]byte, error) {
	return k.signWithValidation(tb, digest, pub, opts, nil)
}

func (k *windowsKey20) signWithValidation(tb tpmBase, digest []byte, pub crypto.PublicKey, opts crypto.SignerOpts, validation *tpm2.Ticket) ([]byte, error) {
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
		return signECDSA(rw, hnd, digest, p.Curve, opts, validation)
	case *rsa.PublicKey:
		return signRSA(rw, hnd, digest, opts, validation)
	default:
		return nil, fmt.Errorf("unsupported signing key type: %T", pub)
	}
}

func (k *windowsKey20) decrypt(tpmBase, []byte) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

func (k *windowsKey20) blobs() ([]byte, []byte, error) {
	return nil, nil, fmt.Errorf("not implemented")
}
