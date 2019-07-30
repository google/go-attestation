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

// +build linux

package attest

import (
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/google/go-tspi/attestation"
)

// key12 represents a key bound to a TPM 1.2 device via tcsd.
type key12 struct {
	blob   []byte
	public []byte
}

func newKey12(blob, public []byte) aik {
	return &key12{
		blob:   blob,
		public: public,
	}
}

// Marshal represents the key in a persistent format which may be
// loaded at a later time using tpm.LoadKey().
func (k *key12) Marshal() ([]byte, error) {
	out := serializedKey{
		Encoding:   keyEncodingEncrypted,
		TPMVersion: TPMVersion12,
		Blob:       k.blob,
		Public:     k.public,
	}
	return out.Serialize()
}

func (k *key12) Close(tpm *TPM) error {
	return nil // No state for tpm 1.2.
}

// ActivateCredential decrypts the specified credential using key.
// This operation is synonymous with TPM2_ActivateCredential.
func (k *key12) ActivateCredential(t *TPM, in EncryptedCredential) ([]byte, error) {
	cred, err := attestation.AIKChallengeResponse(t.ctx, k.blob, in.Credential, in.Secret)
	if err != nil {
		return nil, fmt.Errorf("failed to activate aik: %v", err)
	}
	return cred, nil
}

// Quote returns a quote over the platform state, signed by the key.
func (k *key12) Quote(t *TPM, nonce []byte, alg HashAlg) (*Quote, error) {
	quote, rawSig, err := attestation.GetQuote(t.ctx, k.blob, nonce)
	if err != nil {
		return nil, fmt.Errorf("Quote() failed: %v", err)
	}

	return &Quote{
		Version:   TPMVersion12,
		Quote:     quote,
		Signature: rawSig,
	}, nil
}

// AttestationParameters returns information about the AIK.
func (k *key12) AttestationParameters() AttestationParameters {
	return AttestationParameters{
		Public:                  k.public,
		UseTCSDActivationFormat: true,
	}
}

// key20 represents a key bound to a TPM 2.0.
type key20 struct {
	hnd tpmutil.Handle

	blob              []byte
	public            []byte // used by both TPM1.2 and 2.0
	createData        []byte
	createAttestation []byte
	createSignature   []byte
}

func newKey20(hnd tpmutil.Handle, blob, public, createData, createAttestation, createSig []byte) aik {
	return &key20{
		hnd:               hnd,
		blob:              blob,
		public:            public,
		createData:        createData,
		createAttestation: createAttestation,
		createSignature:   createSig,
	}
}

// Marshal represents the key in a persistent format which may be
// loaded at a later time using tpm.LoadKey().
func (k *key20) Marshal() ([]byte, error) {
	return (&serializedKey{
		Encoding:   keyEncodingEncrypted,
		TPMVersion: TPMVersion20,

		Blob:              k.blob,
		Public:            k.public,
		CreateData:        k.createData,
		CreateAttestation: k.createAttestation,
		CreateSignature:   k.createSignature,
	}).Serialize()
}

// Close frees any resources associated with the key.
func (k *key20) Close(tpm *TPM) error {
	return tpm2.FlushContext(tpm.rwc, k.hnd)
}

// ActivateCredential decrypts the specified credential using key.
// This operation is synonymous with TPM2_ActivateCredential.
func (k *key20) ActivateCredential(t *TPM, in EncryptedCredential) ([]byte, error) {
	ekHnd, _, err := t.getPrimaryKeyHandle(commonEkEquivalentHandle)
	if err != nil {
		return nil, err
	}

	sessHandle, _, err := tpm2.StartAuthSession(
		t.rwc,
		tpm2.HandleNull,  /*tpmKey*/
		tpm2.HandleNull,  /*bindKey*/
		make([]byte, 16), /*nonceCaller*/
		nil,              /*secret*/
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		return nil, fmt.Errorf("creating session: %v", err)
	}
	defer tpm2.FlushContext(t.rwc, sessHandle)

	if _, err := tpm2.PolicySecret(t.rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, sessHandle, nil, nil, nil, 0); err != nil {
		return nil, fmt.Errorf("tpm2.PolicySecret() failed: %v", err)
	}

	return tpm2.ActivateCredentialUsingAuth(t.rwc, []tpm2.AuthCommand{
		{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession},
		{Session: sessHandle, Attributes: tpm2.AttrContinueSession},
	}, k.hnd, ekHnd, in.Credential[2:], in.Secret[2:])
}

// Quote returns a quote over the platform state, signed by the key.
func (k *key20) Quote(t *TPM, nonce []byte, alg HashAlg) (*Quote, error) {
	return quote20(t.rwc, k.hnd, tpm2.Algorithm(alg), nonce)
}

// AttestationParameters returns information about the AIK.
func (k *key20) AttestationParameters() AttestationParameters {
	return AttestationParameters{
		Public:            k.public,
		CreateData:        k.createData,
		CreateAttestation: k.createAttestation,
		CreateSignature:   k.createSignature,
	}
}
