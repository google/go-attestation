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

// +build linux,!gofuzz,cgo

package attest

import (
	"fmt"

	"github.com/google/go-tspi/attestation"
)

// trousersKey12 represents a key bound to a TPM 1.2 device via tcsd.
type trousersKey12 struct {
	blob   []byte
	public []byte
}

func newTrousersKey12(blob, public []byte) ak {
	return &trousersKey12{
		blob:   blob,
		public: public,
	}
}

// Marshal represents the key in a persistent format which may be
// loaded at a later time using tpm.LoadKey().
func (k *trousersKey12) marshal() ([]byte, error) {
	out := serializedKey{
		Encoding:   keyEncodingEncrypted,
		TPMVersion: TPMVersion12,
		Blob:       k.blob,
		Public:     k.public,
	}
	return out.Serialize()
}

func (k *trousersKey12) close(tpm tpmBase) error {
	return nil // No state for tpm 1.2.
}

func (k *trousersKey12) activateCredential(tb tpmBase, in EncryptedCredential) ([]byte, error) {
	t, ok := tb.(*trousersTPM)
	if !ok {
		return nil, fmt.Errorf("expected *linuxTPM, got %T", tb)
	}

	cred, err := attestation.AIKChallengeResponse(t.ctx, k.blob, in.Credential, in.Secret)
	if err != nil {
		return nil, fmt.Errorf("failed to activate ak: %v", err)
	}
	return cred, nil
}

func (k *trousersKey12) quote(tb tpmBase, nonce []byte, alg HashAlg) (*Quote, error) {
	t, ok := tb.(*trousersTPM)
	if !ok {
		return nil, fmt.Errorf("expected *linuxTPM, got %T", tb)
	}
	if alg != HashSHA1 {
		return nil, fmt.Errorf("only SHA1 algorithms supported on TPM 1.2, not %v", alg)
	}

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

func (k *trousersKey12) attestationParameters() AttestationParameters {
	return AttestationParameters{
		Public:                  k.public,
		UseTCSDActivationFormat: true,
	}
}
