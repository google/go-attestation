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
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"io"
)

type appKey interface {
	close(tpmBase) error
	marshal() ([]byte, error)
	attestationParameters() AttestationParameters
	sign(tpmBase, []byte) ([]byte, error)
	decrypt(tpmBase, []byte) ([]byte, error)
}

// ApplicationKey represents a key which can be used for signing and decrypting
// outside-TPM objects.
type ApplicationKey struct {
	appKey appKey
	pub    crypto.PublicKey
	tpm    tpmBase
}

// signer implements crypto.Signer returned by ApplicationKey.Private().
type signer struct {
	appKey appKey
	pub    crypto.PublicKey
	tpm    tpmBase
}

// Sign signs digest with the TPM-stored private signing key.
func (s *signer) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.appKey.sign(s.tpm, digest)
}

// Public returns the public key corresponding to the private signing key.
func (s *signer) Public() crypto.PublicKey {
	return s.pub
}

// AppKeyConfig encapsulates parameters for minting keys. This type is defined
// now (despite being empty) for future interface compatibility.
type AppKeyConfig struct {
}

// Public returns the public key corresponding to the private key.
func (a *ApplicationKey) Public() crypto.PublicKey {
	return a.pub
}

// Private returns an object allowing to use the TPM-backed private key.
// For now it implements only crypto.Signer.
func (a *ApplicationKey) Private(pub crypto.PublicKey) (crypto.PrivateKey, error) {
	switch pub.(type) {
	case *rsa.PublicKey:
		if _, ok := a.pub.(*rsa.PublicKey); !ok {
			return nil, fmt.Errorf("incompatible public key types: %T != %T", pub, a.pub)
		}
	case *ecdsa.PublicKey:
		if _, ok := a.pub.(*ecdsa.PublicKey); !ok {
			return nil, fmt.Errorf("incompatible public key types: %T != %T", pub, a.pub)
		}
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", pub)
	}
	return &signer{a.appKey, a.pub, a.tpm}, nil
}

// Close unloads the key from the system.
func (a *ApplicationKey) Close() error {
	return a.appKey.close(a.tpm)
}

// Marshal encodes the key in a format that can be loaded with tpm.LoadAppKey().
// This method exists to allow consumers to store the key persistently and load
// it as a later time. Users SHOULD NOT attempt to interpret or extract values
// from this blob.
func (a *ApplicationKey) Marshal() ([]byte, error) {
	return a.appKey.marshal()
}

// AttestationParameters returns information about the key, typically used to
// prove key certification.
func (a *ApplicationKey) AttestationParameters() AttestationParameters {
	return a.appKey.attestationParameters()
}
