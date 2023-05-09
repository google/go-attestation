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

type key interface {
	close(tpmBase) error
	marshal() ([]byte, error)
	certificationParameters() CertificationParameters
	sign(tpmBase, []byte, crypto.PublicKey, crypto.SignerOpts) ([]byte, error)
	decrypt(tpmBase, []byte) ([]byte, error)
	blobs() ([]byte, []byte, error)
}

// Key represents a key which can be used for signing and decrypting
// outside-TPM objects.
type Key struct {
	key key
	pub crypto.PublicKey
	tpm tpmBase
}

// signer implements crypto.Signer returned by Key.Private().
type signer struct {
	key key
	pub crypto.PublicKey
	tpm tpmBase
}

// Sign signs digest with the TPM-stored private signing key.
func (s *signer) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.key.sign(s.tpm, digest, s.pub, opts)
}

// Public returns the public key corresponding to the private signing key.
func (s *signer) Public() crypto.PublicKey {
	return s.pub
}

// Algorithm indicates an asymmetric algorithm to be used.
type Algorithm string

// Algorithm types supported.
const (
	ECDSA Algorithm = "ECDSA"
	RSA   Algorithm = "RSA"
)

// KeyConfig encapsulates parameters for minting keys.
type KeyConfig struct {
	// Algorithm to be used, either RSA or ECDSA.
	Algorithm Algorithm
	// Size is used to specify the bit size of the key or elliptic curve. For
	// example, '256' is used to specify curve P-256.
	Size int
	// QualifyingData is data provided from outside to the TPM when an attestation
	// operation is performed. The TPM doesn't interpret the data, but does sign over
	// it. It can be used as a nonce to ensure freshness of an attestation.
	QualifyingData []byte
	// Name is used to specify a name for the key, instead of generating
	// a random one. This property is only used on Windows.
	Name string
}

// defaultConfig is used when no other configuration is specified.
var defaultConfig = &KeyConfig{
	Algorithm: ECDSA,
	Size:      256,
}

// Public returns the public key corresponding to the private key.
func (k *Key) Public() crypto.PublicKey {
	return k.pub
}

// Private returns an object allowing to use the TPM-backed private key.
// For now it implements only crypto.Signer.
func (k *Key) Private(pub crypto.PublicKey) (crypto.PrivateKey, error) {
	switch pub.(type) {
	case *rsa.PublicKey:
		if _, ok := k.pub.(*rsa.PublicKey); !ok {
			return nil, fmt.Errorf("incompatible public key types: %T != %T", pub, k.pub)
		}
	case *ecdsa.PublicKey:
		if _, ok := k.pub.(*ecdsa.PublicKey); !ok {
			return nil, fmt.Errorf("incompatible public key types: %T != %T", pub, k.pub)
		}
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", pub)
	}
	return &signer{k.key, k.pub, k.tpm}, nil
}

// Close unloads the key from the system.
func (k *Key) Close() error {
	return k.key.close(k.tpm)
}

// Marshal encodes the key in a format that can be loaded with tpm.LoadKey().
// This method exists to allow consumers to store the key persistently and load
// it as a later time. Users SHOULD NOT attempt to interpret or extract values
// from this blob.
func (k *Key) Marshal() ([]byte, error) {
	return k.key.marshal()
}

// CertificationParameters returns information about the key required to
// verify key certification.
func (k *Key) CertificationParameters() CertificationParameters {
	return k.key.certificationParameters()
}

// Blobs returns public and private blobs to be used by tpm2.Load().
func (k *Key) Blobs() (pub, priv []byte, err error) {
	return k.key.blobs()
}
