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

// +build !localtest !tpm12
// +build cgo

// NOTE: simulator requires cgo, hence the build tag.

package attest

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"testing"
)

func TestSimTPM20KeyCreateAndLoad(t *testing.T) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()
	testKeyCreateAndLoad(t, tpm)
}

func TestTPM20KeyCreateAndLoad(t *testing.T) {
	if !*testLocal {
		t.SkipNow()
	}
	tpm, err := OpenTPM(nil)
	if err != nil {
		t.Fatalf("OpenTPM() failed: %v", err)
	}
	defer tpm.Close()
	testKeyCreateAndLoad(t, tpm)
}

func testKeyCreateAndLoad(t *testing.T, tpm *TPM) {
	ak, err := tpm.NewAK(nil)
	if err != nil {
		t.Fatalf("NewAK() failed: %v", err)
	}
	sk, err := tpm.NewKey(ak, nil)
	if err != nil {
		t.Fatalf("NewKey() failed: %v", err)
	}
	defer sk.Close()

	enc, err := sk.Marshal()
	if err != nil {
		t.Fatalf("sk.Marshal() failed: %v", err)
	}
	if err := sk.Close(); err != nil {
		t.Fatalf("sk.Close() failed: %v", err)
	}

	loaded, err := tpm.LoadKey(enc)
	if err != nil {
		t.Fatalf("LoadKey() failed: %v", err)
	}
	defer loaded.Close()

	k1, k2 := sk.key.(*wrappedKey20), loaded.key.(*wrappedKey20)
	if !bytes.Equal(k1.public, k2.public) {
		t.Error("Original & loaded Key public blobs did not match.")
		t.Logf("Original = %v", k1.public)
		t.Logf("Loaded   = %v", k2.public)
	}

	priv1, err := sk.Private(sk.Public())
	if err != nil {
		t.Fatalf("sk.Private() failed: %v", err)
	}
	signer1, ok := priv1.(crypto.Signer)
	if !ok {
		t.Fatalf("want crypto.Signer, got %T", priv1)
	}
	pk1, err := x509.MarshalPKIXPublicKey(signer1.Public())
	if err != nil {
		t.Fatalf("cannot marshal public key: %v", err)
	}

	priv2, err := loaded.Private(loaded.Public())
	if err != nil {
		t.Fatalf("loaded.Private() failed: %v", err)
	}
	signer2, ok := priv2.(crypto.Signer)
	if !ok {
		t.Fatalf("want crypto.Signer, got %T", priv2)
	}
	pk2, err := x509.MarshalPKIXPublicKey(signer2.Public())
	if err != nil {
		t.Fatalf("cannot marshal public key: %v", err)
	}

	if !bytes.Equal(pk1, pk2) {
		t.Error("public keys do not match")
	}
}

func TestSimTPM20KeySign(t *testing.T) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()
	testKeySign(t, tpm)
}

func TestTPM20KeySign(t *testing.T) {
	if !*testLocal {
		t.SkipNow()
	}
	tpm, err := OpenTPM(nil)
	if err != nil {
		t.Fatalf("OpenTPM() failed: %v", err)
	}
	defer tpm.Close()
	testKeySign(t, tpm)
}

func testKeySign(t *testing.T, tpm *TPM) {
	ak, err := tpm.NewAK(nil)
	if err != nil {
		t.Fatalf("NewAK() failed: %v", err)
	}
	sk, err := tpm.NewKey(ak, nil)
	if err != nil {
		t.Fatalf("NewKey() failed: %v", err)
	}
	defer sk.Close()

	pub := sk.Public()
	priv, err := sk.Private(pub)
	if err != nil {
		t.Fatalf("sk.Private() failed: %v", err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		t.Fatalf("want crypto.Signer, got %T", priv)
	}
	digest := []byte("12345678901234567890123456789012")
	sig, err := signer.Sign(rand.Reader, digest, nil)
	if !ok {
		t.Fatalf("signer.Sign() failed: %v", err)
	}

	pubECDSA, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("want *ecdsa.PublicKey, got %T", pub)
	}
	if !ecdsa.VerifyASN1(pubECDSA, digest, sig) {
		t.Fatalf("ecdsa.Verify() failed")
	}
}
