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
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"testing"
)

func TestSimTPM20SKCreateAndLoad(t *testing.T) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()
	testCreateAndLoad(t, tpm)
}

func TestTPM20SKCreateAndLoad(t *testing.T) {
	if !*testLocal {
		t.SkipNow()
	}
	tpm, err := OpenTPM(nil)
	if err != nil {
		t.Fatalf("OpenTPM() failed: %v", err)
	}
	defer tpm.Close()
	testCreateAndLoad(t, tpm)
}

func testCreateAndLoad(t *testing.T, tpm *TPM) {
	ak, err := tpm.NewAK(nil)
	if err != nil {
		t.Fatalf("NewAK() failed: %v", err)
	}
	sk, err := tpm.NewSK(ak, nil)
	if err != nil {
		t.Fatalf("NewSK() failed: %v", err)
	}

	enc, err := sk.Marshal()
	if err != nil {
		sk.Close()
		t.Fatalf("sk.Marshal() failed: %v", err)
	}
	if err := sk.Close(); err != nil {
		t.Fatalf("sk.Close() failed: %v", err)
	}

	loaded, err := tpm.LoadSK(enc)
	if err != nil {
		t.Fatalf("LoadKey() failed: %v", err)
	}
	defer loaded.Close()

	k1, k2 := sk.sk.(*wrappedKey20), loaded.sk.(*wrappedKey20)
	if !bytes.Equal(k1.public, k2.public) {
		t.Error("Original & loaded SK public blobs did not match.")
		t.Logf("Original = %v", k1.public)
		t.Logf("Loaded   = %v", k2.public)
	}

	pk1, err := x509.MarshalPKIXPublicKey(sk.Public())
	if err != nil {
		t.Fatalf("cannot marshal public key: %v", err)
	}
	pk2, err := x509.MarshalPKIXPublicKey(loaded.Public())
	if err != nil {
		t.Fatalf("cannot marshal public key: %v", err)
	}
	if !bytes.Equal(pk1, pk2) {
		t.Errorf("public keys do noy match")
	}
}

func TestSimTPM20SKSigning(t *testing.T) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()
	testSKSigning(t, tpm)
}

func TestTPM20SKSigning(t *testing.T) {
	if !*testLocal {
		t.SkipNow()
	}
	tpm, err := OpenTPM(nil)
	if err != nil {
		t.Fatalf("OpenTPM() failed: %v", err)
	}
	defer tpm.Close()
	testSKSigning(t, tpm)
}

func testSKSigning(t *testing.T, tpm *TPM) {
	ak, err := tpm.NewAK(nil)
	if err != nil {
		t.Fatalf("NewAK() failed: %v", err)
	}
	sk, err := tpm.NewSK(ak, nil)
	if err != nil {
		t.Fatalf("NewSK() failed: %v", err)
	}
	digest := []byte("01234567890123456789012345678901")
	sigRaw, err := sk.Sign(nil, digest, nil)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}
	var sig struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(sigRaw, &sig); err != nil {
		t.Fatalf("incorrect signature format")
	}
	pub, ok := sk.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("non-ECDSA public key")
	}
	if !ecdsa.Verify(pub, digest, sig.R, sig.S) {
		t.Fatalf("signature verification failed")
	}
}
