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
	"crypto/x509"
	"testing"
)

func TestSimTPM20SKCreateAndLoad(t *testing.T) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()

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
		sk.Close(tpm)
		t.Fatalf("sk.Marshal() failed: %v", err)
	}
	if err := sk.Close(tpm); err != nil {
		t.Fatalf("sk.Close() failed: %v", err)
	}

	loaded, err := tpm.LoadSK(enc)
	if err != nil {
		t.Fatalf("LoadKey() failed: %v", err)
	}
	defer loaded.Close(tpm)

	k1, k2 := sk.sk.(*wrappedKey20), loaded.sk.(*wrappedKey20)

	if !bytes.Equal(k1.public, k2.public) {
		t.Error("Original & loaded SK public blobs did not match.")
		t.Logf("Original = %v", k1.public)
		t.Logf("Loaded   = %v", k2.public)
	}

	pk1, err := x509.MarshalPKIXPublicKey(sk.signer.Public())
	if err != nil {
		t.Fatalf("cannot marshal public key: %v", err)
	}
	pk2, err := x509.MarshalPKIXPublicKey(loaded.signer.Public())
	if err != nil {
		t.Fatalf("cannot marshal public key: %v", err)
	}
	if !bytes.Equal(pk1, pk2) {
		t.Errorf("public keys do noy match")
	}
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
		sk.Close(tpm)
		t.Fatalf("sk.Marshal() failed: %v", err)
	}
	if err := sk.Close(tpm); err != nil {
		t.Fatalf("sk.Close() failed: %v", err)
	}

	loaded, err := tpm.LoadSK(enc)
	if err != nil {
		t.Fatalf("LoadKey() failed: %v", err)
	}
	defer loaded.Close(tpm)

	k1, k2 := sk.sk.(*wrappedKey20), loaded.sk.(*wrappedKey20)
	if !bytes.Equal(k1.public, k2.public) {
		t.Error("Original & loaded SK public blobs did not match.")
		t.Logf("Original = %v", k1.public)
		t.Logf("Loaded   = %v", k2.public)
	}

	pk1, err := x509.MarshalPKIXPublicKey(sk.signer.Public())
	if err != nil {
		t.Fatalf("cannot marshal public key: %v", err)
	}
	pk2, err := x509.MarshalPKIXPublicKey(loaded.signer.Public())
	if err != nil {
		t.Fatalf("cannot marshal public key: %v", err)
	}
	if !bytes.Equal(pk1, pk2) {
		t.Errorf("public keys do noy match")
	}
}
