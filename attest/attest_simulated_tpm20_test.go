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

// +build !localtest !tpm12

package attest

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"testing"

	"github.com/google/certificate-transparency-go/x509"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/credactivation"
)

func setupSimulatedTPM(t *testing.T) (*simulator.Simulator, *TPM) {
	t.Helper()
	tpm, err := simulator.Get()
	if err != nil {
		t.Fatal(err)
	}
	return tpm, &TPM{
		version: TPMVersion20,
		interf:  TPMInterfaceKernelManaged,
		sysPath: "/dev/tpmrm0",
		rwc:     tpm,
	}
}

func TestSimTPM20EK(t *testing.T) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()

	eks, err := tpm.EKs()
	if err != nil {
		t.Errorf("EKs() failed: %v", err)
	}
	if len(eks) == 0 || (eks[0].Cert == nil && eks[0].Public == nil) {
		t.Errorf("EKs() = %v, want at least 1 EK with populated fields", eks)
	}
}

func TestSimTPM20Info(t *testing.T) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()

	info, err := tpm.Info()
	if err != nil {
		t.Errorf("tpm.Info() failed: %v", err)
	}
	// We dont expect anything to be meaningfully populated as this is a simulator.
	t.Logf("TPM Info = %+v", info)
}

func TestSimTPM20AIKCreateAndLoad(t *testing.T) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()

	aik, err := tpm.MintAIK(nil)
	if err != nil {
		t.Fatalf("MintAIK() failed: %v", err)
	}

	enc, err := aik.Marshal()
	if err != nil {
		aik.Close(tpm)
		t.Fatalf("aik.Marshal() failed: %v", err)
	}
	if err := aik.Close(tpm); err != nil {
		t.Fatalf("aik.Close() failed: %v", err)
	}

	loaded, err := tpm.LoadKey(enc)
	if err != nil {
		t.Fatalf("LoadKey() failed: %v", err)
	}
	defer loaded.Close(tpm)

	if !bytes.Equal(loaded.Public, aik.Public) {
		t.Error("Original & loaded AIK public blobs did not match.")
		t.Logf("Original = %v", aik.Public)
		t.Logf("Loaded   = %v", loaded.Public)
	}
}

// chooseEKPub selects the EK public which will be activated against.
func chooseEKPub(t *testing.T, eks []PlatformEK) crypto.PublicKey {
	t.Helper()

	for _, ek := range eks {
		if ek.Cert != nil && ek.Cert.PublicKeyAlgorithm == x509.RSA {
			return ek.Cert.PublicKey.(*rsa.PublicKey)
		} else if ek.Public != nil {
			return ek.Public
		}
	}

	t.Skip("No suitable RSA EK found")
	return nil
}

func TestSimTPM20ActivateCredential(t *testing.T) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()

	aik, err := tpm.MintAIK(nil)
	if err != nil {
		t.Fatalf("MintAIK() failed: %v", err)
	}
	defer aik.Close(tpm)

	EKs, err := tpm.EKs()
	if err != nil {
		t.Fatalf("EKs() failed: %v", err)
	}
	ek := chooseEKPub(t, EKs)

	att, err := tpm2.DecodeAttestationData(aik.CreateAttestation)
	if err != nil {
		t.Fatalf("tpm2.DecodeAttestationData() failed: %v", err)
	}
	secret := []byte{1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8}

	id, encSecret, err := credactivation.Generate(att.AttestedCreationInfo.Name.Digest, ek, 16, secret)
	if err != nil {
		t.Fatalf("credactivation.Generate() failed: %v", err)
	}

	decryptedSecret, err := aik.ActivateCredential(tpm, EncryptedCredential{
		Credential: id,
		Secret:     encSecret,
	})
	if err != nil {
		t.Errorf("aik.ActivateCredential() failed: %v", err)
	}
	if !bytes.Equal(secret, decryptedSecret) {
		t.Error("secret does not match decrypted secret")
		t.Logf("Secret = %v", secret)
		t.Logf("Decrypted secret = %v", decryptedSecret)
	}
}

func TestSimTPM20Quote(t *testing.T) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()

	aik, err := tpm.MintAIK(nil)
	if err != nil {
		t.Fatalf("MintAIK() failed: %v", err)
	}
	defer aik.Close(tpm)

	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	quote, err := aik.Quote(tpm, nonce, tpm2.AlgSHA256)
	if err != nil {
		t.Fatalf("aik.Quote() failed: %v", err)
	}
	// TODO(jsonp): Parse quote structure once gotpm/tpm2 supports it.
	if quote == nil {
		t.Error("quote was nil, want *Quote")
	}
}

func TestSimTPM20PCRs(t *testing.T) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()

	PCRs, alg, err := tpm.PCRs()
	if err != nil {
		t.Fatalf("PCRs() failed: %v", err)
	}
	if len(PCRs) != 24 {
		t.Errorf("len(PCRs) = %d, want %d", len(PCRs), 24)
	}
	if got, want := tpm2.AlgSHA256, alg; got != want {
		t.Errorf("alg = %v, want %v", got, want)
	}
	for i, pcr := range PCRs {
		if len(pcr.Digest) != pcr.DigestAlg.Size() {
			t.Errorf("PCR %d len(digest) = %d, expected match with digest algorithm size (%d)", pcr.Index, len(pcr.Digest), pcr.DigestAlg.Size())
		}
		if pcr.Index != i {
			t.Errorf("PCR index %d does not match map index %d", pcr.Index, i)
		}
		if pcr.DigestAlg != crypto.SHA256 {
			t.Errorf("pcr.DigestAlg = %v, expected crypto.SHA256", pcr.DigestAlg)
		}
	}
}

func TestSimTPM20Persistence(t *testing.T) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()

	ekHnd, p, err := tpm.getPrimaryKeyHandle(commonEkEquivalentHandle)
	if err != nil {
		t.Fatalf("getPrimaryKeyHandle() failed: %v", err)
	}
	if ekHnd != commonEkEquivalentHandle {
		t.Fatalf("bad EK-equivalent handle: got 0x%x, wanted 0x%x", ekHnd, commonEkEquivalentHandle)
	}
	if p {
		t.Logf("generated a new key")
	} else {
		t.Logf("used existing key")
	}

	ekHnd, p, err = tpm.getPrimaryKeyHandle(commonEkEquivalentHandle)
	if err != nil {
		t.Fatalf("second getPrimaryKeyHandle() failed: %v", err)
	}
	if ekHnd != commonEkEquivalentHandle {
		t.Fatalf("bad EK-equivalent handle: got 0x%x, wanted 0x%x", ekHnd, commonEkEquivalentHandle)
	}
	if p {
		t.Fatalf("generated a new key the second time; that shouldn't happen")
	}
}
