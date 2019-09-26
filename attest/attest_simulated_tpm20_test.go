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
// +build cgo

// NOTE: simulator requires cgo, hence the build tag.

package attest

import (
	"bytes"
	"crypto"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
)

func setupSimulatedTPM(t *testing.T) (*simulator.Simulator, *TPM) {
	t.Helper()
	tpm, err := simulator.Get()
	if err != nil {
		t.Fatal(err)
	}
	return tpm, &TPM{tpm: &platformTPM{
		version: TPMVersion20,
		interf:  TPMInterfaceKernelManaged,
		sysPath: "/dev/tpmrm0",
		rwc:     tpm,
	}}
}

func TestSimTPM20EK(t *testing.T) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()

	eks, err := tpm.EKs()
	if err != nil {
		t.Errorf("EKs() failed: %v", err)
	}
	if len(eks) == 0 || (eks[0].Public == nil) {
		t.Errorf("EKs() = %v, want at least 1 EK with populated fields", eks)
	}
}

func TestSimTPM20Info(t *testing.T) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()

	if _, err := tpm.Info(); err != nil {
		t.Errorf("tpm.Info() failed: %v", err)
	}
}

func TestSimTPM20AIKCreateAndLoad(t *testing.T) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()

	aik, err := tpm.NewAIK(nil)
	if err != nil {
		t.Fatalf("NewAIK() failed: %v", err)
	}

	enc, err := aik.Marshal()
	if err != nil {
		aik.Close(tpm)
		t.Fatalf("aik.Marshal() failed: %v", err)
	}
	if err := aik.Close(tpm); err != nil {
		t.Fatalf("aik.Close() failed: %v", err)
	}

	loaded, err := tpm.LoadAIK(enc)
	if err != nil {
		t.Fatalf("LoadKey() failed: %v", err)
	}
	defer loaded.Close(tpm)

	k1, k2 := aik.aik.(*key20), loaded.aik.(*key20)

	if !bytes.Equal(k1.public, k2.public) {
		t.Error("Original & loaded AIK public blobs did not match.")
		t.Logf("Original = %v", k1.public)
		t.Logf("Loaded   = %v", k2.public)
	}
}

func TestSimTPM20ActivateCredential(t *testing.T) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()

	aik, err := tpm.NewAIK(nil)
	if err != nil {
		t.Fatalf("NewAIK() failed: %v", err)
	}
	defer aik.Close(tpm)

	EKs, err := tpm.EKs()
	if err != nil {
		t.Fatalf("EKs() failed: %v", err)
	}
	ek := chooseEK(t, EKs)

	ap := ActivationParameters{
		TPMVersion: TPMVersion20,
		AIK:        aik.AttestationParameters(),
		EK:         ek,
	}
	secret, challenge, err := ap.Generate()
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	decryptedSecret, err := aik.ActivateCredential(tpm, *challenge)
	if err != nil {
		t.Errorf("aik.ActivateCredential() failed: %v", err)
	}
	if !bytes.Equal(secret, decryptedSecret) {
		t.Error("secret does not match decrypted secret")
		t.Logf("Secret = %v", secret)
		t.Logf("Decrypted secret = %v", decryptedSecret)
	}
}

func TestParseAIKPublic20(t *testing.T) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()

	aik, err := tpm.NewAIK(nil)
	if err != nil {
		t.Fatalf("NewAIK() failed: %v", err)
	}
	defer aik.Close(tpm)
	params := aik.AttestationParameters()
	if _, err := ParseAIKPublic(TPMVersion20, params.Public); err != nil {
		t.Errorf("parsing AIK public blob: %v", err)
	}
}

func TestSimTPM20QuoteAndVerify(t *testing.T) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()

	aik, err := tpm.NewAIK(nil)
	if err != nil {
		t.Fatalf("NewAIK() failed: %v", err)
	}
	defer aik.Close(tpm)

	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	quote, err := aik.Quote(tpm, nonce, HashSHA256)
	if err != nil {
		t.Fatalf("aik.Quote() failed: %v", err)
	}

	// Providing both PCR banks to AIKPublic.Verify() ensures we can handle
	// the case where extra PCRs of a different digest algorithm are provided.
	var pcrs []PCR
	for _, alg := range []HashAlg{HashSHA256, HashSHA1} {
		p, err := tpm.PCRs(alg)
		if err != nil {
			t.Fatalf("tpm.PCRs(%v) failed: %v", alg, err)
		}
		pcrs = append(pcrs, p...)
	}

	pub, err := ParseAIKPublic(tpm.Version(), aik.AttestationParameters().Public)
	if err != nil {
		t.Fatalf("ParseAIKPublic() failed: %v", err)
	}
	if err := pub.Verify(*quote, pcrs, nonce); err != nil {
		t.Errorf("quote verification failed: %v", err)
	}
}

func TestSimTPM20AttestPlatform(t *testing.T) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()

	aik, err := tpm.NewAIK(nil)
	if err != nil {
		t.Fatalf("NewAIK() failed: %v", err)
	}
	defer aik.Close(tpm)

	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	attestation, err := tpm.attestPlatform(aik, nonce, nil)
	if err != nil {
		t.Fatalf("AttestPlatform() failed: %v", err)
	}

	pub, err := ParseAIKPublic(attestation.TPMVersion, attestation.Public)
	if err != nil {
		t.Fatalf("ParseAIKPublic() failed: %v", err)
	}
	for i, q := range attestation.Quotes {
		if err := pub.Verify(q, attestation.PCRs, nonce); err != nil {
			t.Errorf("quote[%d] verification failed: %v", i, err)
		}
	}
}

func TestSimTPM20PCRs(t *testing.T) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()

	PCRs, err := tpm.PCRs(HashSHA256)
	if err != nil {
		t.Fatalf("PCRs() failed: %v", err)
	}
	if len(PCRs) != 24 {
		t.Errorf("len(PCRs) = %d, want %d", len(PCRs), 24)
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

	ekHnd, _, err := tpm.tpm.getPrimaryKeyHandle(commonEkEquivalentHandle)
	if err != nil {
		t.Fatalf("getPrimaryKeyHandle() failed: %v", err)
	}
	if ekHnd != commonEkEquivalentHandle {
		t.Fatalf("bad EK-equivalent handle: got 0x%x, wanted 0x%x", ekHnd, commonEkEquivalentHandle)
	}

	ekHnd, p, err := tpm.tpm.getPrimaryKeyHandle(commonEkEquivalentHandle)
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
