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

//go:build !localtest && cgo && !gofuzz
// +build !localtest,cgo,!gofuzz

// NOTE: simulator requires cgo, hence the build tag.

package attest

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/legacy/tpm2"
)

func setupSimulatedTPM(t *testing.T) (*simulator.Simulator, *TPM) {
	t.Helper()
	tpm, err := simulator.Get()
	if err != nil {
		t.Fatal(err)
	}
	attestTPM, err := OpenTPM(&OpenConfig{CommandChannel: &fakeCmdChannel{tpm}})
	if err != nil {
		t.Fatal(err)
	}
	return tpm, attestTPM
}

func TestSimEK(t *testing.T) {
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

func TestSimInfo(t *testing.T) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()

	if _, err := tpm.Info(); err != nil {
		t.Errorf("tpm.Info() failed: %v", err)
	}
}

func TestSimAKCreateAndLoad(t *testing.T) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()
	for _, test := range []struct {
		name string
		opts *AKConfig
	}{
		{
			name: "NoConfig",
			opts: nil,
		},
		{
			name: "EmptyConfig",
			opts: &AKConfig{},
		},
		{
			name: "RSA",
			opts: &AKConfig{Algorithm: RSA},
		},
		{
			name: "ECDSA",
			opts: &AKConfig{Algorithm: ECDSA},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ak, err := tpm.NewAK(test.opts)
			if err != nil {
				t.Fatalf("NewAK() failed: %v", err)
			}

			enc, err := ak.Marshal()
			if err != nil {
				ak.Close(tpm)
				t.Fatalf("ak.Marshal() failed: %v", err)
			}
			if err := ak.Close(tpm); err != nil {
				t.Fatalf("ak.Close() failed: %v", err)
			}

			loaded, err := tpm.LoadAK(enc)
			if err != nil {
				t.Fatalf("LoadAK() failed: %v", err)
			}
			defer loaded.Close(tpm)

			k1, k2 := ak.ak.(*wrappedKey20), loaded.ak.(*wrappedKey20)

			if !bytes.Equal(k1.public, k2.public) {
				t.Error("Original & loaded AK public blobs did not match.")
				t.Logf("Original = %v", k1.public)
				t.Logf("Loaded   = %v", k2.public)
			}
		})
	}
}

func TestSimActivateCredential(t *testing.T) {
	testActivateCredential(t, false)
}

func TestSimActivateCredentialWithEK(t *testing.T) {
	testActivateCredential(t, true)
}

func testActivateCredential(t *testing.T, useEK bool) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()

	EKs, err := tpm.EKs()
	if err != nil {
		t.Fatalf("EKs() failed: %v", err)
	}
	if len(EKs) == 0 {
		t.Fatalf("No suitable EK found")
	}
	ek := EKs[0]

	ak, err := tpm.NewAK(nil)
	if err != nil {
		t.Fatalf("NewAK() failed: %v", err)
	}
	defer ak.Close(tpm)

	ap := ActivationParameters{
		AK: ak.AttestationParameters(),
		EK: ek.Public,
	}
	secret, challenge, err := ap.Generate()
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	var decryptedSecret []byte
	if useEK {
		decryptedSecret, err = ak.ActivateCredentialWithEK(tpm, *challenge, ek)
	} else {
		decryptedSecret, err = ak.ActivateCredential(tpm, *challenge)
	}
	if err != nil {
		t.Errorf("ak.ActivateCredential() failed: %v", err)
	}
	if !bytes.Equal(secret, decryptedSecret) {
		t.Error("secret does not match decrypted secret")
		t.Logf("Secret = %v", secret)
		t.Logf("Decrypted secret = %v", decryptedSecret)
	}
}

func TestParseAKPublic(t *testing.T) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()

	ak, err := tpm.NewAK(nil)
	if err != nil {
		t.Fatalf("NewAK() failed: %v", err)
	}
	defer ak.Close(tpm)
	params := ak.AttestationParameters()
	if _, err := ParseAKPublic(params.Public); err != nil {
		t.Errorf("parsing AK public blob: %v", err)
	}
}

func TestSimQuoteAndVerifyAll(t *testing.T) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()

	ak, err := tpm.NewAK(nil)
	if err != nil {
		t.Fatalf("NewAK() failed: %v", err)
	}
	defer ak.Close(tpm)

	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	quote256, err := ak.Quote(tpm, nonce, HashSHA256)
	if err != nil {
		t.Fatalf("ak.Quote(SHA256) failed: %v", err)
	}
	quote1, err := ak.Quote(tpm, nonce, HashSHA1)
	if err != nil {
		t.Fatalf("ak.Quote(SHA1) failed: %v", err)
	}

	// Providing both PCR banks to AKPublic.Verify() ensures we can handle
	// the case where extra PCRs of a different digest algorithm are provided.
	var pcrs []PCR
	for _, alg := range []HashAlg{HashSHA256, HashSHA1} {
		p, err := tpm.PCRs(alg)
		if err != nil {
			t.Fatalf("tpm.PCRs(%v) failed: %v", alg, err)
		}
		pcrs = append(pcrs, p...)
	}

	pub, err := ParseAKPublic(ak.AttestationParameters().Public)
	if err != nil {
		t.Fatalf("ParseAKPublic() failed: %v", err)
	}

	// Ensure VerifyAll fails if a quote is missing and hence not all PCR
	// banks are covered.
	if err := pub.VerifyAll([]Quote{*quote256}, pcrs, nonce); err == nil {
		t.Error("VerifyAll().err returned nil, expected failure")
	}

	if err := pub.VerifyAll([]Quote{*quote256, *quote1}, pcrs, nonce); err != nil {
		t.Errorf("quote verification failed: %v", err)
	}
}

func TestSimAttestPlatform(t *testing.T) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()

	ak, err := tpm.NewAK(nil)
	if err != nil {
		t.Fatalf("NewAK() failed: %v", err)
	}
	defer ak.Close(tpm)

	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	attestation, err := tpm.attestPlatform(ak, nonce, nil)
	if err != nil {
		t.Fatalf("AttestPlatform() failed: %v", err)
	}

	pub, err := ParseAKPublic(attestation.Public)
	if err != nil {
		t.Fatalf("ParseAKPublic() failed: %v", err)
	}
	if err := pub.VerifyAll(attestation.Quotes, attestation.PCRs, nonce); err != nil {
		t.Errorf("quote verification failed: %v", err)
	}
}

func TestSimPCRs(t *testing.T) {
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

func TestSimPersistenceSRK(t *testing.T) {
	testPersistenceSRK(t, defaultParentConfig)
}

func TestSimPersistenceECCSRK(t *testing.T) {
	parentConfig := ParentKeyConfig{
		Algorithm: ECDSA,
		Handle:    0x81000002,
	}
	testPersistenceSRK(t, parentConfig)
}

func testPersistenceSRK(t *testing.T, parentConfig ParentKeyConfig) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()

	srkHnd, _, err := tpm.tpm.(*wrappedTPM20).getStorageRootKeyHandle(parentConfig)
	if err != nil {
		t.Fatalf("getStorageRootKeyHandle() failed: %v", err)
	}
	if srkHnd != parentConfig.Handle {
		t.Fatalf("bad SRK-equivalent handle: got 0x%x, wanted 0x%x", srkHnd, parentConfig.Handle)
	}

	srkHnd, p, err := tpm.tpm.(*wrappedTPM20).getStorageRootKeyHandle(parentConfig)
	if err != nil {
		t.Fatalf("second getStorageRootKeyHandle() failed: %v", err)
	}
	if srkHnd != parentConfig.Handle {
		t.Fatalf("bad SRK-equivalent handle: got 0x%x, wanted 0x%x", srkHnd, parentConfig.Handle)
	}
	if p {
		t.Fatalf("generated a new key the second time; that shouldn't happen")
	}
}

func TestSimPersistenceEK(t *testing.T) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()

	eks, err := tpm.EKs()
	if err != nil {
		t.Errorf("EKs() failed: %v", err)
	}
	if len(eks) == 0 || (eks[0].Public == nil) {
		t.Errorf("EKs() = %v, want at least 1 EK with populated fields", eks)
	}

	ek := eks[0]
	ekHnd, _, err := tpm.tpm.(*wrappedTPM20).getEndorsementKeyHandle(&ek)
	if err != nil {
		t.Fatalf("getStorageRootKeyHandle() failed: %v", err)
	}
	if ekHnd != ek.handle {
		t.Fatalf("bad EK-equivalent handle: got 0x%x, wanted 0x%x", ekHnd, ek.handle)
	}

	ekHnd, p, err := tpm.tpm.(*wrappedTPM20).getEndorsementKeyHandle(&ek)
	if err != nil {
		t.Fatalf("second getEndorsementKeyHandle() failed: %v", err)
	}
	if ekHnd != ek.handle {
		t.Fatalf("bad EK-equivalent handle: got 0x%x, wanted 0x%x", ekHnd, ek.handle)
	}
	if p {
		t.Fatalf("generated a new key the second time; that shouldn't happen")
	}
}

func TestTPMHash(t *testing.T) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()

	sizes := []int{
		tpm2BMaxBufferSize / 2,
		tpm2BMaxBufferSize - 1,
		tpm2BMaxBufferSize,
		tpm2BMaxBufferSize + 1,
		tpm2BMaxBufferSize * 1.5,
		tpm2BMaxBufferSize*2 - 1,
		tpm2BMaxBufferSize * 2,
		tpm2BMaxBufferSize*2 + 1,
	}

	for _, size := range sizes {
		t.Run(fmt.Sprintf("size=%d", size), func(t *testing.T) {
			msg := make([]byte, size)
			rand.Read(msg)

			digest, validation, err := tpmHash(tpm.tpm.(*wrappedTPM20).rwc, msg, crypto.SHA256)
			if err != nil {
				t.Fatalf("Hash() failed: %v", err)
			}

			trueDigest := sha256.Sum256(msg)
			if !bytes.Equal(digest, trueDigest[:]) {
				t.Errorf("Hash() = %v, want %v", digest, trueDigest[:])
			}

			if validation.Hierarchy == tpm2.HandleNull {
				t.Errorf("Hash() validation.Hierarchy = tpm2.HandleNull")
			}
		})
	}
}

func TestTPMHashMsgTooShort(t *testing.T) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()

	// TPM will refuse to hash a message that is too short.
	sizes := []int{0, 1, 2}

	for _, size := range sizes {
		t.Run(fmt.Sprintf("size=%d", size), func(t *testing.T) {
			msg := make([]byte, size)
			_, _, err := tpmHash(tpm.tpm.(*wrappedTPM20).rwc, msg, crypto.SHA256)
			if err == nil {
				t.Errorf("Hash() succeeded, want error")
			}
		})
	}
}

func TestSignMsg(t *testing.T) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()

	ak, err := tpm.NewAK(nil)
	if err != nil {
		t.Fatalf("NewAK() failed: %v", err)
	}

	msg := []byte("hello world")
	hashed := sha256.Sum256(msg)

	sig, err := ak.SignMsg(tpm, msg, crypto.SHA256)
	if err != nil {
		t.Fatalf("SignMsg() failed: %v", err)
	}

	if err := rsa.VerifyPKCS1v15(ak.Public().(*rsa.PublicKey), crypto.SHA256, hashed[:], sig); err != nil {
		t.Errorf("rsa.VerifyPKCS1v15() failed: %v", err)
	}
}
