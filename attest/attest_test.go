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

package attest

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"testing"

	"github.com/google/certificate-transparency-go/x509"

	"github.com/google/go-tpm/tpm2/credactivation"
	"github.com/google/go-tpm/tpm2"
)

func TestOpen(t *testing.T) {
	tpm, err := OpenTPM(nil)
	if err != nil {
		t.Fatalf("OpenTPM() failed: %v", err)
	}
	if tpm == nil {
		t.Fatalf("Expected non-nil tpm struct")
	}
	defer tpm.Close()
}

func TestInfo(t *testing.T) {
	tpm, err := OpenTPM(nil)
	if err != nil {
		t.Fatalf("OpenTPM() failed: %v", err)
	}
	defer tpm.Close()

	info, err := tpm.Info()
	if err != nil {
		t.Errorf("tpm.Info() failed: %v", err)
	}
	if info.Manufacturer.String() == "" {
		t.Error("Expected info.Manufacturer.String() != ''")
	}
	t.Logf("TPM Info = %+v", info)
}

func TestEKs(t *testing.T) {
	tpm, err := OpenTPM(nil)
	if err != nil {
		t.Fatalf("OpenTPM() failed: %v", err)
	}
	defer tpm.Close()

	eks, err := tpm.EKs()
	if err != nil {
		t.Errorf("EKs() failed: %v", err)
	}
	if len(eks) == 0 {
		t.Log("EKs() did not return anything. This could be an issue if an EK is present.")
	}
}

func TestAIKCreateAndLoad(t *testing.T) {
	tpm, err := OpenTPM(nil)
	if err != nil {
		t.Fatalf("OpenTPM() failed: %v", err)
	}
	defer tpm.Close()

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

// chooseEK selects the EK public which will be activated against.
func chooseEK(t *testing.T, eks []PlatformEK) crypto.PublicKey {
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

func TestActivateCredentialTPM20(t *testing.T) {
	tpm, err := OpenTPM(nil)
	if err != nil {
		t.Fatalf("OpenTPM() failed: %v", err)
	}
	defer tpm.Close()
	if tpm.version != TPMVersion20 {
		t.Skip("N/A for non-TPM2.0 TPMs")
	}

	aik, err := tpm.MintAIK(nil)
	if err != nil {
		t.Fatalf("MintAIK() failed: %v", err)
	}
	defer aik.Close(tpm)

	EKs, err := tpm.EKs()
	if err != nil {
		t.Fatalf("EKs() failed: %v", err)
	}
	ek := chooseEK(t, EKs)

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

func TestQuoteTPM20(t *testing.T) {
	tpm, err := OpenTPM(nil)
	if err != nil {
		t.Fatalf("OpenTPM() failed: %v", err)
	}
	defer tpm.Close()
	if tpm.version != TPMVersion20 {
		t.Skip("N/A for non-TPM2.0 TPMs")
	}

	aik, err := tpm.MintAIK(nil)
	if err != nil {
		t.Fatalf("MintAIK() failed: %v", err)
	}
	defer aik.Close(tpm)

	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	quote, err := aik.Quote(tpm, nonce, tpm2.AlgSHA1)
	if err != nil {
		t.Fatalf("aik.Quote() failed: %v", err)
	}
	// TODO(jsonp): Parse quote structure once gotpm/tpm2 supports it.
	if quote == nil {
		t.Error("quote was nil, want *Quote")
	}
}

func TestPCRsTPM20(t *testing.T) {
	tpm, err := OpenTPM(nil)
	if err != nil {
		t.Fatalf("OpenTPM() failed: %v", err)
	}
	defer tpm.Close()
	if tpm.version != TPMVersion20 {
		t.Skip("N/A for non-TPM2.0 TPMs")
	}

	PCRs, _, err := tpm.PCRs()
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
		if pcr.DigestAlg != crypto.SHA1 {
			t.Errorf("pcr.DigestAlg = %v, expected crypto.SHA1", pcr.DigestAlg)
		}
	}
}
