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
	"crypto/rand"
	"flag"
	"sort"
	"testing"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tspi/verification"
)

var (
	testTPM12   = flag.Bool("testTPM12", false, "run tests for TPM1.2")
	tpm12config = &OpenConfig{TPMVersion12}
)

func TestTPM12Info(t *testing.T) {
	if !*testTPM12 {
		t.SkipNow()
	}
	tpm, err := OpenTPM(tpm12config)
	if err != nil {
		t.Fatalf("Failed to open tpm 1.2: %v", err)
	}
	defer tpm.Close()

	Info, err := tpm.Info()
	if err != nil {
		t.Fatalf("Failed to get Vendor info: %v", err)
	}

	t.Logf("Vendor info: %s\n", Info.VendorInfo)
}

func TestTPM12PCRs(t *testing.T) {
	if !*testTPM12 {
		t.SkipNow()
	}
	tpm, err := OpenTPM(tpm12config)
	if err != nil {
		t.Fatalf("Failed to open tpm 1.2: %v", err)
	}
	defer tpm.Close()

	PCRs, _, err := tpm.PCRs()
	if err != nil {
		t.Fatalf("Failed to get PCR values: %v", err)
	}

	var indices []int
	for i, PCR := range PCRs {
		if i != PCR.Index {
			t.Errorf("Index %d does not match the PCRindex %d\n", i, PCR.Index)
		}
		indices = append(indices, i)
	}
	sort.Ints(indices)
	for i := range indices {
		PCR := PCRs[i]
		t.Logf("PCR %v contains value 0x%x, which was caculated using alg %v\n", PCR.Index, bytes.NewBuffer(PCR.Digest), PCR.DigestAlg)
	}
}

func TestTPM12EKs(t *testing.T) {
	if !*testTPM12 {
		t.SkipNow()
	}
	tpm, err := OpenTPM(tpm12config)
	if err != nil {
		t.Fatalf("Failed to open tpm 1.2: %v", err)
	}
	defer tpm.Close()

	EKs, err := tpm.EKs()
	if err != nil {
		t.Fatalf("Failed to get EKs: %v", err)
	}

	if len(EKs) == 0 {
		t.Fatalf("EKs returned nothing")
	}

	t.Logf("EKCert Raw: %x\n", EKs[0].Cert.Raw)
}

func TestMintAIK(t *testing.T) {
	if !*testTPM12 {
		t.SkipNow()
	}
	tpm, err := OpenTPM(tpm12config)
	if err != nil {
		t.Fatalf("failed to open tpm 1.2: %v", err)
	}
	defer tpm.Close()

	aik, err := tpm.MintAIK(nil)
	if err != nil {
		t.Fatalf("MintAIK failed: %v", err)
	}

	if (aik.TPMVersion != TPMVersion12) ||
		(aik.Purpose != AttestationKey) {
		t.Error("aik does not match expected format")
	}
	t.Logf("aik blob: %x\naik pubkey: %x\n", aik.KeyBlob, aik.Public)
}

func TestTPMQuote(t *testing.T) {
	if !*testTPM12 {
		t.SkipNow()
	}
	nonce := make([]byte, 20)
	rand.Read(nonce)

	tpm, err := OpenTPM(tpm12config)
	if err != nil {
		t.Fatalf("Failed to open tpm 1.2: %v", err)
	}
	defer tpm.Close()

	aik, err := tpm.MintAIK(nil)
	if err != nil {
		t.Fatalf("MintAIK failed: %v", err)
	}

	quote, err := aik.Quote(tpm, nonce, tpm2.AlgSHA1)
	if err != nil {
		t.Fatalf("Quote failed: %v", err)
	}

	t.Logf("Quote{version: %v, quote: %x, signature: %x}\n", quote.Version, quote.Quote, quote.Signature)
}

// chooseEKCertRaw selects the EK cert which will be activated against.
func chooseEKCertRaw(t *testing.T, eks []PlatformEK) []byte {
	t.Helper()

	for _, ek := range eks {
		if ek.Cert != nil && ek.Cert.PublicKeyAlgorithm == x509.RSA || ek.Cert.PublicKeyAlgorithm == x509.RSAESOAEP {
			return ek.Cert.Raw
		}
	}

	t.Skip("No suitable RSA EK found")
	return nil
}

func TestTPMActivateCredential(t *testing.T) {
	if !*testTPM12 {
		t.SkipNow()
	}
	var challenge EncryptedCredential
	nonce := make([]byte, 20)
	rand.Read(nonce)

	tpm, err := OpenTPM(tpm12config)
	if err != nil {
		t.Fatalf("failed to open tpm 1.2: %v", err)
	}
	defer tpm.Close()

	aik, err := tpm.MintAIK(nil)
	if err != nil {
		t.Fatalf("MintAIK failed: %v", err)
	}

	EKs, err := tpm.EKs()
	if err != nil {
		t.Fatalf("failed to read EKs: %v", err)
	}
	ekcert := chooseEKCertRaw(t, EKs)

	challenge.Credential, challenge.Secret, err = verification.GenerateChallenge(ekcert, aik.Public, nonce)
	if err != nil {
		t.Fatalf("GenerateChallenge failed: %v", err)
	}

	validation, err := aik.ActivateCredential(tpm, challenge)
	if err != nil {
		t.Fatalf("ActivateCredential failed: %v", err)
	}

	if !bytes.Equal(validation, nonce) {
		t.Errorf("secret mismatch: expected %x, got %x", nonce, validation)
	}

	t.Logf("validation: %x", validation)
}
