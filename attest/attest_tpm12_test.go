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
)

var (
	testTPM12   = flag.Bool("testTPM12", false, "run tests for TPM1.2")
	tpm12config = &OpenConfig{TPMVersion: TPMVersion12}
)

func openTPM12(t *testing.T) *TPM {
	if !*testTPM12 {
		t.SkipNow()
	}
	tpm, err := OpenTPM(tpm12config)
	if err != nil {
		t.Fatalf("Failed to open tpm 1.2: %v", err)
	}
	return tpm
}

func TestTPM12Info(t *testing.T) {
	tpm := openTPM12(t)
	defer tpm.Close()

	Info, err := tpm.Info()
	if err != nil {
		t.Fatalf("Failed to get Vendor info: %v", err)
	}

	t.Logf("Vendor info: %s\n", Info.VendorInfo)
}

func TestTPM12PCRs(t *testing.T) {
	tpm := openTPM12(t)
	defer tpm.Close()

	PCRs, err := tpm.PCRs(HashSHA1)
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
	tpm := openTPM12(t)
	defer tpm.Close()

	eks, err := tpm.EKs()
	if err != nil {
		t.Fatalf("Failed to get EKs: %v", err)
	}

	if len(eks) == 0 {
		t.Fatalf("EKs returned nothing")
	}
}

func TestNewAK(t *testing.T) {
	tpm := openTPM12(t)
	defer tpm.Close()

	if _, err := tpm.NewAK(nil); err != nil {
		t.Fatalf("NewAK failed: %v", err)
	}
}

func TestTPMQuote(t *testing.T) {
	tpm := openTPM12(t)
	defer tpm.Close()

	nonce := make([]byte, 20)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("reading nonce: %v", err)
	}

	ak, err := tpm.NewAK(nil)
	if err != nil {
		t.Fatalf("NewAK failed: %v", err)
	}

	quote, err := ak.Quote(tpm, nonce, HashSHA1)
	if err != nil {
		t.Fatalf("Quote failed: %v", err)
	}

	t.Logf("Quote{version: %v, quote: %x, signature: %x}\n", quote.Version, quote.Quote, quote.Signature)
}

func TestParseAKPublic12(t *testing.T) {
	tpm := openTPM12(t)
	defer tpm.Close()

	ak, err := tpm.NewAK(nil)
	if err != nil {
		t.Fatalf("NewAK() failed: %v", err)
	}
	defer ak.Close(tpm)
	params := ak.AttestationParameters()
	if _, err := ParseAKPublic(TPMVersion12, params.Public); err != nil {
		t.Errorf("parsing AK public blob: %v", err)
	}
}

func TestTPMActivateCredential(t *testing.T) {
	tpm := openTPM12(t)
	defer tpm.Close()

	ak, err := tpm.NewAK(nil)
	if err != nil {
		t.Fatalf("NewAK failed: %v", err)
	}

	EKs, err := tpm.EKs()
	if err != nil {
		t.Fatalf("failed to read EKs: %v", err)
	}
	ek := chooseEK(t, EKs)

	ap := ActivationParameters{
		TPMVersion: TPMVersion12,
		AK:         ak.AttestationParameters(),
		EK:         ek.Public,
	}
	secret, challenge, err := ap.Generate()
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	validation, err := ak.ActivateCredential(tpm, *challenge)
	if err != nil {
		t.Fatalf("ActivateCredential failed: %v", err)
	}

	if !bytes.Equal(validation, secret) {
		t.Errorf("secret mismatch: expected %x, got %x", secret, validation)
	}

	t.Logf("validation: %x", validation)
}
