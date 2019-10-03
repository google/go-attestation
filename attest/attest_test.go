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
	"flag"
	"testing"
)

var (
	testLocal = flag.Bool("testLocal", false, "run tests against local hardware")
)

func TestOpen(t *testing.T) {
	if !*testLocal {
		t.SkipNow()
	}
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
	if !*testLocal {
		t.SkipNow()
	}
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
	if !*testLocal {
		t.SkipNow()
	}
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

func TestAKCreateAndLoad(t *testing.T) {
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
		t.Fatalf("LoadKey() failed: %v", err)
	}
	defer loaded.Close(tpm)

	k1, k2 := ak.ak.(*key20), loaded.ak.(*key20)

	if !bytes.Equal(k1.public, k2.public) {
		t.Error("Original & loaded AK public blobs did not match.")
		t.Logf("Original = %v", k1.public)
		t.Logf("Loaded   = %v", k2.public)
	}
}

// chooseEK selects the EK public which will be activated against.
func chooseEK(t *testing.T, eks []EK) crypto.PublicKey {
	t.Helper()

	for _, ek := range eks {
		return ek.Public
	}

	t.Fatalf("No suitable EK found")
	return nil
}

func TestPCRs(t *testing.T) {
	if !*testLocal {
		t.SkipNow()
	}
	tpm, err := OpenTPM(nil)
	if err != nil {
		t.Fatalf("OpenTPM() failed: %v", err)
	}
	defer tpm.Close()

	PCRs, err := tpm.PCRs(HashSHA1)
	if err != nil {
		t.Fatalf("PCRs() failed: %v", err)
	}
	if len(PCRs) != 24 {
		t.Errorf("len(PCRs) = %d, want %d", len(PCRs), 24)
	}
	for i, pcr := range PCRs {
		if pcr.Index != i {
			t.Errorf("PCR index %d does not match map index %d", pcr.Index, i)
		}
	}
}
