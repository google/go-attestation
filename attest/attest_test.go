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
	"flag"
	"fmt"
	"reflect"
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

	k1, k2 := ak.ak.(*wrappedKey20), loaded.ak.(*wrappedKey20)

	if !bytes.Equal(k1.public, k2.public) {
		t.Error("Original & loaded AK public blobs did not match.")
		t.Logf("Original = %v", k1.public)
		t.Logf("Loaded   = %v", k2.public)
	}
}

// chooseEK selects the EK which will be activated against.
func chooseEK(t *testing.T, eks []EK) EK {
	t.Helper()

	for _, ek := range eks {
		return ek
	}

	t.Fatalf("No suitable EK found")
	return EK{}
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

func TestBug139(t *testing.T) {
	// Tests ParseAKPublic() with known parseable but non-spec-compliant blobs, and ensure
	// an error is returned rather than a segfault.
	// https://github.com/google/go-attestation/issues/139
	badBlob := []byte{0, 1, 0, 4, 0, 1, 0, 0, 0, 0, 0, 6, 0, 128, 0, 67, 0, 16, 8, 0, 0, 1, 0, 1, 0, 0}
	msg := "parsing public key: missing rsa signature scheme"
	if _, err := ParseAKPublic(TPMVersion20, badBlob); err == nil || err.Error() != msg {
		t.Errorf("ParseAKPublic() err = %v, want %v", err, msg)
	}
}

func TestBug142(t *testing.T) {
	// Tests ParseEKCertificate() with a malformed size prefix which would overflow
	// an int16, ensuring an error is returned rather than a panic occurring.
	input := []byte{0x10, 0x01, 0x00, 0xff, 0xff, 0x20}
	wantErr := fmt.Errorf("parsing nvram header: ekCert size %d smaller than specified cert length %d", len(input), 65535)
	if _, err := ParseEKCertificate(input); !reflect.DeepEqual(err, wantErr) {
		t.Errorf("ParseEKCertificate() = %v, want %v", err, wantErr)
	}
}
