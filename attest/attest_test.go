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

func TestEKCertificates(t *testing.T) {
	if !*testLocal {
		t.SkipNow()
	}
	tpm, err := OpenTPM(nil)
	if err != nil {
		t.Fatalf("OpenTPM() failed: %v", err)
	}
	defer tpm.Close()

	eks, err := tpm.EKCertificates()
	if err != nil {
		t.Errorf("EKCertificates() failed: %v", err)
	}
	if len(eks) == 0 {
		t.Log("EKCertificates() did not return anything. This could be an issue if an EK is present.")
	}
}

func TestAKCreateAndLoad(t *testing.T) {
	if !*testLocal {
		t.SkipNow()
	}
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
			tpm, err := OpenTPM(nil)
			if err != nil {
				t.Fatalf("OpenTPM() failed: %v", err)
			}
			defer tpm.Close()

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

			k1 := ak.ak.attestationParameters()
			k2 := loaded.ak.attestationParameters()

			if !bytes.Equal(k1.Public, k2.Public) {
				t.Error("Original & loaded AK public blobs did not match.")
				t.Logf("Original = %v", k1.Public)
				t.Logf("Loaded   = %v", k2.Public)
			}
		})
	}
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
	if _, err := ParseAKPublic(badBlob); err == nil || err.Error() != msg {
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

func TestFromCryptoHash(t *testing.T) {
	tests := []struct {
		hash crypto.Hash
		want HashAlg
		err  bool
	}{
		{
			hash: crypto.SHA1,
			want: HashSHA1,
		},
		{
			hash: crypto.SHA256,
			want: HashSHA256,
		},
		{
			hash: crypto.SHA384,
			want: HashSHA384,
		},
		{
			hash: crypto.SHA512,
			want: HashSHA512,
		},
		{
			hash: crypto.MD5,
			err:  true,
		},
	}

	for _, tc := range tests {
		got, err := FromCryptoHash(tc.hash)
		if tc.err != (err != nil) {
			t.Errorf("FromCryptoHash(%v) returned err=%v, want err=%v", tc.hash, err, tc.err)
		}
		if got != tc.want {
			t.Errorf("FromCryptoHash(%v) = %v, want %v", tc.hash, got, tc.want)
		}
	}
}
