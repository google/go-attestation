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
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

// Dump describes the layout of serialized information from the dump command.
type Dump struct {
	Static struct {
		TPMVersion TPMVersion
		EKPem      []byte
	}

	AK AttestationParameters

	Quote struct {
		Nonce     []byte
		Alg       HashAlg
		Quote     []byte
		Signature []byte
	}

	Log struct {
		PCRs   []PCR
		PCRAlg tpm2.Algorithm
		Raw    []byte // The measured boot log in binary form.
	}
}

func TestParseEventLogWindows(t *testing.T) {
	testParseEventLog(t, "testdata/windows_gcp_shielded_vm.json")
}

func TestParseEventLogLinux(t *testing.T) {
	testParseEventLog(t, "testdata/linux_tpm12.json")
}

func testParseEventLog(t *testing.T, testdata string) {
	data, err := ioutil.ReadFile(testdata)
	if err != nil {
		t.Fatalf("reading test data: %v", err)
	}
	var dump Dump
	if err := json.Unmarshal(data, &dump); err != nil {
		t.Fatalf("parsing test data: %v", err)
	}
	if _, err := ParseEventLog(dump.Log.Raw); err != nil {
		t.Fatalf("parsing event log: %v", err)
	}
}

func TestParseCryptoAgileEventLog(t *testing.T) {
	data, err := ioutil.ReadFile("testdata/crypto_agile_eventlog")
	if err != nil {
		t.Fatalf("reading test data: %v", err)
	}
	if _, err := ParseEventLog(data); err != nil {
		t.Fatalf("parsing event log: %v", err)
	}
}

func TestEventLogLinux(t *testing.T) {
	testEventLog(t, "testdata/linux_tpm12.json")
}

func TestEventLog(t *testing.T) {
	testEventLog(t, "testdata/windows_gcp_shielded_vm.json")
}

func testEventLog(t *testing.T, testdata string) {
	data, err := ioutil.ReadFile(testdata)
	if err != nil {
		t.Fatalf("reading test data: %v", err)
	}
	var dump Dump
	if err := json.Unmarshal(data, &dump); err != nil {
		t.Fatalf("parsing test data: %v", err)
	}

	ak, err := ParseAKPublic(dump.Static.TPMVersion, dump.AK.Public)
	if err != nil {
		t.Fatalf("parsing AK: %v", err)
	}
	if err := ak.Verify(Quote{
		Version:   dump.Static.TPMVersion,
		Quote:     dump.Quote.Quote,
		Signature: dump.Quote.Signature,
	}, dump.Log.PCRs, dump.Quote.Nonce); err != nil {
		t.Fatalf("verifying quote: %v", err)
	}

	el, err := ParseEventLog(dump.Log.Raw)
	if err != nil {
		t.Fatalf("parsing event log: %v", err)
	}
	events, err := el.Verify(dump.Log.PCRs)
	if err != nil {
		t.Fatalf("validating event log: %v", err)
	}

	for i, e := range events {
		if e.sequence != i {
			t.Errorf("event out of order: events[%d].sequence = %d, want %d", i, e.sequence, i)
		}
	}
}

func TestParseEventLogEventSizeTooLarge(t *testing.T) {
	data := []byte{
		// PCR index
		0x30, 0x34, 0x39, 0x33,
		// type
		0x36, 0x30, 0x30, 0x32,

		// Digest
		0x31, 0x39, 0x36, 0x33, 0x39, 0x34, 0x34, 0x37, 0x39, 0x32,
		0x31, 0x32, 0x32, 0x37, 0x39, 0x30, 0x34, 0x30, 0x31, 0x6d,

		// Even size (3.183 GB)
		0xbd, 0xbf, 0xef, 0x47,

		// "event data"
		0x00, 0x00, 0x00, 0x00,
	}

	// If this doesn't panic, the test passed
	// TODO(ericchiang): use errors.As once go-attestation switches to Go 1.13.
	_, err := ParseEventLog(data)
	if err == nil {
		t.Fatalf("expected parsing invalid event log to fail")
	}
}

func TestParseSpecIDEvent(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    []uint16
		wantErr bool
	}{
		{
			name: "sha1",
			data: append(
				[]byte("Spec ID Event03"), 0x0,
				0x0, 0x0, 0x0, 0x0, // platform class
				0x0,                // version minor
				0x2,                // version major
				0x0,                // errata
				0x8,                // uintn size
				0x1, 0x0, 0x0, 0x0, // num algs
				0x04, 0x0, // SHA1
				0x14, 0x0, // size
				0x2, // vendor info size
				0x0, 0x0,
			),
			want: []uint16{0x0004},
		},
		{
			name: "sha1_and_sha256",
			data: append(
				[]byte("Spec ID Event03"), 0x0,
				0x0, 0x0, 0x0, 0x0, // platform class
				0x0,                // version minor
				0x2,                // version major
				0x0,                // errata
				0x8,                // uintn size
				0x2, 0x0, 0x0, 0x0, // num algs
				0x04, 0x0, // SHA1
				0x14, 0x0, // size
				0x0B, 0x0, // SHA256
				0x20, 0x0, // size
				0x2, // vendor info size
				0x0, 0x0,
			),
			want: []uint16{0x0004, 0x000B},
		},
		{
			name: "invalid_version",
			data: append(
				[]byte("Spec ID Event03"), 0x0,
				0x0, 0x0, 0x0, 0x0, // platform class
				0x2,                // version minor
				0x1,                // version major
				0x0,                // errata
				0x8,                // uintn size
				0x2, 0x0, 0x0, 0x0, // num algs
				0x04, 0x0, // SHA1
				0x14, 0x0, // size
				0x0B, 0x0, // SHA256
				0x20, 0x0, // size
				0x2, // vendor info size
				0x0, 0x0,
			),
			wantErr: true,
		},
		{
			name: "malicious_number_of_algs",
			data: append(
				[]byte("Spec ID Event03"), 0x0,
				0x0, 0x0, 0x0, 0x0, // platform class
				0x0,                    // version minor
				0x2,                    // version major
				0x0,                    // errata
				0x8,                    // uintn size
				0xff, 0xff, 0xff, 0xff, // num algs
				0x04, 0x0, // SHA1
				0x14, 0x0, // size
				0x2, // vendor info size
				0x0, 0x0,
			),
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec, err := parseSpecIDEvent(test.data)
			if (err != nil) != test.wantErr {
				t.Fatalf("parsing spec, wantErr=%t, got=%v", test.wantErr, err)
			}
			if err != nil {
				return
			}
			algsEq := func(got, want []uint16) bool {
				if len(got) != len(want) {
					return false
				}
				for i, alg := range got {
					if want[i] != alg {
						return false
					}
				}
				return true
			}

			if !algsEq(test.want, spec.algs) {
				t.Errorf("algorithms, got=%x, want=%x", spec.algs, test.want)
			}
		})
	}
}
