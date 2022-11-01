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
	"encoding/base64"
	"encoding/json"
	"os"
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
	data, err := os.ReadFile(testdata)
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
	data, err := os.ReadFile("testdata/crypto_agile_eventlog")
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
	data, err := os.ReadFile(testdata)
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

		// Event size (3.183 GB)
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

func TestParseEventLogEventSizeZero(t *testing.T) {
	data := []byte{
		// PCR index
		0x4, 0x0, 0x0, 0x0,

		// type
		0xd, 0x0, 0x0, 0x0,

		// Digest
		0x94, 0x2d, 0xb7, 0x4a, 0xa7, 0x37, 0x5b, 0x23, 0xea, 0x23,
		0x58, 0xeb, 0x3b, 0x31, 0x59, 0x88, 0x60, 0xf6, 0x90, 0x59,

		// Event size (0 B)
		0x0, 0x0, 0x0, 0x0,

		// no "event data"
	}

	if _, err := parseRawEvent(bytes.NewBuffer(data), nil); err != nil {
		t.Fatalf("parsing event log: %v", err)
	}
}

func TestParseShortNoAction(t *testing.T) {
	// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf#page=110
	// says: "For EV_NO_ACTION events other than the EFI Specification ID event
	// (Section 9.4.5.1) the log will ...". Thus it is concluded other
	// than "EFI Specification ID" events are also valid as NO_ACTION events.
	//
	// Currently we just assume that such events will have Data shorter than
	// "EFI Specification ID" field.

	data, err := os.ReadFile("testdata/short_no_action_eventlog")
	if err != nil {
		t.Fatalf("reading test data: %v", err)
	}
	if _, err := ParseEventLog(data); err != nil {
		t.Fatalf("parsing event log: %v", err)
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
			var algs []uint16
			if (err != nil) != test.wantErr {
				t.Fatalf("parsing spec, wantErr=%t, got=%v", test.wantErr, err)
			}
			if err != nil {
				return
			}
			algsEq := func(want, got []uint16) bool {
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

			for _, alg := range spec.algs {
				algs = append(algs, alg.ID)
			}

			if !algsEq(test.want, algs) {
				t.Errorf("algorithms, got=%x, want=%x", spec.algs, test.want)
			}
		})
	}
}

func TestEBSVerifyWorkaround(t *testing.T) {
	pcr5 := []PCR{
		{
			Index: 5,
			Digest: []byte{
				0x31, 0x24, 0x58, 0x08, 0xd6, 0xd3, 0x58, 0x49, 0xbc, 0x39,
				0x4f, 0x63, 0x43, 0xf2, 0xb3, 0xff, 0x90, 0x8e, 0xd5, 0xe3,
			},
			DigestAlg: HashSHA1.cryptoHash(),
		},
		{
			Index: 5,
			Digest: []byte{
				0x6c, 0xae, 0xa1, 0x23, 0xfa, 0x61, 0x11, 0x30, 0x5e, 0xe6, 0x24,
				0xe4, 0x52, 0xe2, 0x69, 0xad, 0x14, 0xac, 0x52, 0x2a, 0xb8, 0xbf,
				0x0c, 0x88, 0xe1, 0x16, 0x16, 0xde, 0x4c, 0x22, 0x2f, 0x7d,
			},
			DigestAlg: HashSHA256.cryptoHash(),
		},
	}

	elr, err := os.ReadFile("testdata/ebs_event_missing_eventlog")
	if err != nil {
		t.Fatal(err)
	}
	el, err := ParseEventLog(elr)
	if err != nil {
		t.Fatalf("ParseEventLog() failed: %v", err)
	}
	if _, err := el.Verify(pcr5); err != nil {
		t.Errorf("Verify() failed: %v", err)
	}
}

func TestAppendEvents(t *testing.T) {
	base, err := os.ReadFile("testdata/ubuntu_2104_shielded_vm_no_secure_boot_eventlog")
	if err != nil {
		t.Fatalf("reading test data: %v", err)
	}

	extraLog, err := base64.StdEncoding.DecodeString(`AAAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACUAAABTcGVjIElEIEV2ZW50MDMAAAAAAAACAAEC
AAAABAAUAAsAIAAACAAAAAYAAAACAAAABACX3UqVWDMNeg2Hkxyy6Q35wO4yBwsAVXbW4fKD8+xm
Kv75L4ecBpvSR4d6bz+A7z1prUcKPuMrAQAACAISpgJpbWFfaGFzaD1zaGEyNTYgYXBwYXJtb3I9
MSBwY2k9bm9hZXIsbm9hdHMgcHJpbnRrLmRldmttc2c9b24gc2xhYl9ub21lcmdlIGNvbnNvbGU9
dHR5UzAsMTE1MjAwbjggY29uc29sZT10dHkwIGdsaW51eC1ib290LWltYWdlPTIwMjExMDI3LjAy
LjAzIHF1aWV0IHNwbGFzaCBwbHltb3V0aC5pZ25vcmUtc2VyaWFsLWNvbnNvbGVzIGxzbT1sb2Nr
ZG93bix5YW1hLGxvYWRwaW4sc2FmZXNldGlkLGludGVncml0eSxhcHBhcm1vcixzZWxpbnV4LHNt
YWNrLHRvbW95byxicGYgcGFuaWM9MzAgaTkxNS5lbmFibGVfcHNyPTA=`)
	if err != nil {
		t.Fatal(err)
	}

	combined, err := AppendEvents(base, extraLog)
	if err != nil {
		t.Fatalf("CombineEventLogs() failed: %v", err)
	}

	// Make sure the combined log parses successfully and has one more
	// event than the base log.
	parsedBase, err := ParseEventLog(base)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseEventLog(combined)
	if err != nil {
		t.Fatalf("ParseEventLog(combined_log) failed: %v", err)
	}

	if got, want := len(parsed.rawEvents), len(parsedBase.rawEvents)+1; got != want {
		t.Errorf("unexpected number of events in combined log: got %d, want %d", got, want)
		for i, e := range parsed.rawEvents {
			t.Logf("logs[%d] = %+v", i, e)
		}
	}
}
