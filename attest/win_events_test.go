// Copyright 2020 Google Inc.
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
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestParseWinEvents(t *testing.T) {
	want := &WinEvents{
		ColdBoot:             true,
		BootCount:            4,
		DEPEnabled:           TernaryTrue,
		CodeIntegrityEnabled: TernaryTrue,
		BitlockerUnlocks:     []BitlockerStatus{0, 0},
		LoadedModules: map[string]WinModuleLoad{
			"0fdce7d71936f79445e7d2c84cbeb97c948d3730e0b839166b0a4e625c2d4547": {
				FilePath:           `\Windows\System32\drivers\vioscsi.sys`,
				ImageBase:          []uint64{81416192},
				ImageSize:          uint64(86016),
				HashAlgorithm:      WinAlgSHA256,
				ImageValidated:     true,
				AuthorityIssuer:    "Microsoft Windows Third Party Component CA 2014",
				AuthorityPublisher: "Microsoft Windows Hardware Compatibility Publisher",
				AuthoritySerial: []uint8{
					0x33, 0x00, 0x00, //  |3..|
					0x00, 0x25, 0x3a, 0x27, 0x38, 0x69, 0x0a, 0x34, 0x51, 0xc1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x25, // -|.%:'8i.4Q......%|
				},
				AuthoritySHA1: []uint8{
					0x26, 0x29, 0xe8, 0x6a, 0xae, 0x6e, 0xb9, 0xc9, 0xad, 0xcc, 0x1c, 0x54, 0x8d, 0x60, 0x1a, 0x50,
					0xfd, 0x96, 0x92, 0x7a,
				},
				AuthenticodeHash: []byte{15, 220, 231, 215, 25, 54, 247, 148, 69, 231, 210, 200, 76, 190, 185, 124, 148, 141, 55, 48, 224, 184, 57, 22, 107, 10, 78, 98, 92, 45, 69, 71},
			},
			"055a36a9921b98cc04042ca95249c7eca655536868dafcec7508947ebe5e71f4": {
				FilePath:           `\Windows\System32\Drivers\ksecpkg.sys`,
				ImageBase:          []uint64{82952192},
				ImageSize:          uint64(204800),
				HashAlgorithm:      WinAlgSHA256,
				ImageValidated:     true,
				AuthorityIssuer:    "Microsoft Windows Production PCA 2011",
				AuthorityPublisher: "Microsoft Windows",
				AuthoritySerial: []uint8{
					0x33, 0x00, 0x00, 0x01, 0xc4, 0x22, 0xb2, 0xf7, 0x9b, 0x79, 0x3d, 0xac, 0xb2, 0x00, 0x00, 0x00,
					0x00, 0x01, 0xc4,
				},
				AuthoritySHA1: []uint8{
					0xae, 0x9c, 0x1a, 0xe5, 0x47, 0x63, 0x82, 0x2e, 0xec, 0x42, 0x47, 0x49, 0x83, 0xd8, 0xb6, 0x35,
					0x11, 0x6c, 0x84, 0x52,
				},
				AuthenticodeHash: []byte{5, 90, 54, 169, 146, 27, 152, 204, 4, 4, 44, 169, 82, 73, 199, 236, 166, 85, 83, 104, 104, 218, 252, 236, 117, 8, 148, 126, 190, 94, 113, 244},
			},
			"2bedd1589410b6fa13c82f35db735025b6a160595922750248771f5abd0fee58": {
				FilePath:           `\Windows\System32\drivers\volmgrx.sys`,
				ImageBase:          []uint64{80875520},
				ImageSize:          uint64(405504),
				HashAlgorithm:      WinAlgSHA256,
				ImageValidated:     true,
				AuthorityIssuer:    "Microsoft Windows Production PCA 2011",
				AuthorityPublisher: "Microsoft Windows",
				AuthoritySerial: []uint8{
					0x33, 0x00, 0x00, 0x01, 0xc4, 0x22, 0xb2, 0xf7, 0x9b, 0x79, 0x3d, 0xac, 0xb2, 0x00, 0x00, 0x00,
					0x00, 0x01, 0xc4,
				},
				AuthoritySHA1: []uint8{
					0xae, 0x9c, 0x1a, 0xe5, 0x47, 0x63, 0x82, 0x2e, 0xec, 0x42, 0x47, 0x49, 0x83, 0xd8, 0xb6, 0x35,
					0x11, 0x6c, 0x84, 0x52,
				},
				AuthenticodeHash: []byte{43, 237, 209, 88, 148, 16, 182, 250, 19, 200, 47, 53, 219, 115, 80, 37, 182, 161, 96, 89, 89, 34, 117, 2, 72, 119, 31, 90, 189, 15, 238, 88},
			},
		},
		ELAM: map[string]WinELAM{
			"Windows Defender": {Measured: []byte{0x06, 0x7d, 0x5b, 0x9d, 0xc5, 0x62, 0x7f, 0x97, 0xdc, 0xf3, 0xfe, 0xff, 0x60, 0x2a, 0x34, 0x2e, 0xd6, 0x98, 0xd2, 0xcc}},
		},
	}

	data, err := os.ReadFile("testdata/windows_gcp_shielded_vm.json")
	if err != nil {
		t.Fatalf("reading test data: %v", err)
	}
	var dump Dump
	if err := json.Unmarshal(data, &dump); err != nil {
		t.Fatalf("parsing test data: %v", err)
	}

	el, err := ParseEventLog(dump.Log.Raw)
	if err != nil {
		t.Fatalf("parsing event log: %v", err)
	}
	events, err := el.Verify(dump.Log.PCRs)
	if err != nil {
		t.Fatalf("validating event log: %v", err)
	}

	winState, err := ParseWinEvents(events)
	if err != nil {
		t.Fatalf("ExtractSecurebootState() failed: %v", err)
	}

	// Theres way too many modules to cross-check by hand, so we filter it down
	// to a manageable number.
	keep := map[string]bool{
		"0fdce7d71936f79445e7d2c84cbeb97c948d3730e0b839166b0a4e625c2d4547": true,
		"055a36a9921b98cc04042ca95249c7eca655536868dafcec7508947ebe5e71f4": true,
		"2bedd1589410b6fa13c82f35db735025b6a160595922750248771f5abd0fee58": true,
	}
	for k := range winState.LoadedModules {
		if _, keep := keep[k]; !keep {
			delete(winState.LoadedModules, k)
		}
	}

	if diff := cmp.Diff(winState, want, cmpopts.IgnoreUnexported(WinEvents{})); diff != "" {
		t.Errorf("Unexpected WinEvents (+got, -want):\n%s", diff)
	}
}
