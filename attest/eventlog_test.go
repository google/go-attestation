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
