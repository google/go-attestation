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

package eventlog

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-attestation/attest/attest-tool/internal"
)

func parseEvents(t *testing.T, testdata string) []attest.Event {
	data, err := os.ReadFile(testdata)
	if err != nil {
		t.Fatalf("reading test data: %v", err)
	}
	var dump internal.Dump
	if err := json.Unmarshal(data, &dump); err != nil {
		t.Fatalf("parsing test data: %v", err)
	}

	ak, err := attest.ParseAKPublic(dump.Static.TPMVersion, dump.AK.Public)
	if err != nil {
		t.Fatalf("parsing AK: %v", err)
	}
	if err := ak.Verify(attest.Quote{
		Version:   dump.Static.TPMVersion,
		Quote:     dump.Quote.Quote,
		Signature: dump.Quote.Signature,
	}, dump.Log.PCRs, dump.Quote.Nonce); err != nil {
		t.Fatalf("verifying quote: %v", err)
	}

	el, err := attest.ParseEventLog(dump.Log.Raw)
	if err != nil {
		t.Fatalf("parsing event log: %v", err)
	}
	events, err := el.Verify(dump.Log.PCRs)
	if err != nil {
		t.Fatalf("validating event log: %v", err)
	}
	return events
}

func notEmpty(t *testing.T, name string, field []byte) {
	t.Helper()
	if len(field) == 0 {
		t.Errorf("field %s wasn't populated", name)
	}
}

func isEmpty(t *testing.T, name string, field []byte) {
	t.Helper()
	if len(field) != 0 {
		t.Errorf("expected field %s not to be populated", name)
	}
}

func TestParseSecureBootWindows(t *testing.T) {
	events := parseEvents(t, "../../../testdata/windows_gcp_shielded_vm.json")
	sb, err := ParseSecureBoot(events)
	if err != nil {
		t.Fatalf("parse secure boot: %v", err)
	}
	if !sb.Enabled {
		t.Errorf("expected secure boot to be enabled")
	}
	notEmpty(t, "db", sb.DB)
	notEmpty(t, "dbx", sb.DBX)
	notEmpty(t, "pk", sb.PK)
	notEmpty(t, "kek", sb.KEK)
	isEmpty(t, "dbt", sb.DBT)
	isEmpty(t, "dbr", sb.DBR)
	notEmpty(t, "Authority", sb.Authority)
}

func TestParseSecureBootLinux(t *testing.T) {
	events := parseEvents(t, "../../../testdata/linux_tpm12.json")
	sb, err := ParseSecureBoot(events)
	if err != nil {
		t.Errorf("parse secure boot: %v", err)
	}
	if sb.Enabled {
		t.Errorf("expected secure boot to be disabled")
	}
	notEmpty(t, "db", sb.DB)
	notEmpty(t, "dbx", sb.DBX)
	isEmpty(t, "dbt", sb.DBT)
	isEmpty(t, "dbr", sb.DBR)
	isEmpty(t, "Authority", sb.Authority)
}
