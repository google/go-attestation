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

package events

import (
	"crypto"
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/google/go-attestation/attest"
)

func TestParseEvents(t *testing.T) {
	var emptyPCRs [24]attest.PCR

	for i, _ := range emptyPCRs {
		emptyPCRs[i].Index = i
		emptyPCRs[i].Digest = make([]byte, 20)
		emptyPCRs[i].DigestAlg = crypto.SHA1
	}
	testParseEvent(t, emptyPCRs[:], "testdata/binary_bios_measurements_15")
	testParseEvent(t, emptyPCRs[:], "testdata/binary_bios_measurements_27")
	testParseEvent(t, emptyPCRs[:], "testdata/linux_event_log")
	testParseEvent(t, emptyPCRs[:], "testdata/tpm12_windows_lenovo_x1carbonv3")
}

func TestParseCryptoAgileEvents(t *testing.T) {
	var emptyPCRs [24]attest.PCR
	for i, _ := range emptyPCRs {
		emptyPCRs[i].Index = i
		emptyPCRs[i].Digest = make([]byte, 32)
		emptyPCRs[i].DigestAlg = crypto.SHA256
	}

	testParseEvent(t, emptyPCRs[:], "testdata/crypto_agile_eventlog")
	testParseEvent(t, emptyPCRs[:], "testdata/tpm2_windows_lenovo_yogax1v2")
	testParseEvent(t, emptyPCRs[:], "testdata/windows_event_log")
}

func testParseEvent(t *testing.T, PCRs []attest.PCR, filename string) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatalf("reading test data %s: %v", filename, err)
	}
	el, err := attest.ParseEventLog(data)
	if err != nil {
		t.Fatalf("parsing event log %s: %v", filename, err)
	}
	outputEvents, err := el.Verify(PCRs[:])
	if err != nil {
		if replayErr, isReplayErr := err.(attest.ReplayError); isReplayErr {
			outputEvents = replayErr.Events
		} else {
			t.Fatalf("failed to verify from event log %s: %v", filename, err)
		}
	}
	if len(outputEvents) == 0 {
		t.Fatalf("failed to extract any events from %s", filename)
	}

	parsedEvents, err := ParseEvents(outputEvents)

	if err != nil {
		t.Fatalf("parsing events %s: %v", filename, err)
	}

	if len(parsedEvents) == 0 {
		t.Fatalf("failed to parse any events from %s", filename)
	}

	reference := filename + ".json"
	referenceData, err := ioutil.ReadFile(reference)
	if err != nil {
		t.Fatalf("failed to read json reference %s: %v", reference, err)
	}

	parsedEventsJson, err := json.MarshalIndent(parsedEvents, "", "    ")
	if err != nil {
		t.Fatalf("failed to marshal json for %s: %v", reference, err)
	}

	if string(parsedEventsJson) != string(referenceData) {
		t.Fatalf("parsed events for %s don't match reference JSON", filename)
	}
}
