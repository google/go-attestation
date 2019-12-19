package attest

import (
	"encoding/json"
	"io/ioutil"
	"testing"
)

func TestSecureBoot(t *testing.T) {
	data, err := ioutil.ReadFile("testdata/windows_gcp_shielded_vm.json")
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

	sbState, err := ParseSecurebootState(events)
	if err != nil {
		t.Fatalf("ExtractSecurebootState() failed: %v", err)
	}

	if got, want := sbState.Enabled, true; got != want {
		t.Errorf("secureboot.Enabled = %v, want %v", got, want)
	}
}
