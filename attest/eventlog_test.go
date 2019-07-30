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

	AIK AttestationParameters

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
	if _, err := parseEventLog(dump.Log.Raw); err != nil {
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

	aik, err := ParseAIKPublic(dump.Static.TPMVersion, dump.AIK.Public)
	if err != nil {
		t.Fatalf("parsing AIK: %v", err)
	}

	el := EventLog{
		AIKPublic: aik.Public,
		AIKHash:   aik.Hash,
		Quote: &Quote{
			Version:   dump.Static.TPMVersion,
			Quote:     dump.Quote.Quote,
			Signature: dump.Quote.Signature,
		},
		Nonce:          dump.Quote.Nonce,
		PCRs:           dump.Log.PCRs,
		MeasurementLog: dump.Log.Raw,
	}
	if _, err := el.Validate(); err != nil {
		t.Fatalf("validating event log: %v", err)
	}
}
