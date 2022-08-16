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
	"encoding/base64"
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

// See: https://github.com/google/go-attestation/issues/157
func TestSecureBootBug157(t *testing.T) {
	raw, err := ioutil.ReadFile("testdata/sb_cert_eventlog")
	if err != nil {
		t.Fatalf("reading test data: %v", err)
	}
	elr, err := ParseEventLog(raw)
	if err != nil {
		t.Fatalf("parsing event log: %v", err)
	}

	pcrs := []PCR{
		{'\x00', []byte("Q\xc3#\xde\f\fiOF\x01\xcd\xd0+\xebX\xff\x13b\x9ft"), '\x03', false},
		{'\x01', []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), '\x03', false},
		{'\x02', []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), '\x03', false},
		{'\x03', []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), '\x03', false},
		{'\x04', []byte("\xb7q\x00\x8d\x17<\x02+\xc1oKM\x1a\u007f\x8b\x99\xed\x88\xee\xb1"), '\x03', false},
		{'\x05', []byte("\xd79j\xc6\xe8\x87\xda\"ޠ;@\x95/p\xb8\xdbҩ\x96"), '\x03', false},
		{'\x06', []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), '\x03', false},
		{'\a', []byte("E\xa8b\x1d4\xa5}\xf2\xb2\xe7\xf1L\x92\xb9\x9a\xc8\xde}X\x05"), '\x03', false},
		{'\b', []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), '\x03', false},
		{'\t', []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), '\x03', false},
		{'\n', []byte("\x82\x84\x10>\x06\xd4\x01\"\xbcd\xa0䡉\x1a\xf9\xec\xd4\\\xf6"), '\x03', false},
		{'\v', []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), '\x03', false},
		{'\f', []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), '\x03', false},
		{'\r', []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), '\x03', false},
		{'\x0e', []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), '\x03', false},
		{'\x0f', []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), '\x03', false},
		{'\x10', []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), '\x03', false},
		{'\x11', []byte("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"), '\x03', false},
		{'\x12', []byte("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"), '\x03', false},
		{'\x13', []byte("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"), '\x03', false},
		{'\x14', []byte("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"), '\x03', false},
		{'\x15', []byte("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"), '\x03', false},
		{'\x16', []byte("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"), '\x03', false},
		{'\x17', []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), '\x03', false},
		{'\x00', []byte("\xfc\xec\xb5j\xcc08b\xb3\x0e\xb3Bę\v\xebP\xb5ૉr$I\xc2٧?7\xb0\x19\xfe"), '\x05', false},
		{'\x01', []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), '\x05', false},
		{'\x02', []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), '\x05', false},
		{'\x03', []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), '\x05', false},
		{'\x04', []byte("\xa9)h\x80oy_\xa3D5\xd9\xf1\x18\x13hL\xa1\xe7\x05`w\xf7\x00\xbaI\xf2o\x99b\xf8m\x89"), '\x05', false},
		{'\x05', []byte("̆\x18\xb7y2\xb4\xef\xda\x12\xccX\xba\xd9>\xcdѕ\x9d\xea)\xe5\xabyE%\xa6\x19\xf5\xba\xab\xee"), '\x05', false},
		{'\x06', []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), '\x05', false},
		{'\a', []byte("Q\xb3\x04\x88\xc9\xe6%]\x82+\xdc\x1b ٩,2\xbd\xe6\xc3\xe7\xbc\x02\xbc\xdd2\x82^\xb5\xef\x06\x9a"), '\x05', false},
		{'\b', []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), '\x05', false},
		{'\t', []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), '\x05', false},
		{'\n', []byte("\xc3l\x9a\xb1\x10\x9b\xa0\x8a?dX!\x18\xf8G\x1a]i[\xc9#\xa0\xa2\xbd\x04]\xb1K\x97OB9"), '\x05', false},
		{'\v', []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), '\x05', false},
		{'\f', []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), '\x05', false},
		{'\r', []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), '\x05', false},
		{'\x0e', []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), '\x05', false},
		{'\x0f', []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), '\x05', false},
		{'\x10', []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), '\x05', false},
		{'\x11', []byte("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"), '\x05', false},
		{'\x12', []byte("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"), '\x05', false},
		{'\x13', []byte("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"), '\x05', false},
		{'\x14', []byte("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"), '\x05', false},
		{'\x15', []byte("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"), '\x05', false},
		{'\x16', []byte("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"), '\x05', false},
		{'\x17', []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), '\x05', false},
	}

	events, err := elr.Verify(pcrs)
	if err != nil {
		t.Fatalf("failed to verify log: %v", err)
	}

	sbs, err := ParseSecurebootState(events)
	if err != nil {
		t.Fatalf("failed parsing secureboot state: %v", err)
	}
	if got, want := len(sbs.PostSeparatorAuthority), 3; got != want {
		t.Errorf("len(sbs.PostSeparatorAuthority) = %d, want %d", got, want)
	}
}

func b64MustDecode(input string) []byte {
	b, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		panic(err)
	}
	return b
}

func TestSecureBootOptionRom(t *testing.T) {
	raw, err := ioutil.ReadFile("testdata/option_rom_eventlog")
	if err != nil {
		t.Fatalf("reading test data: %v", err)
	}
	elr, err := ParseEventLog(raw)
	if err != nil {
		t.Fatalf("parsing event log: %v", err)
	}

	pcrs := []PCR{
		{'\x00', b64MustDecode("AVGK7ch6DvUF0nJh74NYCefaAIY="), '\x03', false},
		{'\x01', b64MustDecode("vr/0wIpmd0c6tgTO3vuC+FDN6IM="), '\x03', false},
		{'\x02', b64MustDecode("NmoxoMB1No8OEIVzM+ou1uigD9M="), '\x03', false},
		{'\x03', b64MustDecode("sqg7Dr8vg3Qpmlsr38MeqVWtcjY="), '\x03', false},
		{'\x04', b64MustDecode("OfOIw5WekEaUcm9MAVttzq4GgKE="), '\x03', false},
		{'\x05', b64MustDecode("cjoFIM9/KXhUh0K9FUFwayRGRZ4="), '\x03', false},
		{'\x06', b64MustDecode("sqg7Dr8vg3Qpmlsr38MeqVWtcjY="), '\x03', false},
		{'\x07', b64MustDecode("IN59+6a838ytrX4+sJnJHU2Xxa0="), '\x03', false},
	}

	events, err := elr.Verify(pcrs)
	if err != nil {
		t.Errorf("failed to verify log: %v", err)
	}

	sbs, err := ParseSecurebootState(events)
	if err != nil {
		t.Errorf("failed parsing secureboot state: %v", err)
	}
	if got, want := len(sbs.PostSeparatorAuthority), 2; got != want {
		t.Errorf("len(sbs.PostSeparatorAuthority) = %d, want %d", got, want)
	}

	if got, want := len(sbs.DriverLoadSourceHints), 1; got != want {
		t.Fatalf("len(sbs.DriverLoadSourceHints) = %d, want %d", got, want)
	}
	if got, want := sbs.DriverLoadSourceHints[0], PciMmioSource; got != want {
		t.Errorf("sbs.DriverLoadSourceHints[0] = %v, want %v", got, want)
	}
}

func TestSecureBootEventLogUbuntu(t *testing.T) {
	data, err := ioutil.ReadFile("testdata/ubuntu_2104_shielded_vm_no_secure_boot_eventlog")
	if err != nil {
		t.Fatalf("reading test data: %v", err)
	}
	el, err := ParseEventLog(data)
	if err != nil {
		t.Fatalf("parsing event log: %v", err)
	}
	evts := el.Events(HashSHA256)
	if err != nil {
		t.Fatalf("verifying event log: %v", err)
	}
	_, err = ParseSecurebootState(evts)
	if err != nil {
		t.Errorf("parsing sb state: %v", err)
	}
}

func TestSecureBootEventLogFedora36(t *testing.T) {
	data, err := ioutil.ReadFile("testdata/coreos_36_shielded_vm_no_secure_boot_eventlog")
	if err != nil {
		t.Fatalf("reading test data: %v", err)
	}
	el, err := ParseEventLog(data)
	if err != nil {
		t.Fatalf("parsing event log: %v", err)
	}
	evts := el.Events(HashSHA256)
	if err != nil {
		t.Fatalf("verifying event log: %v", err)
	}
	_, err = ParseSecurebootState(evts)
	if err != nil {
		t.Errorf("parsing sb state: %v", err)
	}
}
