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
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

func TestSecureBoot(t *testing.T) {
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
	raw, err := os.ReadFile("testdata/sb_cert_eventlog")
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
	raw, err := os.ReadFile("testdata/option_rom_eventlog")
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
	data, err := os.ReadFile("testdata/ubuntu_2104_shielded_vm_no_secure_boot_eventlog")
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
	data, err := os.ReadFile("testdata/coreos_36_shielded_vm_no_secure_boot_eventlog")
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

const (
	// TCG PC Client Specific Implementation Specification for Conventional BIOS
	// 1.21, Section 10.4.1 (EV_SEPARATOR).
	testEVSeparator EventType = 0x00000004
	// TCG EFI Platform Specification 1.22, Section 7.2
	// (EV_EFI_VARIABLE_DRIVER_CONFIG and EV_EFI_VARIABLE_AUTHORITY).
	testEVEFIVariableDriverConfig EventType = 0x80000001
	testEVEFIVariableAuthority    EventType = 0x800000e0
)

var (
	// EFI_GLOBAL_VARIABLE (8be4df61-93ca-11d2-aa0d-00e098032b8c) in mixed-endian
	// EFI_GUID wire format (UEFI Specification 2.8, Section 3.3). Used for
	// SecureBoot, PK, and KEK variables.
	testEFIGlobalVariableGUID = [16]byte{
		0x61, 0xdf, 0xe4, 0x8b, 0xca, 0x93, 0xd2, 0x11,
		0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c,
	}

	// EFI_IMAGE_SECURITY_DATABASE_GUID (d719b2cb-3d3a-4596-a3bc-dad00e67656f) in
	// mixed-endian EFI_GUID wire format (UEFI Specification 2.8, Section 32.5.3.3).
	// Used for db and dbx signature database variables.
	testEFIImageSecurityDatabaseGUID = [16]byte{
		0xcb, 0xb2, 0x19, 0xd7, 0x3a, 0x3d, 0x96, 0x45,
		0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f,
	}

	// EFI_CERT_X509_GUID (a5c059a1-94e4-4aa7-87b5-ab155c2bf072) in mixed-endian
	// EFI_GUID wire format (UEFI Specification 2.8, Section 32.4.1.4). Identifies
	// DER-encoded X.509 certificates in an EFI_SIGNATURE_LIST.
	testEFICertX509GUID = [16]byte{
		0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a,
		0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72,
	}

	// SHIM_LOCK_GUID (605dab50-e046-4300-abb6-3dd810dd8b23) in mixed-endian
	// EFI_GUID wire format (rhboot/shim lib/guid.c). Used by Linux shim for
	// Shim, SbatLevel, and MokListTrusted EV_EFI_VARIABLE_AUTHORITY events.
	testShimLockGUID = [16]byte{
		0x50, 0xab, 0x5d, 0x60, 0x46, 0xe0, 0x00, 0x43,
		0xab, 0xb6, 0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23,
	}

	// Representative SbatLevel payload measured by rhboot/shim into PCR 7 as an
	// EV_EFI_VARIABLE_AUTHORITY event (https://github.com/rhboot/shim/blob/main/SBAT.md).
	testShimSBATPayload = []byte("sbat,1,2021030218\n")

	// Representative MokListTrusted payload (1-byte boolean flag = 1) measured by
	// rhboot/shim into PCR 7 as an EV_EFI_VARIABLE_AUTHORITY event
	// (https://github.com/rhboot/shim/blob/main/MokVars.txt).
	testShimMokListTrustedPayload = []byte{1}
)

func newTestSecureBootCert(t *testing.T, commonName string) *x509.Certificate {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() failed: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(1<<32, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("x509.CreateCertificate(%q) failed: %v", commonName, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("x509.ParseCertificate(%q) failed: %v", commonName, err)
	}
	return cert
}

// encodeUEFIVariableData serializes a UEFI_VARIABLE_DATA structure per TCG PC
// Client Platform Firmware Profile Specification, Section 10.2.6.
func encodeUEFIVariableData(guid [16]byte, name string, varData []byte) []byte {
	utf16Name := utf16.Encode([]rune(name))
	var buf bytes.Buffer
	buf.Write(guid[:])
	binary.Write(&buf, binary.LittleEndian, uint64(len(utf16Name)))
	binary.Write(&buf, binary.LittleEndian, uint64(len(varData)))
	for _, c := range utf16Name {
		binary.Write(&buf, binary.LittleEndian, c)
	}
	buf.Write(varData)
	return buf.Bytes()
}

// encodeEFISignatureData serializes an EFI_SIGNATURE_DATA structure (16-byte
// SignatureOwner GUID followed by SignatureData) per UEFI Specification 2.8,
// Section 32.4.1.
func encodeEFISignatureData(owner [16]byte, sigData []byte) []byte {
	out := make([]byte, 0, len(owner)+len(sigData))
	out = append(out, owner[:]...)
	out = append(out, sigData...)
	return out
}

// encodeX509EFISignatureList serializes a single-certificate EFI_SIGNATURE_LIST
// of type EFI_CERT_X509_GUID per UEFI Specification 2.8, Section 32.4.1.
func encodeX509EFISignatureList(owner [16]byte, certDER []byte) []byte {
	entry := encodeEFISignatureData(owner, certDER)
	const headerSize = 16 + 4 + 4 + 4
	var buf bytes.Buffer
	buf.Write(testEFICertX509GUID[:])
	binary.Write(&buf, binary.LittleEndian, uint32(headerSize+len(entry))) // SignatureListSize
	binary.Write(&buf, binary.LittleEndian, uint32(0))                     // SignatureHeaderSize
	binary.Write(&buf, binary.LittleEndian, uint32(len(entry)))            // SignatureSize
	buf.Write(entry)
	return buf.Bytes()
}

func newPCR7Event(typ EventType, data []byte) Event {
	sum := sha256.Sum256(data)
	return Event{
		Index:  7,
		Type:   typ,
		Data:   data,
		Digest: sum[:],
	}
}

func newTamperedPCR7Event(typ EventType, data []byte) Event {
	ev := newPCR7Event(typ, data)
	ev.Digest[0] ^= 0xff
	return ev
}

func secureBootEnabledConfigEvents(pkCert, kekCert, dbCert *x509.Certificate) []Event {
	return []Event{
		newPCR7Event(testEVEFIVariableDriverConfig, encodeUEFIVariableData(testEFIGlobalVariableGUID, "SecureBoot", []byte{1})),
		newPCR7Event(testEVEFIVariableDriverConfig, encodeUEFIVariableData(testEFIGlobalVariableGUID, "PK", encodeX509EFISignatureList(testEFIGlobalVariableGUID, pkCert.Raw))),
		newPCR7Event(testEVEFIVariableDriverConfig, encodeUEFIVariableData(testEFIGlobalVariableGUID, "KEK", encodeX509EFISignatureList(testEFIGlobalVariableGUID, kekCert.Raw))),
		newPCR7Event(testEVEFIVariableDriverConfig, encodeUEFIVariableData(testEFIImageSecurityDatabaseGUID, "db", encodeX509EFISignatureList(testEFIImageSecurityDatabaseGUID, dbCert.Raw))),
	}
}

func buildPCR7Events(groups ...[]Event) []Event {
	all := slices.Concat(groups...)
	for i := range all {
		all[i].sequence = i
	}
	return all
}

func certsEqual(a, b []x509.Certificate) bool {
	return slices.EqualFunc(a, b, func(x, y x509.Certificate) bool {
		return x.Equal(&y)
	})
}

func TestParseSecurebootStateAuthorityErrors(t *testing.T) {
	pkCert := newTestSecureBootCert(t, "Test PK")
	kekCert := newTestSecureBootCert(t, "Test KEK")
	dbCert := newTestSecureBootCert(t, "Test DB")

	cfgEvents := secureBootEnabledConfigEvents(pkCert, kekCert, dbCert)
	sepEvent := []Event{newPCR7Event(testEVSeparator, []byte{0, 0, 0, 0})}
	sbatEvent := newPCR7Event(testEVEFIVariableAuthority, encodeUEFIVariableData(testShimLockGUID, "SbatLevel", testShimSBATPayload))
	mokTrustedEvent := newPCR7Event(testEVEFIVariableAuthority, encodeUEFIVariableData(testShimLockGUID, "MokListTrusted", testShimMokListTrustedPayload))
	x509AuthEvent := newPCR7Event(testEVEFIVariableAuthority, encodeUEFIVariableData(testEFIImageSecurityDatabaseGUID, "db", encodeEFISignatureData(testEFIImageSecurityDatabaseGUID, dbCert.Raw)))
	tamperedSBATEvent := newTamperedPCR7Event(testEVEFIVariableAuthority, encodeUEFIVariableData(testShimLockGUID, "SbatLevel", testShimSBATPayload))
	tamperedMokTrustedEvent := newTamperedPCR7Event(testEVEFIVariableAuthority, encodeUEFIVariableData(testShimLockGUID, "MokListTrusted", testShimMokListTrustedPayload))

	tests := []struct {
		name    string
		events  []Event
		wantErr string
	}{
		{
			name:    "no_authority_events",
			events:  buildPCR7Events(cfgEvents, sepEvent),
			wantErr: "secure boot was enabled but no key was used",
		},
		{
			name:    "only_sbat_level_post_separator",
			events:  buildPCR7Events(cfgEvents, sepEvent, []Event{sbatEvent}),
			wantErr: "secure boot was enabled but no key was used",
		},
		{
			name:    "only_mok_list_trusted_post_separator",
			events:  buildPCR7Events(cfgEvents, sepEvent, []Event{mokTrustedEvent}),
			wantErr: "secure boot was enabled but no key was used",
		},
		{
			name:    "only_sbat_level_and_mok_list_trusted_pre_and_post_separator",
			events:  buildPCR7Events(cfgEvents, []Event{sbatEvent}, sepEvent, []Event{sbatEvent, mokTrustedEvent}),
			wantErr: "secure boot was enabled but no key was used",
		},
		{
			name:    "tampered_sbat_level_digest_without_x509_authority",
			events:  buildPCR7Events(cfgEvents, sepEvent, []Event{tamperedSBATEvent}),
			wantErr: "invalid digest for authority",
		},
		{
			name:    "tampered_sbat_level_digest_with_valid_x509_authority",
			events:  buildPCR7Events(cfgEvents, sepEvent, []Event{x509AuthEvent, tamperedSBATEvent}),
			wantErr: "invalid digest for authority",
		},
		{
			name:    "tampered_mok_list_trusted_digest_with_valid_x509_authority",
			events:  buildPCR7Events(cfgEvents, sepEvent, []Event{x509AuthEvent, tamperedMokTrustedEvent}),
			wantErr: "invalid digest for authority",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseSecurebootState(tc.events)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("ParseSecurebootState() = (%v, %v), want error containing %q", got, err, tc.wantErr)
			}
		})
	}
}

func TestParseSecurebootStateAuthority(t *testing.T) {
	pkCert := newTestSecureBootCert(t, "Test PK")
	kekCert := newTestSecureBootCert(t, "Test KEK")
	dbCert := newTestSecureBootCert(t, "Test DB")
	shimCert := newTestSecureBootCert(t, "Test Shim Vendor Authority")

	cfgEvents := secureBootEnabledConfigEvents(pkCert, kekCert, dbCert)
	disabledCfgEvents := []Event{
		newPCR7Event(testEVEFIVariableDriverConfig, encodeUEFIVariableData(testEFIGlobalVariableGUID, "SecureBoot", []byte{0})),
	}
	sepEvent := []Event{newPCR7Event(testEVSeparator, []byte{0, 0, 0, 0})}
	sbatEvent := newPCR7Event(testEVEFIVariableAuthority, encodeUEFIVariableData(testShimLockGUID, "SbatLevel", testShimSBATPayload))
	mokTrustedEvent := newPCR7Event(testEVEFIVariableAuthority, encodeUEFIVariableData(testShimLockGUID, "MokListTrusted", testShimMokListTrustedPayload))
	dbAuthEvent := newPCR7Event(testEVEFIVariableAuthority, encodeUEFIVariableData(testEFIImageSecurityDatabaseGUID, "db", encodeEFISignatureData(testEFIImageSecurityDatabaseGUID, dbCert.Raw)))
	shimAuthEvent := newPCR7Event(testEVEFIVariableAuthority, encodeUEFIVariableData(testShimLockGUID, "Shim", encodeEFISignatureData(testShimLockGUID, shimCert.Raw)))

	tests := []struct {
		name              string
		events            []Event
		wantEnabled       bool
		wantPreAuthority  []x509.Certificate
		wantPostAuthority []x509.Certificate
	}{
		{
			name:              "post_separator_x509_with_sbat_level_and_mok_list_trusted",
			events:            buildPCR7Events(cfgEvents, sepEvent, []Event{sbatEvent, dbAuthEvent, mokTrustedEvent, shimAuthEvent}),
			wantEnabled:       true,
			wantPostAuthority: []x509.Certificate{*dbCert, *shimCert},
		},
		{
			name:             "pre_separator_x509_with_post_separator_sbat_level_and_mok_list_trusted",
			events:           buildPCR7Events(cfgEvents, []Event{dbAuthEvent}, sepEvent, []Event{sbatEvent, mokTrustedEvent}),
			wantEnabled:      true,
			wantPreAuthority: []x509.Certificate{*dbCert},
		},
		{
			name:              "pre_and_post_separator_x509_with_shim_metadata",
			events:            buildPCR7Events(cfgEvents, []Event{sbatEvent, dbAuthEvent}, sepEvent, []Event{mokTrustedEvent, shimAuthEvent}),
			wantEnabled:       true,
			wantPreAuthority:  []x509.Certificate{*dbCert},
			wantPostAuthority: []x509.Certificate{*shimCert},
		},
		{
			name:        "secure_boot_disabled_with_only_sbat_level_and_mok_list_trusted",
			events:      buildPCR7Events(disabledCfgEvents, sepEvent, []Event{sbatEvent, mokTrustedEvent}),
			wantEnabled: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseSecurebootState(tc.events)
			if err != nil {
				t.Fatalf("ParseSecurebootState() unexpected error: %v", err)
			}
			if got.Enabled != tc.wantEnabled {
				t.Errorf("ParseSecurebootState().Enabled = %v, want %v", got.Enabled, tc.wantEnabled)
			}
			if !certsEqual(got.PreSeparatorAuthority, tc.wantPreAuthority) {
				t.Errorf("ParseSecurebootState().PreSeparatorAuthority = %v, want %v", got.PreSeparatorAuthority, tc.wantPreAuthority)
			}
			if !certsEqual(got.PostSeparatorAuthority, tc.wantPostAuthority) {
				t.Errorf("ParseSecurebootState().PostSeparatorAuthority = %v, want %v", got.PostSeparatorAuthority, tc.wantPostAuthority)
			}
		})
	}
}
