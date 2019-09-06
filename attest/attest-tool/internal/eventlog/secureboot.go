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
	"bytes"
	"crypto"
	"encoding/binary"
	"fmt"
	"io"
	"unicode/utf16"

	"github.com/google/go-attestation/attest"
)

var (
	// https://uefi.org/sites/default/files/resources/UEFI_Spec_2_8_final.pdf#page=153
	efiGlobalVariable = efiGUID{
		0x8BE4DF61, 0x93CA, 0x11d2, [8]uint8{0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C}}

	efiGlobalVariableSecureBoot     = "SecureBoot"
	efiGlobalVariablePlatformKey    = "PK"
	efiGlobalVariableKeyExchangeKey = "KEK"

	// https://uefi.org/sites/default/files/resources/UEFI_Spec_2_8_final.pdf#page=1804
	efiImageSecurityDatabaseGUID = efiGUID{
		0xd719b2cb, 0x3d3a, 0x4596, [8]uint8{0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f}}

	efiImageSecurityDatabase  = "db"
	efiImageSecurityDatabase1 = "dbx"
	efiImageSecurityDatabase2 = "dbt"
	efiImageSecurityDatabase3 = "dbr"
)

type efiGUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]uint8
}

func (e efiGUID) String() string {
	if s, ok := efiGUIDString[e]; ok {
		return s
	}
	return fmt.Sprintf("{0x%x,0x%x,0x%x,{%x}}", e.Data1, e.Data2, e.Data3, e.Data4)
}

var efiGUIDString = map[efiGUID]string{
	efiGlobalVariable:            "EFI_GLOBAL_VARIABLE",
	efiImageSecurityDatabaseGUID: "EFI_IMAGE_SECURITY_DATABASE_GUID",
}

type uefiVariableData struct {
	id   efiGUID
	name string
	data []byte
}

func (d *uefiVariableData) String() string {
	return fmt.Sprintf("%s %s data length %d", d.id, d.name, len(d.data))
}

// SecureBoot holds parsed PCR 7 values representing secure boot settings for
// the device.
type SecureBoot struct {
	Enabled bool

	// TODO(ericchiang): parse these as EFI_SIGNATURE_LIST
	//
	// https://uefi.org/sites/default/files/resources/UEFI_Spec_2_8_final.pdf#page=1788

	PK  []byte
	KEK []byte

	DB  []byte
	DBX []byte

	DBT []byte
	DBR []byte

	// Authority is the set of certificate that were used during secure boot
	// validation. This will be a subset of the certifiates in DB.
	Authority []byte
}

// ParseSecureBoot parses UEFI secure boot variables (PCR[7) from a verified event log.
//
// See https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClient_Specific_Platform_Profile_for_TPM_2p0_1p04_PUBLIC.pdf#page=56
func ParseSecureBoot(events []attest.Event) (*SecureBoot, error) {
	var sb SecureBoot
	seenSep := false
	for i, e := range events {
		if e.Index != 7 {
			continue
		}
		t := eventType(e.Type)
		switch t {
		case evEFIVariableDriverConfig:
			if seenSep {
				return nil, fmt.Errorf("event %d %s after %s", i, t, evSeparator)
			}
			data, err := parseUEFIVariableData(e.Data, e.Digest)
			if err != nil {
				return nil, fmt.Errorf("parsing event %d, PCR[%02d] %s: %v", i, e.Index, t, err)
			}

			switch data.id {
			case efiGlobalVariable:
				switch data.name {
				case efiGlobalVariableSecureBoot:
					if len(data.data) != 1 {
						return nil, fmt.Errorf("%s/%s was %d bytes", data.id, data.name, len(data.data))
					}
					switch data.data[0] {
					case 0x0:
						sb.Enabled = false
					case 0x1:
						sb.Enabled = true
					default:
						return nil, fmt.Errorf("invalid %s/%s value 0x%x", data.id, data.name, data.data)
					}
				case efiGlobalVariablePlatformKey:
					sb.PK = data.data
				case efiGlobalVariableKeyExchangeKey:
					sb.KEK = data.data
				}
			case efiImageSecurityDatabaseGUID:
				switch data.name {
				case efiImageSecurityDatabase:
					sb.DB = data.data
				case efiImageSecurityDatabase1:
					sb.DBX = data.data
				case efiImageSecurityDatabase2:
					sb.DBT = data.data
				case efiImageSecurityDatabase3:
					sb.DBR = data.data
				}
			}
		case evEFIVariableAuthority:
			if !seenSep {
				return nil, fmt.Errorf("event %d %s before %s", i, t, evSeparator)
			}
			data, err := parseUEFIVariableData(e.Data, e.Digest)
			if err != nil {
				return nil, fmt.Errorf("parsing event %d, PCR[%02d] %s: %v", i, e.Index, t, err)
			}
			switch data.id {
			case efiImageSecurityDatabaseGUID:
				switch data.name {
				case efiImageSecurityDatabase:
					if !sb.Enabled {
						return nil, fmt.Errorf("%s/%s present when secure boot wasn't enabled", t, data.name)
					}
					if len(sb.Authority) != 0 {
						// If a malicious value is appended to the eventlog,
						// ensure we only trust the first value written by
						// the UEFI firmware.
						return nil, fmt.Errorf("%s/%s was already present earlier in the event log", t, data.name)
					}
					sb.Authority = data.data
				}
			}
		case evSeparator:
			seenSep = true
		}
	}
	return &sb, nil
}

func binaryRead(r io.Reader, i interface{}) error {
	return binary.Read(r, binary.LittleEndian, i)
}

var hashBySize = map[int]crypto.Hash{
	crypto.SHA1.Size():   crypto.SHA1,
	crypto.SHA256.Size(): crypto.SHA256,
}

func verifyDigest(digest, data []byte) bool {
	h, ok := hashBySize[len(digest)]
	if !ok {
		return false
	}
	hash := h.New()
	hash.Write(data)
	return bytes.Equal(digest, hash.Sum(nil))
}

// parseUEFIVariableData parses a UEFI_VARIABLE_DATA struct and validates the
// digest of an event entry.
//
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClient_Specific_Platform_Profile_for_TPM_2p0_1p04_PUBLIC.pdf#page=100
func parseUEFIVariableData(b, digest []byte) (*uefiVariableData, error) {
	r := bytes.NewBuffer(b)
	var hdr struct {
		ID         efiGUID
		NameLength uint64
		DataLength uint64
	}
	if err := binaryRead(r, &hdr); err != nil {
		return nil, err
	}
	name := make([]uint16, hdr.NameLength)
	if err := binaryRead(r, &name); err != nil {
		return nil, fmt.Errorf("parsing name: %v", err)
	}
	if r.Len() != int(hdr.DataLength) {
		return nil, fmt.Errorf("remaining bytes %d doesn't match data length %d", r.Len(), hdr.DataLength)
	}
	data := r.Bytes()
	// TODO(ericchiang): older UEFI firmware (Lenovo Bios version 1.17) logs the
	// digest of the data, which doesn't encapsulate the ID or name. This lets
	// attackers alter keys and we should determine if this is an acceptable risk.
	if !verifyDigest(digest, b) && !verifyDigest(digest, data) {
		return nil, fmt.Errorf("digest didn't match data")
	}
	return &uefiVariableData{id: hdr.ID, name: string(utf16.Decode(name)), data: r.Bytes()}, nil
}
