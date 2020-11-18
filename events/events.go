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
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"regexp"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/google/go-attestation/attest"
	"github.com/google/uuid"
)

const (
	//      BIOS Events (TCG PC Client Specific Implementation Specification for Conventional BIOS 1.21)
	prebootCert          attest.EventType = 0x00000000
	postCode             attest.EventType = 0x00000001
	unused               attest.EventType = 0x00000002
	noAction             attest.EventType = 0x00000003
	separator            attest.EventType = 0x00000004
	action               attest.EventType = 0x00000005
	eventTag             attest.EventType = 0x00000006
	sCRTMContents        attest.EventType = 0x00000007
	sCRTMVersion         attest.EventType = 0x00000008
	cpuMicrocode         attest.EventType = 0x00000009
	platformConfigFlags  attest.EventType = 0x0000000A
	tableOfDevices       attest.EventType = 0x0000000B
	compactHash          attest.EventType = 0x0000000C
	ipl                  attest.EventType = 0x0000000D
	iplPartitionData     attest.EventType = 0x0000000E
	nonhostCode          attest.EventType = 0x0000000F
	nonhostConfig        attest.EventType = 0x00000010
	nonhostInfo          attest.EventType = 0x00000011
	omitBootDeviceEvents attest.EventType = 0x00000012

	// EFI Events (TCG EFI Platform Specification Version 1.22)
	efiEventBase               attest.EventType = 0x80000000
	efiVariableDriverConfig    attest.EventType = 0x80000001
	efiVariableBoot            attest.EventType = 0x80000002
	efiBootServicesApplication attest.EventType = 0x80000003
	efiBootServicesDriver      attest.EventType = 0x80000004
	efiRuntimeServicesDriver   attest.EventType = 0x80000005
	efiGPTEvent                attest.EventType = 0x80000006
	efiAction                  attest.EventType = 0x80000007
	efiPlatformFirmwareBlob    attest.EventType = 0x80000008
	efiHandoffTables           attest.EventType = 0x80000009
	efiHCRTMEvent              attest.EventType = 0x80000010
	efiVariableAuthority       attest.EventType = 0x800000e0
)

type eventID uint32

const (
	smbios                 eventID = 0x00
	bisCertificate         eventID = 0x01
	postBIOSROM            eventID = 0x02
	escdeventID            eventID = 0x03
	cmos                   eventID = 0x04
	nvram                  eventID = 0x05
	optionROMExecute       eventID = 0x06
	optionROMConfiguration eventID = 0x07
)

// efiGUID represents the EFI_GUID type.
// See section "2.3.1 Data Types" in the specification for more information.
// type efiGUID [16]byte
type efiGUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

func (d efiGUID) String() string {
	var buf bytes.Buffer

	if err := binary.Write(&buf, binary.BigEndian, d.Data1); err != nil {
		return ""
	}
	if err := binary.Write(&buf, binary.BigEndian, d.Data2); err != nil {
		return ""
	}
	if err := binary.Write(&buf, binary.BigEndian, d.Data3); err != nil {
		return ""
	}
	if err := binary.Write(&buf, binary.BigEndian, d.Data4); err != nil {
		return ""
	}
	uuid := uuid.UUID{}
	if err := uuid.UnmarshalBinary(buf.Bytes()); err != nil {
		return ""
	}
	return uuid.String()
}

// efiConfigurationTable represents the EFI_CONFIGURATION_TABLE type.
// See section "4.6 EFI Configuration Table & Properties Table" in the specification for more information.
type efiConfigurationTable struct {
	VendorGUID  efiGUID
	VendorTable uint64 // "A pointer to the table associated with VendorGuid"
}

type uefiVariableDataHeader struct {
	VariableName       efiGUID
	UnicodeNameLength  uint64 // uintN
	VariableDataLength uint64 // uintN
}

// uefiVariableData represents the UEFI_VARIABLE_DATA structure.
type uefiVariableData struct {
	Header       uefiVariableDataHeader
	UnicodeName  []uint16
	VariableData []byte // []int8
}

// efiTableHeader represents the EFI_TABLE_HEADER type.
// See section "4.2 EFI Table Header" in the specification for more information.
type efiTableHeader struct {
	Signature  uint64
	Revision   uint32
	HeaderSize uint32
	CRC32      uint32
	Reserved   uint32
}

// efiPartitionTableHeader represents the structure described by "Table 20. GPT Header."
// See section "5.3.2 GPT Header" in the specification for more information.
type efiPartitionTableHeader struct {
	Header                   efiTableHeader
	MyLBA                    efiLBA
	AlternateLBA             efiLBA
	FirstUsableLBA           efiLBA
	LastUsableLBA            efiLBA
	DiskGUID                 efiGUID
	PartitionEntryLBA        efiLBA
	NumberOfPartitionEntries uint32
	SizeOfPartitionEntry     uint32
	PartitionEntryArrayCRC32 uint32
}

// efiPartition represents the structure described by "Table 21. GPT Partition Entry."
// See section "5.3.3 GPT Partition Entry" in the specification for more information.
type efiPartition struct {
	TypeGUID       efiGUID
	PartitionGUID  efiGUID
	FirstLBA       efiLBA
	LastLBA        efiLBA
	AttributeFlags uint64
	PartitionName  [36]uint16
}

type TPMEvent interface {
	RawEvent() attest.Event
}

type baseEvent struct {
	attest.Event
	Err error
}

type stringEvent struct {
	baseEvent
	Message string
}

type PrebootCertEvent struct {
	baseEvent
}

type PostEvent struct {
	stringEvent
}

type NoActionEvent struct {
	baseEvent
}

type SeparatorEvent struct {
	baseEvent
}

type ActionEvent struct {
	stringEvent
}

type EventTagEvent struct {
	baseEvent
	EventID   eventID
	EventData []byte
}

type CRTMContentEvent struct {
	stringEvent
}

type CRTMEvent struct {
	stringEvent
}

type MicrocodeEvent struct {
	stringEvent
}

type PlatformConfigFlagsEvent struct {
	baseEvent
}

type TableOfDevicesEvent struct {
	baseEvent
}

type CompactHashEvent struct {
	baseEvent
}

type IPLEvent struct {
	stringEvent
}

type IPLPartitionEvent struct {
	baseEvent
}

type NonHostCodeEvent struct {
	baseEvent
}

type NonHostConfigEvent struct {
	baseEvent
}

type NonHostInfoEvent struct {
	baseEvent
}

type OmitBootDeviceEventsEvent struct {
	stringEvent
}

type uefiVariableEvent struct {
	baseEvent
	VariableGUID efiGUID
	VariableName string
	VariableData []byte
}

type UefiVariableDriverConfigEvent struct {
	uefiVariableEvent
}

type UefiBootVariableEvent struct {
	uefiVariableEvent
	Description   string
	DevicePath    string
	DevicePathRaw []byte
	OptionalData  []byte
}

type UefiVariableAuthorityEvent struct {
	uefiVariableEvent
}

type uefiImageLoadEvent struct {
	baseEvent
	ImageLocationInMemory uint64
	ImageLengthInMemory   uint64
	ImageLinkTimeAddress  uint64
	DevicePath            string
	DevicePathRaw         []byte
}

type UefiBootServicesApplicationEvent struct {
	uefiImageLoadEvent
}

type UefiBootServicesDriverEvent struct {
	uefiImageLoadEvent
}

type UefiRuntimeServicesDriverEvent struct {
	uefiImageLoadEvent
}

type UefiActionEvent struct {
	stringEvent
}

type UefiGPTEvent struct {
	baseEvent
	UEFIPartitionHeader efiPartitionTableHeader
	Partitions          []efiPartition
}

type UefiPlatformFirmwareBlobEvent struct {
	baseEvent
	BlobBase   uint64
	BlobLength uint64
}

type UefiHandoffTableEvent struct {
	baseEvent
	Tables []efiConfigurationTable
}

type OptionROMConfigEvent struct {
	baseEvent
	PFA             uint16
	OptionROMStruct []byte
}

type MicrosoftBootEvent struct {
	baseEvent
	Events []MicrosoftEvent
}

func (event baseEvent) RawEvent() attest.Event {
	return event.Event
}

func parseStringData(b []byte) (string, error) {
	var buf []uint16
	for i := 0; i < len(b); i += 2 {
		if b[i+1] != 0x00 {
			buf = nil
			break
		}
		buf = append(buf, binary.LittleEndian.Uint16(b[i:]))
	}

	if buf != nil {
		return string(utf16.Decode(buf)), nil
	}

	if !utf8.Valid(b) {
		return "", errors.New("invalid UTF-8 string")
	}

	return string(b), nil
}

func parseEfiVariableData(b []byte, parsedEvent *uefiVariableEvent) error {
	var header uefiVariableDataHeader
	buf := bytes.NewBuffer(b)
	err := binary.Read(buf, binary.LittleEndian, &header)
	if err != nil {
		return err
	}
	unicodeName := make([]uint16, header.UnicodeNameLength)
	for i := 0; i < int(header.UnicodeNameLength); i++ {
		err = binary.Read(buf, binary.LittleEndian, &unicodeName[i])
		if err != nil {
			return err
		}
	}
	parsedEvent.VariableGUID = header.VariableName
	parsedEvent.VariableName = string(utf16.Decode(unicodeName))
	parsedEvent.VariableData = make([]byte, header.VariableDataLength)
	_, err = io.ReadFull(buf, parsedEvent.VariableData)
	return err
}

// Regular expression that matches UEFI "Boot####" variable names
var bootOption = regexp.MustCompile(`^Boot[0-9A-F]{4}$`)

func parseEfiBootVariableData(b []byte, parsedEvent *UefiBootVariableEvent) error {
	var attributes uint32
	var dplength uint16
	var description []uint16
	var dpoffset int

	err := parseEfiVariableData(b, &parsedEvent.uefiVariableEvent)
	if err != nil {
		return err
	}

	if !bootOption.MatchString(parsedEvent.VariableName) {
		return nil
	}

	buf := bytes.NewBuffer(parsedEvent.VariableData)

	err = binary.Read(buf, binary.LittleEndian, &attributes)
	if err != nil {
		return err
	}
	err = binary.Read(buf, binary.LittleEndian, &dplength)
	if err != nil {
		return err
	}

	// The device path starts after the null terminator in the UTF16 description
	for dpoffset = 6; dpoffset < len(parsedEvent.VariableData); dpoffset += 2 {
		var tmp uint16
		err = binary.Read(buf, binary.LittleEndian, &tmp)

		description = append(description, tmp)
		if tmp == 0 {
			// Null terminator
			dpoffset += 2
			break
		}
	}

	parsedEvent.Description = string(utf16.Decode(description))

	// Verify that the structure is well formed
	if dpoffset+int(dplength) > len(parsedEvent.VariableData) {
		return fmt.Errorf("malformed boot variable")
	}

	parsedEvent.DevicePathRaw = make([]byte, dplength)
	err = binary.Read(buf, binary.LittleEndian, &parsedEvent.DevicePathRaw)
	if err != nil {
		return err
	}
	parsedEvent.DevicePath, err = efiDevicePath(parsedEvent.DevicePathRaw)
	if err != nil {
		return err
	}

	// Check whether there's any optional data
	optionaldatalen := len(parsedEvent.VariableData) - dpoffset - int(dplength)
	if optionaldatalen > 0 {
		parsedEvent.OptionalData = make([]byte, optionaldatalen)
		err = binary.Read(buf, binary.LittleEndian, &parsedEvent.OptionalData)
	}

	return err
}

func parseEfiImageLoadEvent(b []byte, parsedEvent *uefiImageLoadEvent) error {
	var devicePathLength uint64
	buf := bytes.NewBuffer(b)

	err := binary.Read(buf, binary.LittleEndian, &parsedEvent.ImageLocationInMemory)
	if err != nil {
		return err
	}
	err = binary.Read(buf, binary.LittleEndian, &parsedEvent.ImageLengthInMemory)
	if err != nil {
		return err
	}
	err = binary.Read(buf, binary.LittleEndian, &parsedEvent.ImageLinkTimeAddress)
	if err != nil {
		return err
	}
	err = binary.Read(buf, binary.LittleEndian, &devicePathLength)
	if err != nil {
		return err
	}
	parsedEvent.DevicePathRaw = make([]byte, devicePathLength)
	err = binary.Read(buf, binary.LittleEndian, &parsedEvent.DevicePathRaw)
	if err != nil {
		return err
	}
	parsedEvent.DevicePath, err = efiDevicePath(parsedEvent.DevicePathRaw)

	return err
}

func parseUefiGPTEvent(b []byte, parsedEvent *UefiGPTEvent) error {
	r := bytes.NewReader(b)
	err := binary.Read(r, binary.LittleEndian, &parsedEvent.UEFIPartitionHeader)
	if err != nil {
		return err
	}

	var numPartitions uint64
	err = binary.Read(r, binary.LittleEndian, &numPartitions)
	if err != nil {
		return err
	}

	if numPartitions*uint64(parsedEvent.UEFIPartitionHeader.SizeOfPartitionEntry) > uint64(r.Len()) {
		err = fmt.Errorf("(numPartitions * SizeOfPartitionEntry) > b.Len(), %d > %d", numPartitions*uint64(parsedEvent.UEFIPartitionHeader.SizeOfPartitionEntry), r.Len())
		return err
	}

	for i := uint64(0); i < numPartitions; i++ {
		r.Seek(int64(100+i*uint64(parsedEvent.UEFIPartitionHeader.SizeOfPartitionEntry)), io.SeekStart)
		var partition efiPartition
		err = binary.Read(r, binary.LittleEndian, &partition)
		if err != nil {
			return err
		}
		parsedEvent.Partitions = append(parsedEvent.Partitions, partition)
	}

	return nil
}

func parseUefiPlatformFirmwareBlobEvent(b []byte, parsedEvent *UefiPlatformFirmwareBlobEvent) error {
	if len(b) != 16 {
		return fmt.Errorf("unexpected length for a platform firmware blob event: %d", len(b))
	}
	parsedEvent.BlobBase = binary.LittleEndian.Uint64(b)
	parsedEvent.BlobLength = binary.LittleEndian.Uint64(b[8:])
	return nil
}

func parseEFIGUID(r io.Reader) (ret efiGUID, err error) {
	if err = binary.Read(r, binary.LittleEndian, &ret.Data1); err != nil {
		return
	}
	if err = binary.Read(r, binary.LittleEndian, &ret.Data2); err != nil {
		return
	}
	if err = binary.Read(r, binary.LittleEndian, &ret.Data3); err != nil {
		return
	}
	_, err = r.Read(ret.Data4[:])
	return
}

func parseUefiHandoffTableEvent(b []byte, parsedEvent *UefiHandoffTableEvent) error {
	r := bytes.NewReader(b)
	var numTables uint64
	err := binary.Read(r, binary.LittleEndian, &numTables)
	if err != nil {
		return err
	}
	parsedEvent.Tables = make([]efiConfigurationTable, numTables)
	for i := uint64(0); i < numTables; i++ {
		if parsedEvent.Tables[i].VendorGUID, err = parseEFIGUID(r); err != nil {
			err = fmt.Errorf("TableEntry[%d]: %v", i, err)
			return err
		}
		if err = binary.Read(r, binary.LittleEndian, &parsedEvent.Tables[i].VendorTable); err != nil {
			err = fmt.Errorf("TableEntry[%d]: %v", i, err)
			return err
		}
	}
	return err
}

func parseOptionROMConfig(b []byte, parsedEvent *OptionROMConfigEvent) error {
	r := bytes.NewReader(b)
	var dummy uint16
	if err := binary.Read(r, binary.LittleEndian, &dummy); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &parsedEvent.PFA); err != nil {
		return err
	}
	_, err := io.ReadFull(r, parsedEvent.OptionROMStruct)
	return err
}

func ParseEvents(events []attest.Event) ([]TPMEvent, error) {
	var parsedEvents []TPMEvent

	for _, event := range events {
		buf := bytes.NewBuffer(event.Data)
		var err error
		switch event.Type {
		case prebootCert: // 0x00
			var parsedEvent PrebootCertEvent
			parsedEvent.Event = event
			parsedEvents = append(parsedEvents, parsedEvent)
		case postCode: // 0x01
			var parsedEvent PostEvent
			parsedEvent.Event = event
			parsedEvent.Message, err = parseStringData(event.Data)
			if err != nil {
				parsedEvent.Err = err
			}
			parsedEvents = append(parsedEvents, parsedEvent)
		case noAction: // 0x03
			var parsedEvent NoActionEvent
			parsedEvent.Event = event
			parsedEvents = append(parsedEvents, parsedEvent)
		case separator: // 0x04
			var parsedEvent SeparatorEvent
			parsedEvent.Event = event
			parsedEvents = append(parsedEvents, parsedEvent)
		case action: // 0x05
			var parsedEvent ActionEvent
			parsedEvent.Event = event
			parsedEvent.Message, err = parseStringData(event.Data)
			if err != nil {
				parsedEvent.Err = err
			}
			parsedEvents = append(parsedEvents, parsedEvent)
		case eventTag: // 0x06
			var parsedEvent EventTagEvent
			var eventSize uint32
			parsedEvent.EventData = event.Data[8:]
			parsedEvent.Event = event
			if err := binary.Read(buf, binary.LittleEndian, &parsedEvent.EventID); err != nil {
				parsedEvent.Err = err
				parsedEvents = append(parsedEvents, parsedEvent)
				continue
			}
			if err := binary.Read(buf, binary.LittleEndian, &eventSize); err != nil {
				parsedEvent.Err = err
				parsedEvents = append(parsedEvents, parsedEvent)
				continue
			}
			switch parsedEvent.EventID {
			case optionROMConfiguration:
				var OptionROMConfigEvent OptionROMConfigEvent
				OptionROMConfigEvent.Event = event
				err := parseOptionROMConfig(parsedEvent.EventData, &OptionROMConfigEvent)
				if err != nil {
					parsedEvent.Err = err
					parsedEvents = append(parsedEvents, parsedEvent)
					continue
				}
				OptionROMConfigEvent.Event = event
				parsedEvents = append(parsedEvents, OptionROMConfigEvent)
			default:
				var MicrosoftEvent MicrosoftBootEvent
				// Pass the raw event data including the header
				err := parseMicrosoftEvent(parsedEvent.Data, &MicrosoftEvent)
				if err != nil {
					parsedEvent.Err = err
					parsedEvents = append(parsedEvents, parsedEvent)
					continue
				}
				MicrosoftEvent.Event = event
				parsedEvents = append(parsedEvents, MicrosoftEvent)
			}
		case sCRTMContents: // 0x07
			var parsedEvent CRTMContentEvent
			parsedEvent.Event = event
			parsedEvent.Message, err = parseStringData(event.Data)
			parsedEvents = append(parsedEvents, parsedEvent)
		case sCRTMVersion: // 0x08
			var parsedEvent CRTMEvent
			parsedEvent.Event = event
			parsedEvent.Message, err = parseStringData(event.Data)
			if err != nil {
				parsedEvent.Err = err
			}
			parsedEvents = append(parsedEvents, parsedEvent)
		case cpuMicrocode: // 0x09
			var parsedEvent MicrocodeEvent
			parsedEvent.Event = event
			parsedEvent.Message, err = parseStringData(event.Data)
			if err != nil {
				parsedEvent.Err = err
			}
			parsedEvents = append(parsedEvents, parsedEvent)
		case platformConfigFlags: // 0x0a
			var parsedEvent PlatformConfigFlagsEvent
			parsedEvent.Event = event
			parsedEvents = append(parsedEvents, parsedEvent)
		case tableOfDevices: // 0x0b
			var parsedEvent TableOfDevicesEvent
			parsedEvent.Event = event
			parsedEvents = append(parsedEvents, parsedEvent)
		case compactHash: // 0x0c
			var parsedEvent CompactHashEvent
			parsedEvent.Event = event
			parsedEvents = append(parsedEvents, parsedEvent)
		case ipl: // 0x0d
			var parsedEvent IPLEvent
			parsedEvent.Event = event
			parsedEvent.Message, err = parseStringData(event.Data)
			if err != nil {
				parsedEvent.Err = err
			}
			parsedEvents = append(parsedEvents, parsedEvent)
		case iplPartitionData: // 0x0e
			var parsedEvent IPLPartitionEvent
			parsedEvent.Event = event
			parsedEvents = append(parsedEvents, parsedEvent)
		case nonhostCode: // 0x0f
			var parsedEvent NonHostCodeEvent
			parsedEvent.Event = event
			parsedEvents = append(parsedEvents, parsedEvent)
		case nonhostConfig: // 0x10
			var parsedEvent NonHostConfigEvent
			parsedEvent.Event = event
			parsedEvents = append(parsedEvents, parsedEvent)
		case nonhostInfo: // 0x11
			var parsedEvent NonHostInfoEvent
			parsedEvent.Event = event
			parsedEvents = append(parsedEvents, parsedEvent)
		case omitBootDeviceEvents: // 0x12
			var parsedEvent OmitBootDeviceEventsEvent
			parsedEvent.Event = event
			parsedEvent.Message, err = parseStringData(event.Data)
			if err != nil {
				parsedEvent.Err = err
			}
			parsedEvents = append(parsedEvents, parsedEvent)
		case efiVariableDriverConfig: // 0x80000001
			var parsedEvent UefiVariableDriverConfigEvent
			parsedEvent.Event = event
			err = parseEfiVariableData(event.Data, &parsedEvent.uefiVariableEvent)
			if err != nil {
				parsedEvent.Err = err
			}
			parsedEvents = append(parsedEvents, parsedEvent)
		case efiVariableBoot: // 0x80000002
			var parsedEvent UefiBootVariableEvent
			parsedEvent.Event = event
			err = parseEfiBootVariableData(event.Data, &parsedEvent)
			if err != nil {
				parsedEvent.Err = err
			}
			parsedEvents = append(parsedEvents, parsedEvent)
		case efiBootServicesApplication: // 0x80000003
			var parsedEvent UefiBootServicesApplicationEvent
			parsedEvent.Event = event
			err = parseEfiImageLoadEvent(event.Data, &parsedEvent.uefiImageLoadEvent)
			if err != nil {
				parsedEvent.Err = err
			}
			parsedEvents = append(parsedEvents, parsedEvent)
		case efiBootServicesDriver: // 0x80000004
			var parsedEvent UefiBootServicesDriverEvent
			parsedEvent.Event = event
			err = parseEfiImageLoadEvent(event.Data, &parsedEvent.uefiImageLoadEvent)
			if err != nil {
				parsedEvent.Err = err
			}
			parsedEvents = append(parsedEvents, parsedEvent)
		case efiAction: // 0x80000005
			var parsedEvent UefiActionEvent
			parsedEvent.Event = event
			parsedEvent.Message, err = parseStringData(event.Data)
			if err != nil {
				parsedEvent.Err = err
			}
			parsedEvents = append(parsedEvents, parsedEvent)
		case efiRuntimeServicesDriver: // 0x80000006
			var parsedEvent UefiRuntimeServicesDriverEvent
			parsedEvent.Event = event
			err = parseEfiImageLoadEvent(event.Data, &parsedEvent.uefiImageLoadEvent)
			if err != nil {
				parsedEvent.Err = err
			}
			parsedEvents = append(parsedEvents, parsedEvent)
		case efiGPTEvent: // 0x80000007
			var parsedEvent UefiGPTEvent
			parsedEvent.Event = event
			err = parseUefiGPTEvent(event.Data, &parsedEvent)
			if err != nil {
				parsedEvent.Err = err
			}
			parsedEvents = append(parsedEvents, parsedEvent)
		case efiPlatformFirmwareBlob: // 0x80000008
			var parsedEvent UefiPlatformFirmwareBlobEvent
			parsedEvent.Event = event
			err = parseUefiPlatformFirmwareBlobEvent(event.Data, &parsedEvent)
			if err != nil {
				parsedEvent.Err = err
			}
			parsedEvents = append(parsedEvents, parsedEvent)
		case efiHandoffTables:
			var parsedEvent UefiHandoffTableEvent
			parsedEvent.Event = event
			err = parseUefiHandoffTableEvent(event.Data, &parsedEvent)
			if err != nil {
				parsedEvent.Err = err
			}
			parsedEvents = append(parsedEvents, parsedEvent)
		case efiVariableAuthority:
			var parsedEvent UefiVariableAuthorityEvent
			parsedEvent.Event = event
			err = parseEfiVariableData(event.Data, &parsedEvent.uefiVariableEvent)
			if err != nil {
				parsedEvent.Err = err
			}
			parsedEvents = append(parsedEvents, parsedEvent)
		}
	}

	return parsedEvents, nil
}
