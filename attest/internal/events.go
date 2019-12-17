package internal

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unicode/utf16"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/uuid"
)

// EventType describes the type of event signalled in the event log.
type EventType uint32

// 	BIOS Events (TCG PC Client Specific Implementation Specification for Conventional BIOS 1.21)
const (
	PrebootCert          EventType = 0x00000000
	PostCode             EventType = 0x00000001
	unused               EventType = 0x00000002
	NoAction             EventType = 0x00000003
	Separator            EventType = 0x00000004
	Action               EventType = 0x00000005
	EventTag             EventType = 0x00000006
	SCRTMContents        EventType = 0x00000007
	SCRTMVersion         EventType = 0x00000008
	CpuMicrocode         EventType = 0x00000009
	PlatformConfigFlags  EventType = 0x0000000A
	TableOfDevices       EventType = 0x0000000B
	CompactHash          EventType = 0x0000000C
	Ipl                  EventType = 0x0000000D
	IplPartitionData     EventType = 0x0000000E
	NonhostCode          EventType = 0x0000000F
	NonhostConfig        EventType = 0x00000010
	NonhostInfo          EventType = 0x00000011
	OmitBootDeviceEvents EventType = 0x00000012
)

// EFI Events (TCG EFI Platform Specification Version 1.22)
const (
	EFIEventBase               EventType = 0x80000000
	EFIVariableDriverConfig    EventType = 0x80000001
	EFIVariableBoot            EventType = 0x80000002
	EFIBootServicesApplication EventType = 0x80000003
	EFIBootServicesDriver      EventType = 0x80000004
	EFIRuntimeServicesDriver   EventType = 0x80000005
	EFIGPTEvent                EventType = 0x80000006
	EFIAction                  EventType = 0x80000007
	EFIPlatformFirmwareBlob    EventType = 0x80000008
	EFIHandoffTables           EventType = 0x80000009
	EFIHCRTMEvent              EventType = 0x80000010
	EFIVariableAuthority       EventType = 0x800000e0
)

var eventTypeNames = map[EventType]string{
	PrebootCert:          "Preboot Cert",
	PostCode:             "POST Code",
	unused:               "Unused",
	NoAction:             "No Action",
	Separator:            "Separator",
	Action:               "Action",
	EventTag:             "Event Tag",
	SCRTMContents:        "S-CRTM Contents",
	SCRTMVersion:         "S-CRTM Version",
	CpuMicrocode:         "CPU Microcode",
	PlatformConfigFlags:  "Platform Config Flags",
	TableOfDevices:       "Table of Devices",
	CompactHash:          "Compact Hash",
	Ipl:                  "IPL",
	IplPartitionData:     "IPL Partition Data",
	NonhostCode:          "Non-Host Code",
	NonhostConfig:        "Non-HostConfig",
	NonhostInfo:          "Non-Host Info",
	OmitBootDeviceEvents: "Omit Boot Device Events",

	EFIEventBase:               "EFI Event Base",
	EFIVariableDriverConfig:    "EFI Variable Driver Config",
	EFIVariableBoot:            "EFI Variable Boot",
	EFIBootServicesApplication: "EFI Boot Services Application",
	EFIBootServicesDriver:      "EFI Boot Services Driver",
	EFIRuntimeServicesDriver:   "EFI Runtime Services Driver",
	EFIGPTEvent:                "EFI GPT Event",
	EFIAction:                  "EFI Action",
	EFIPlatformFirmwareBlob:    "EFI Platform Firmware Blob",
	EFIVariableAuthority:       "EFI Variable Authority",
	EFIHandoffTables:           "EFI Handoff Tables",
	EFIHCRTMEvent:              "EFI H-CRTM Event",
}

func (e EventType) String() string {
	if s, ok := eventTypeNames[e]; ok {
		return s
	}
	return fmt.Sprintf("EventType(0x%x)", uint32(e))
}

// ExtractEventType returns the event type indicated by the provided value.
func ExtractEventType(et uint32) (EventType, error) {
	// "The value associated with a UEFI specific platform event type MUST be in
	// the range between 0x80000000 and 0x800000FF, inclusive."
	if (et < 0x80000000 && et > 0x800000FF) || (et < 0x0 && et > 0x12) {
		return EventType(0), fmt.Errorf("event type not between [0x0, 0x12] or [0x80000000, 0x800000FF]: got %#x", et)
	}
	if _, ok := eventTypeNames[EventType(et)]; !ok {
		return EventType(0), fmt.Errorf("unknown event type %#x", et)
	}
	return EventType(et), nil
}

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

// UEFIVariableDataHeader represents the leading fixed-size fields
// within UEFI_VARIABLE_DATA.
type UEFIVariableDataHeader struct {
	VariableName       efiGUID
	UnicodeNameLength  uint64 // uintN
	VariableDataLength uint64 // uintN
}

// UEFIVariableData represents the UEFI_VARIABLE_DATA structure.
type UEFIVariableData struct {
	Header       UEFIVariableDataHeader
	UnicodeName  []uint16
	VariableData []byte // []int8
}

// ParseUEFIVariableData parses the data section of an event structured as
// a UEFI variable.
func ParseUEFIVariableData(r io.Reader) (ret UEFIVariableData, err error) {
	err = binary.Read(r, binary.LittleEndian, &ret.Header)
	if err != nil {
		return
	}
	ret.UnicodeName = make([]uint16, ret.Header.UnicodeNameLength)
	for i := 0; uint64(i) < ret.Header.UnicodeNameLength; i++ {
		err = binary.Read(r, binary.LittleEndian, &ret.UnicodeName[i])
		if err != nil {
			return
		}
	}
	ret.VariableData = make([]byte, ret.Header.VariableDataLength)
	_, err = io.ReadFull(r, ret.VariableData)
	return
}

func (v *UEFIVariableData) VarName() string {
	return string(utf16.Decode(v.UnicodeName))
}

func (v *UEFIVariableData) SignatureData() (certs []x509.Certificate, hashes [][]byte, err error) {
	return parseEfiSignatureList(v.VariableData)
}

// UEFIVariableAuthority describes the contents of a UEFI variable authority
// event.
type UEFIVariableAuthority struct {
	Certs []x509.Certificate
}

// ParseUEFIVariableAuthority parses the data section of an event structured as
// a UEFI variable authority.
func ParseUEFIVariableAuthority(r io.Reader) (UEFIVariableAuthority, error) {
	v, err := ParseUEFIVariableData(r)
	if err != nil {
		return UEFIVariableAuthority{}, err
	}
	certs, err := parseEfiSignature(v.VariableData)
	if err != nil {
		return UEFIVariableAuthority{}, err
	}
	return UEFIVariableAuthority{Certs: certs}, nil
}

// efiSignatureData represents the EFI_SIGNATURE_DATA type.
// See section "31.4.1 Signature Database" in the specification for more information.
type efiSignatureData struct {
	SignatureOwner efiGUID
	SignatureData  []byte // []int8
}

// efiSignatureList represents the EFI_SIGNATURE_LIST type.
// See section "31.4.1 Signature Database" in the specification for more information.
type efiSignatureListHeader struct {
	SignatureType       efiGUID
	SignatureListSize   uint32
	SignatureHeaderSize uint32
	SignatureSize       uint32
}

type efiSignatureList struct {
	Header        efiSignatureListHeader
	SignatureData []byte
	Signatures    []byte
}

func parseEfiSignatureList(b []byte) ([]x509.Certificate, [][]byte, error) {
	if len(b) < 28 {
		// Being passed an empty signature list here appears to be valid
		return nil, nil, nil
	}
	signatures := efiSignatureList{}
	buf := bytes.NewReader(b)
	certificates := []x509.Certificate{}
	hashes := [][]byte{}

	for offset := 0; offset < len(b); {
		err := binary.Read(buf, binary.LittleEndian, &signatures.Header)
		if err != nil {
			return nil, nil, err
		}
		signatureType := signatures.Header.SignatureType.String()
		switch signatureType {
		case "a5c059a1-94e4-4aa7-87b5-ab155c2bf072": // X509 certificate
			for sigOffset := 0; uint32(sigOffset) < signatures.Header.SignatureListSize-28; {
				signature := efiSignatureData{}
				signature.SignatureData = make([]byte, signatures.Header.SignatureSize-16)
				err := binary.Read(buf, binary.LittleEndian, &signature.SignatureOwner)
				if err != nil {
					return nil, nil, err
				}
				err = binary.Read(buf, binary.LittleEndian, &signature.SignatureData)
				if err != nil {
					return nil, nil, err
				}
				cert, err := x509.ParseCertificate(signature.SignatureData)
				if err != nil {
					return nil, nil, err
				}
				sigOffset += int(signatures.Header.SignatureSize)
				certificates = append(certificates, *cert)
			}
		case "c1c41626-504c-4092-aca9-41f936934328": // SHA256
			for sigOffset := 0; uint32(sigOffset) < signatures.Header.SignatureListSize-28; {
				signature := efiSignatureData{}
				signature.SignatureData = make([]byte, signatures.Header.SignatureSize-16)
				err := binary.Read(buf, binary.LittleEndian, &signature.SignatureOwner)
				if err != nil {
					return nil, nil, err
				}
				err = binary.Read(buf, binary.LittleEndian, &signature.SignatureData)
				hashes = append(hashes, signature.SignatureData)
				sigOffset += int(signatures.Header.SignatureSize)
			}
		case "3c5766e8-269c-4e34-aa14-ed776e8b3b6": // Raw RSA2048 keys
			err = errors.New("unhandled RSA2048 key")
		case "e2b36190-879b-4a3d-ad8d-f2e7bba32784":
			err = errors.New("unhandled RSA2048-SHA256 key")
		case "826ca512-cf10-4ac9-b187-be01496631bd":
			err = errors.New("unhandled SHA1 hash")
		case "67f8444f-8743-48f1-a328-1eaab8736080":
			err = errors.New("unhandled RSA2048-SHA1 key")
		case "b6e5233-a65c-44c9-9407-d9ab83bfc8bd":
			err = errors.New("unhandled SHA224 hash")
		case "ff3e5307-9fd0-48c9-85f1-8ad56c701e01":
			err = errors.New("unhandled SHA384 hash")
		case "93e0fae-a6c4-4f50-9f1b-d41e2b89c19a":
			err = errors.New("unhandled SHA512 hash")
		case "3bd2a492-96c0-4079-b420-fcf98ef103ed":
			err = errors.New("unhandled X509-SHA256 key")
		default:
			err = fmt.Errorf("unhandled signature type %s", signatureType)
		}
		if err != nil {
			return nil, nil, err
		}
		offset += int(signatures.Header.SignatureListSize)
	}
	return certificates, hashes, nil
}

// EFISignatureData represents the EFI_SIGNATURE_DATA type.
// See section "31.4.1 Signature Database" in the specification
// for more information.
type EFISignatureData struct {
	SignatureOwner efiGUID
	SignatureData  []byte // []int8
}

func parseEfiSignature(b []byte) ([]x509.Certificate, error) {
	certificates := []x509.Certificate{}

	buf := bytes.NewReader(b)
	signature := EFISignatureData{}
	signature.SignatureData = make([]byte, len(b)-16)

	if err := binary.Read(buf, binary.LittleEndian, &signature.SignatureOwner); err != nil {
		return certificates, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &signature.SignatureData); err != nil {
		return certificates, err
	}
	cert, err := x509.ParseCertificate(signature.SignatureData)
	if err == nil {
		certificates = append(certificates, *cert)
	}
	return certificates, err
}
