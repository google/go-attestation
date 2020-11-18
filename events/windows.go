package events

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"unicode/utf16"
)

type microsoftEventHeader struct {
	Type windowsEvent
	Size uint32
}

type microsoftBootRevocationList struct {
	CreationTime  uint64
	DigestLength  uint32
	HashAlgorithm uint16
	Digest        []byte
}

type windowsEvent uint32

type MicrosoftEvent interface {
}

type microsoftBaseEvent struct {
	Type windowsEvent
}

type MicrosoftStringEvent struct {
	microsoftBaseEvent
	Message string
}

type MicrosoftRevocationEvent struct {
	microsoftBaseEvent
	CreationTime  uint64
	DigestLength  uint32
	HashAlgorithm uint16
	Digest        []byte
}

type MicrosoftDataEvent struct {
	microsoftBaseEvent
	Data []byte
}

// SIPA event types
const (
	sipaTypeMask                    windowsEvent = 0x000f0000
	sipaContainer                   windowsEvent = 0x00010000
	sipaInformation                 windowsEvent = 0x00020000
	sipaError                       windowsEvent = 0x00030000
	sipaPreOsParameter              windowsEvent = 0x00040000
	sipaOSParameter                 windowsEvent = 0x00050000
	sipaAuthority                   windowsEvent = 0x00060000
	sipaLoadedModule                windowsEvent = 0x00070000
	sipaTrustPoint                  windowsEvent = 0x00080000
	sipaELAM                        windowsEvent = 0x00090000
	sipaVBS                         windowsEvent = 0x000a0000
	trustBoundary                   windowsEvent = 0x40010001
	elamAggregation                 windowsEvent = 0x40010002
	loadedModuleAggregation         windowsEvent = 0x40010003
	trustpointAggregation           windowsEvent = 0xC0010004
	ksrAggregation                  windowsEvent = 0x40010005
	ksrSignedMeasurementAggregation windowsEvent = 0x40010006
	information                     windowsEvent = 0x00020001
	bootCounter                     windowsEvent = 0x00020002
	transferControl                 windowsEvent = 0x00020003
	applicationReturn               windowsEvent = 0x00020004
	bitlockerUnlock                 windowsEvent = 0x00020005
	eventCounter                    windowsEvent = 0x00020006
	counterID                       windowsEvent = 0x00020007
	morBitNotCancelable             windowsEvent = 0x00020008
	applicationSVN                  windowsEvent = 0x00020009
	svnChainStatus                  windowsEvent = 0x0002000A
	morBitAPIStatus                 windowsEvent = 0x0002000B
	bootDebugging                   windowsEvent = 0x00040001
	bootRevocationList              windowsEvent = 0x00040002
	osKernelDebug                   windowsEvent = 0x00050001
	codeIntegrity                   windowsEvent = 0x00050002
	testSigning                     windowsEvent = 0x00050003
	dataExecutionPrevention         windowsEvent = 0x00050004
	safeMode                        windowsEvent = 0x00050005
	winPE                           windowsEvent = 0x00050006
	physicalAddressExtension        windowsEvent = 0x00050007
	osDevice                        windowsEvent = 0x00050008
	systemRoot                      windowsEvent = 0x00050009
	hypervisorLaunchType            windowsEvent = 0x0005000A
	hypervisorPath                  windowsEvent = 0x0005000B
	hypervisorIOMMUPolicy           windowsEvent = 0x0005000C
	hypervisorDebug                 windowsEvent = 0x0005000D
	driverLoadPolicy                windowsEvent = 0x0005000E
	siPolicy                        windowsEvent = 0x0005000F
	hypervisorMMIONXPolicy          windowsEvent = 0x00050010
	hypervisorMSRFilterPolicy       windowsEvent = 0x00050011
	vsmLaunchType                   windowsEvent = 0x00050012
	osRevocationList                windowsEvent = 0x00050013
	vsmIDKInfo                      windowsEvent = 0x00050020
	flightSigning                   windowsEvent = 0x00050021
	pagefileEncryptionEnabled       windowsEvent = 0x00050022
	vsmIDKSInfo                     windowsEvent = 0x00050023
	hibernationDisabled             windowsEvent = 0x00050024
	dumpsDisabled                   windowsEvent = 0x00050025
	dumpEncryptionEnabled           windowsEvent = 0x00050026
	dumpEncryptionKeyDigest         windowsEvent = 0x00050027
	lsaISOConfig                    windowsEvent = 0x00050028
	noAuthority                     windowsEvent = 0x00060001
	authorityPubKey                 windowsEvent = 0x00060002
	filePath                        windowsEvent = 0x00070001
	imageSize                       windowsEvent = 0x00070002
	hashAlgorithmID                 windowsEvent = 0x00070003
	authenticodeHash                windowsEvent = 0x00070004
	authorityIssuer                 windowsEvent = 0x00070005
	authoritySerial                 windowsEvent = 0x00070006
	imageBase                       windowsEvent = 0x00070007
	authorityPublisher              windowsEvent = 0x00070008
	authoritySHA1Thumbprint         windowsEvent = 0x00070009
	imageValidated                  windowsEvent = 0x0007000A
	moduleSVN                       windowsEvent = 0x0007000B
	quote                           windowsEvent = 0x80080001
	quoteSignature                  windowsEvent = 0x80080002
	aikID                           windowsEvent = 0x80080003
	aikPubDigest                    windowsEvent = 0x80080004
	elamKeyname                     windowsEvent = 0x00090001
	elamConfiguration               windowsEvent = 0x00090002
	elamPolicy                      windowsEvent = 0x00090003
	elamMeasured                    windowsEvent = 0x00090004
	vbsVSMRequired                  windowsEvent = 0x000A0001
	vbsSecurebootRequired           windowsEvent = 0x000A0002
	vbsIOMMURequired                windowsEvent = 0x000A0003
	vbsNXRequired                   windowsEvent = 0x000A0004
	vbsMSRFilteringRequired         windowsEvent = 0x000A0005
	vbsMandatoryEnforcement         windowsEvent = 0x000A0006
	vbsHVCIPolicy                   windowsEvent = 0x000A0007
	vbsMicrosoftBootChainRequired   windowsEvent = 0x000A0008
	ksrSignature                    windowsEvent = 0x000B0001
)

var windowsEventNames = map[windowsEvent]string{
	trustBoundary:                   "TrustBoundary",
	elamAggregation:                 "ELAMAggregation",
	loadedModuleAggregation:         "LoadedModuleAggregation",
	trustpointAggregation:           "TrustpointAggregation",
	ksrAggregation:                  "KSRAggregation",
	ksrSignedMeasurementAggregation: "KSRSignedMeasurementAggregation",
	information:                     "Information",
	bootCounter:                     "BootCounter",
	transferControl:                 "TransferControl",
	applicationReturn:               "ApplicationReturn",
	bitlockerUnlock:                 "BitlockerUnlock",
	eventCounter:                    "EventCounter",
	counterID:                       "CounterID",
	morBitNotCancelable:             "MORBitNotCancelable",
	applicationSVN:                  "ApplicationSVN",
	svnChainStatus:                  "SVNChainStatus",
	morBitAPIStatus:                 "MORBitAPIStatus",
	bootDebugging:                   "BootDebugging",
	bootRevocationList:              "BootRevocationList",
	osKernelDebug:                   "OSKernelDebug",
	codeIntegrity:                   "CodeIntegrity",
	testSigning:                     "TestSigning",
	dataExecutionPrevention:         "DataExecutionPrevention",
	safeMode:                        "SafeMode",
	winPE:                           "WinPE",
	physicalAddressExtension:        "PhysicalAddressExtension",
	osDevice:                        "OSDevice",
	systemRoot:                      "SystemRoot",
	hypervisorLaunchType:            "HypervisorLaunchType",
	hypervisorPath:                  "HypervisorPath",
	hypervisorIOMMUPolicy:           "HypervisorIOMMUPolicy",
	hypervisorDebug:                 "HypervisorDebug",
	driverLoadPolicy:                "DriverLoadPolicy",
	siPolicy:                        "SIPolicy",
	hypervisorMMIONXPolicy:          "HypervisorMMIONXPolicy",
	hypervisorMSRFilterPolicy:       "HypervisorMSRFilterPolicy",
	vsmLaunchType:                   "VSMLaunchType",
	osRevocationList:                "OSRevocationList",
	vsmIDKInfo:                      "VSMIDKInfo",
	flightSigning:                   "FlightSigning",
	pagefileEncryptionEnabled:       "PagefileEncryptionEnabled",
	vsmIDKSInfo:                     "VSMIDKSInfo",
	hibernationDisabled:             "HibernationDisabled",
	dumpsDisabled:                   "DumpsDisabled",
	dumpEncryptionEnabled:           "DumpEncryptionEnabled",
	dumpEncryptionKeyDigest:         "DumpEncryptionKeyDigest",
	lsaISOConfig:                    "LSAISOConfig",
	noAuthority:                     "NoAuthority",
	authorityPubKey:                 "AuthorityPubKey",
	filePath:                        "FilePath",
	imageSize:                       "ImageSize",
	hashAlgorithmID:                 "HashAlgorithmID",
	authenticodeHash:                "AuthenticodeHash",
	authorityIssuer:                 "AuthorityIssuer",
	authoritySerial:                 "AuthoritySerial",
	imageBase:                       "ImageBase",
	authorityPublisher:              "AuthorityPublisher",
	authoritySHA1Thumbprint:         "AuthoritySHA1Thumbprint",
	imageValidated:                  "ImageValidated",
	moduleSVN:                       "ModuleSVN",
	quote:                           "Quote",
	quoteSignature:                  "QuoteSignature",
	aikID:                           "AIKID",
	aikPubDigest:                    "AIKPubDigest",
	elamKeyname:                     "ELAMKeyname",
	elamConfiguration:               "ELAMConfiguration",
	elamPolicy:                      "ELAMPolicy",
	elamMeasured:                    "ELAMMeasured",
	vbsVSMRequired:                  "VBSVSMRequired",
	vbsSecurebootRequired:           "VBSSecurebootRequired",
	vbsIOMMURequired:                "VBSIOMMURequired",
	vbsNXRequired:                   "VBSNXRequired",
	vbsMSRFilteringRequired:         "VBSMSRFilteringRequired",
	vbsMandatoryEnforcement:         "VBSMandatoryEnforcement",
	vbsHVCIPolicy:                   "VBSHVCIPolicy",
	vbsMicrosoftBootChainRequired:   "VBSMicrosoftBootChainRequired",
	ksrSignature:                    "KSRSignature",
}

func (e windowsEvent) String() string {
	if s, ok := windowsEventNames[e]; ok {
		return s
	}
	return fmt.Sprintf("windowsEvent(%#v)", uint32(e))
}

func parseMicrosoftEvent(b []byte, parsedEvent *MicrosoftBootEvent) error {
	events, err := parseMicrosoftEventContainer(b)
	if err != nil {
		return err
	}
	parsedEvent.Events = events
	return nil
}

func parseMicrosoftEventContainer(b []byte) ([]MicrosoftEvent, error) {
	var header microsoftEventHeader
	var events []MicrosoftEvent
	r := bytes.NewReader(b)
	for {
		err := binary.Read(r, binary.LittleEndian, &header)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("unable to read Windows event: %v", err)
		}
		data := make([]byte, header.Size)
		if err = binary.Read(r, binary.LittleEndian, &data); err != nil {
			return nil, fmt.Errorf("unable to read Windows event: %v", err)
		}
		if (header.Type & sipaTypeMask) == sipaContainer {
			ret, err := parseMicrosoftEventContainer(data)
			if err != nil {
				return nil, fmt.Errorf("unable to parse Windows event container: %v", err)
			}
			events = append(events, ret...)
			continue
		}
		buf := bytes.NewBuffer(data)
		switch header.Type {
		case filePath, authorityIssuer, authorityPublisher, systemRoot, elamKeyname:
			var Event MicrosoftStringEvent
			var utf16data []uint16
			for i := 0; i < int(header.Size)/2; i++ {
				var tmp uint16
				if err = binary.Read(buf, binary.LittleEndian, &tmp); err != nil {
					return nil, fmt.Errorf("unable to read Windows event data: %v", err)
				}
				utf16data = append(utf16data, tmp)
			}

			Event.Message = string(utf16.Decode(utf16data))
			Event.Type = header.Type
			events = append(events, Event)
		case bootRevocationList:
			var Event MicrosoftRevocationEvent
			var digestLen uint32

			if err = binary.Read(buf, binary.LittleEndian, &Event.CreationTime); err != nil {
				return nil, fmt.Errorf("unable to read Windows revocation list event: %v", err)
			}
			if err = binary.Read(buf, binary.LittleEndian, &digestLen); err != nil {
				return nil, fmt.Errorf("unable to read Windows revocation list event: %v", err)
			}
			if err = binary.Read(buf, binary.LittleEndian, &Event.HashAlgorithm); err != nil {
				return nil, fmt.Errorf("unable to read Windows revocation list event: %v", err)
			}
			Event.Digest = make([]byte, digestLen)
			if err = binary.Read(buf, binary.LittleEndian, &Event.Digest); err != nil {
				return nil, fmt.Errorf("unable to read Windows revocation list event: %v", err)
			}

			Event.Type = header.Type
			events = append(events, Event)
		default:
			var Event MicrosoftDataEvent
			Event.Type = header.Type
			Event.Data = data
			events = append(events, Event)
		}
	}
	return events, nil
}
