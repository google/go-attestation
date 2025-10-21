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

// Package eventlog implements experimental logic for parsing the TCG event log format.
package eventlog

import "fmt"

// eventType indicates what kind of data an event is reporting.
type eventType uint32

func isReserved(t eventType) bool {
	if 0x00000013 <= t && t <= 0x0000FFFF {
		return true
	}
	if 0x800000E1 <= t && t <= 0x8000FFFF {
		return true
	}
	return false
}

// String returns the name as defined by the TCG specification.
func (e eventType) String() string {
	if s, ok := eventTypeNames[e]; ok {
		return s
	}
	s := fmt.Sprintf("eventType(0x%08x)", int(e))
	if isReserved(e) {
		s += " (reserved)"
	}
	return s
}

const (
	// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClient_Specific_Platform_Profile_for_TPM_2p0_1p04_PUBLIC.pdf#page=103

	// Reserved for future use.
	evPrebootCert eventType = 0x00000000

	// Host platform trust chain measurements. The event data can contain one of
	// the following, indicating different points of boot: "POST CODE", "SMM CODE",
	// "ACPI DATA", "BIS CODE", "Embedded UEFI Driver".
	//
	// PCR[0] MUST be extended with this event type.
	//
	// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClient_Specific_Platform_Profile_for_TPM_2p0_1p04_PUBLIC.pdf#page=38
	evPostCode eventType = 0x00000001

	// The event type was never used and is considered reserved.
	evUnused eventType = 0x00000002

	// Used for PCRs[0,6]. This event type doesn't extend the PCR, the digest MUST
	// be all zeros, and the data holds information intended for parsers such as
	// delimiting a switch to the agile crypto event format.
	//
	// This event MUST NOT extend any PCR
	evNoAction eventType = 0x00000003

	// Delineates the point where the Platform Firmware relinquishes control of TPM
	// measurements to the operating system.
	//
	// Event data size MUST contain either 0x00000000 or 0xFFFFFFFF, the digest MUST
	// match the data.
	//
	// This event MUST extend the PCRs 0 through 7 inclusive.
	evSeparator eventType = 0x00000004

	// An event indicating a particular action in the boot sequence, for example
	// "User Password Entered" or "Booting BCV Device s".
	//
	// The digests field contains the tagged hash of the event field for each PCR bank.
	//
	// Used for PCRs [1, 2, 3, 4, 5, and 6].
	evAction eventType = 0x00000005

	// Used for PCRs defined for OS and application usage. The digest field MUST
	// contain a hash of the data. The data contains a TCG_PCClientTaggedEvent
	// structure.
	evEventTag eventType = 0x00000006

	// Used for PCR[0] only. The digest contains the hash of the SRTM for each PCR
	// bank. The data is informative and not expected to match the digest.
	evSCRTMContents eventType = 0x00000007
	evSCRTMVersion  eventType = 0x00000008

	// The digests field contains the tagged hash of the microcode patch applied for
	// each PCR bank. The data is informative and not expected to match the digest.
	evCUPMicrocode eventType = 0x00000009

	// TODO(ericchiang): explain these events
	evPlatformConfigFiles eventType = 0x0000000A
	evTableOfDevices      eventType = 0x0000000B

	// Can be used for any PCRs except 0, 1, 2, or 3.
	evCompactHash eventType = 0x0000000C

	// IPL events are deprecated
	evIPL              eventType = 0x0000000D
	evIPLPartitionData eventType = 0x0000000E

	// Used for PCR[0] only.
	//
	// TODO(ericchiang): explain these events
	evNonhostCode          eventType = 0x0000000F
	evNonhostConfig        eventType = 0x00000010
	evNonhostInfo          eventType = 0x00000011
	evOmitBootDeviceEvents eventType = 0x00000012

	// The following events are UEFI specific.

	// Data contains a UEFI_VARIABLE_DATA structure.
	evEFIVariableDriverConfig eventType = 0x80000001 // PCR[1,3,5]
	evEFIVariableBoot         eventType = 0x80000002 // PCR[1]

	// Data contains a UEFI_IMAGE_LOAD_EVENT structure.
	evEFIBootServicesApplication eventType = 0x80000003 // PCR[2,4]
	evEFIBootServicesDriver      eventType = 0x80000004 // PCR[0,2]
	evEFIRuntimeServicesDriver   eventType = 0x80000005 // PCR[2,4]

	// Data contains a UEFI_GPT_DATA structure.
	evEFIGPTEvent eventType = 0x80000006 // PCR[5]

	evEFIAction eventType = 0x80000007 // PCR[1,2,3,4,5,6,7]

	// Data contains a UEFI_PLATFORM_FIRMWARE_BLOB structure.
	evEFIPlatformFirmwareBlob eventType = 0x80000008 // PCR[0,2,4]

	// Data contains a UEFI_HANDOFF_TABLE_POINTERS structure.
	evEFIHandoffTables eventType = 0x80000009 // PCR[1]

	// The digests field contains the tagged hash of the H-CRTM event
	// data for each PCR bank.
	//
	// The Event Data MUST be the string: “HCRTM”.
	evEFIHCRTMEvent eventType = 0x80000010 // PCR[0]

	// Data contains a UEFI_VARIABLE_DATA structure.
	evEFIVariableAuthority eventType = 0x800000E0 // PCR[7]
)

var eventTypeNames = map[eventType]string{
	evPrebootCert:          "EV_PREBOOT_CERT",
	evPostCode:             "EV_POST_CODE",
	evUnused:               "EV_UNUSED",
	evNoAction:             "EV_NO_ACTION",
	evSeparator:            "EV_SEPARATOR",
	evAction:               "EV_ACTION",
	evEventTag:             "EV_EVENT_TAG",
	evSCRTMContents:        "EV_S_CRTM_CONTENTS",
	evSCRTMVersion:         "EV_S_CRTM_VERSION",
	evCUPMicrocode:         "EV_CPU_MICROCODE",
	evPlatformConfigFiles:  "EV_PLATFORM_CONFIG_FLAGS",
	evTableOfDevices:       "EV_TABLE_OF_DEVICES",
	evCompactHash:          "EV_COMPACT_HASH",
	evIPL:                  "EV_IPL (deprecated)",
	evIPLPartitionData:     "EV_IPL_PARTITION_DATA (deprecated)",
	evNonhostCode:          "EV_NONHOST_CODE",
	evNonhostConfig:        "EV_NONHOST_CONFIG",
	evNonhostInfo:          "EV_NONHOST_INFO",
	evOmitBootDeviceEvents: "EV_OMIT_BOOT_DEVICE_EVENTS",

	// UEFI events
	evEFIVariableDriverConfig:    "EV_EFI_VARIABLE_DRIVER_CONFIG",
	evEFIVariableBoot:            "EV_EFI_VARIABLE_BOOT",
	evEFIBootServicesApplication: "EV_EFI_BOOT_SERVICES_APPLICATION",
	evEFIBootServicesDriver:      "EV_EFI_BOOT_SERVICES_DRIVER",
	evEFIRuntimeServicesDriver:   "EV_EFI_RUNTIME_SERVICES_DRIVER",
	evEFIGPTEvent:                "EV_EFI_GPT_EVENT",
	evEFIAction:                  "EV_EFI_ACTION",
	evEFIPlatformFirmwareBlob:    "EV_EFI_PLATFORM_FIRMWARE_BLOB",
	evEFIHandoffTables:           "EV_EFI_HANDOFF_TABLES",
	evEFIHCRTMEvent:              "EV_EFI_HCRTM_EVENT",
	evEFIVariableAuthority:       "EV_EFI_VARIABLE_AUTHORITY",
}
