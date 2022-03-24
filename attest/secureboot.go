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
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/google/go-attestation/attest/internal"
)

// SecurebootState describes the secure boot status of a machine, as determined
// by processing its event log.
type SecurebootState struct {
	Enabled bool

	// PlatformKeys enumerates keys which can sign a key exchange key.
	PlatformKeys []x509.Certificate
	// PlatformKeys enumerates key hashes which can sign a key exchange key.
	PlatformKeyHashes [][]byte

	// ExchangeKeys enumerates keys which can sign a database of permitted or
	// forbidden keys.
	ExchangeKeys []x509.Certificate
	// ExchangeKeyHashes enumerates key hashes which can sign a database or
	// permitted or forbidden keys.
	ExchangeKeyHashes [][]byte

	// PermittedKeys enumerates keys which may sign binaries to run.
	PermittedKeys []x509.Certificate
	// PermittedHashes enumerates hashes which permit binaries to run.
	PermittedHashes [][]byte

	// ForbiddenKeys enumerates keys which must not permit a binary to run.
	ForbiddenKeys []x509.Certificate
	// ForbiddenKeys enumerates hashes which must not permit a binary to run.
	ForbiddenHashes [][]byte

	// PreSeparatorAuthority describes the use of a secure-boot key to authorize
	// the execution of a binary before the separator.
	PreSeparatorAuthority []x509.Certificate
	// PostSeparatorAuthority describes the use of a secure-boot key to authorize
	// the execution of a binary after the separator.
	PostSeparatorAuthority []x509.Certificate

	// DriverLoadSourceHints describes the origin of boot services drivers.
	// This data is not tamper-proof and must only be used as a hint.
	DriverLoadSourceHints []DriverLoadSource

	// DMAProtectionDisabled is true if the platform reports during boot that
	// DMA protection is supported but disabled.
	//
	// See: https://docs.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-kernel-dma-protection
	DMAProtectionDisabled bool
}

// DriverLoadSource describes the logical origin of a boot services driver.
type DriverLoadSource uint8

const (
	UnknownSource DriverLoadSource = iota
	PciMmioSource
)

// ParseSecurebootState parses a series of events to determine the
// configuration of secure boot on a device. An error is returned if
// the state cannot be determined, or if the event log is structured
// in such a way that it may have been tampered post-execution of
// platform firmware.
func ParseSecurebootState(events []Event) (*SecurebootState, error) {
	// This algorithm verifies the following:
	// - All events in PCR 7 have event types which are expected in PCR 7.
	// - All events are parsable according to their event type.
	// - All events have digests values corresponding to their data/event type.
	// - No unverifiable events were present.
	// - All variables are specified before the separator and never duplicated.
	// - The SecureBoot variable has a value of 0 or 1.
	// - If SecureBoot was 1 (enabled), authority events were present indicating
	//   keys were used to perform verification.
	// - If SecureBoot was 1 (enabled), platform + exchange + database keys
	//   were specified.
	// - No UEFI debugger was attached.

	var (
		out            SecurebootState
		seenSeparator7 bool
		seenSeparator2 bool
		seenAuthority  bool
		seenVars       = map[string]bool{}
		driverSources  [][]internal.EFIDevicePathElement
	)

	for _, e := range events {
		if e.Index != 7 && e.Index != 2 {
			continue
		}

		et, err := internal.UntrustedParseEventType(uint32(e.Type))
		if err != nil {
			return nil, fmt.Errorf("unrecognised event type: %v", err)
		}
		digestVerify := e.digestEquals(e.Data)

		switch e.Index {
		case 7:
			switch et {
			case internal.Separator:
				if seenSeparator7 {
					return nil, fmt.Errorf("duplicate separator at event %d", e.sequence)
				}
				seenSeparator7 = true
				if !bytes.Equal(e.Data, []byte{0, 0, 0, 0}) {
					return nil, fmt.Errorf("invalid separator data at event %d: %v", e.sequence, e.Data)
				}
				if digestVerify != nil {
					return nil, fmt.Errorf("invalid separator digest at event %d: %v", e.sequence, digestVerify)
				}

			case internal.EFIAction:
				switch string(e.Data) {
				case "UEFI Debug Mode":
					return nil, errors.New("a UEFI debugger was present during boot")
				case "DMA Protection Disabled":
					if digestVerify != nil {
						return nil, fmt.Errorf("invalid digest for EFI Action 'DMA Protection Disabled' on event %d: %v", e.sequence, digestVerify)
					}
					out.DMAProtectionDisabled = true
				default:
					return nil, fmt.Errorf("event %d: unexpected EFI action event", e.sequence)
				}

			case internal.EFIVariableDriverConfig:
				v, err := internal.ParseUEFIVariableData(bytes.NewReader(e.Data))
				if err != nil {
					return nil, fmt.Errorf("failed parsing EFI variable at event %d: %v", e.sequence, err)
				}
				if _, seenBefore := seenVars[v.VarName()]; seenBefore {
					return nil, fmt.Errorf("duplicate EFI variable %q at event %d", v.VarName(), e.sequence)
				}
				seenVars[v.VarName()] = true
				if seenSeparator7 {
					return nil, fmt.Errorf("event %d: variable %q specified after separator", e.sequence, v.VarName())
				}

				if digestVerify != nil {
					return nil, fmt.Errorf("invalid digest for variable %q on event %d: %v", v.VarName(), e.sequence, digestVerify)
				}

				switch v.VarName() {
				case "SecureBoot":
					if len(v.VariableData) != 1 {
						return nil, fmt.Errorf("event %d: SecureBoot data len is %d, expected 1", e.sequence, len(v.VariableData))
					}
					out.Enabled = v.VariableData[0] == 1
				case "PK":
					if out.PlatformKeys, out.PlatformKeyHashes, err = v.SignatureData(); err != nil {
						return nil, fmt.Errorf("event %d: failed parsing platform keys: %v", e.sequence, err)
					}
				case "KEK":
					if out.ExchangeKeys, out.ExchangeKeyHashes, err = v.SignatureData(); err != nil {
						return nil, fmt.Errorf("event %d: failed parsing key exchange keys: %v", e.sequence, err)
					}
				case "db":
					if out.PermittedKeys, out.PermittedHashes, err = v.SignatureData(); err != nil {
						return nil, fmt.Errorf("event %d: failed parsing signature database: %v", e.sequence, err)
					}
				case "dbx":
					if out.ForbiddenKeys, out.ForbiddenHashes, err = v.SignatureData(); err != nil {
						return nil, fmt.Errorf("event %d: failed parsing forbidden signature database: %v", e.sequence, err)
					}
				}

			case internal.EFIVariableAuthority:
				v, err := internal.ParseUEFIVariableData(bytes.NewReader(e.Data))
				if err != nil {
					return nil, fmt.Errorf("failed parsing UEFI variable data: %v", err)
				}

				a, err := internal.ParseUEFIVariableAuthority(v)
				if err != nil {
					// Workaround for: https://github.com/google/go-attestation/issues/157
					if err == internal.ErrSigMissingGUID {
						// Versions of shim which do not carry
						// https://github.com/rhboot/shim/commit/8a27a4809a6a2b40fb6a4049071bf96d6ad71b50
						// have an erroneous additional byte in the event, which breaks digest
						// verification. If verification failed, we try removing the last byte.
						if digestVerify != nil && len(e.Data) > 0 {
							digestVerify = e.digestEquals(e.Data[:len(e.Data)-1])
						}
					} else {
						return nil, fmt.Errorf("failed parsing EFI variable authority at event %d: %v", e.sequence, err)
					}
				}
				seenAuthority = true
				if digestVerify != nil {
					return nil, fmt.Errorf("invalid digest for authority on event %d: %v", e.sequence, digestVerify)
				}
				if !seenSeparator7 {
					out.PreSeparatorAuthority = append(out.PreSeparatorAuthority, a.Certs...)
				} else {
					out.PostSeparatorAuthority = append(out.PostSeparatorAuthority, a.Certs...)
				}

			default:
				return nil, fmt.Errorf("unexpected event type in PCR7: %v", et)
			}

		case 2:
			switch et {
			case internal.Separator:
				if seenSeparator2 {
					return nil, fmt.Errorf("duplicate separator at event %d", e.sequence)
				}
				seenSeparator2 = true
				if !bytes.Equal(e.Data, []byte{0, 0, 0, 0}) {
					return nil, fmt.Errorf("invalid separator data at event %d: %v", e.sequence, e.Data)
				}
				if digestVerify != nil {
					return nil, fmt.Errorf("invalid separator digest at event %d: %v", e.sequence, digestVerify)
				}

			case internal.EFIBootServicesDriver:
				if !seenSeparator2 {
					imgLoad, err := internal.ParseEFIImageLoad(bytes.NewReader(e.Data))
					if err != nil {
						return nil, fmt.Errorf("failed parsing EFI image load at boot services driver event %d: %v", e.sequence, err)
					}
					dp, err := imgLoad.DevicePath()
					if err != nil {
						return nil, fmt.Errorf("failed to parse device path for driver load event %d: %v", e.sequence, err)
					}
					driverSources = append(driverSources, dp)
				}
			}
		}
	}

	// Compute driver source hints based on the EFI device path observed in
	// EFI Boot-services driver-load events.
sourceLoop:
	for _, source := range driverSources {
		// We consider a driver to have originated from PCI-MMIO if any number
		// of elements in the device path [1] were PCI devices, and are followed by
		// an element representing a "relative offset range" read.
		// In the wild, we have typically observed 4-tuple device paths for such
		// devices: ACPI device -> PCI device -> PCI device -> relative offset.
		//
		// [1]: See section 9 of the UEFI specification v2.6 or greater.
		var seenPCI bool
		for _, e := range source {
			// subtype 0x1 corresponds to a PCI device (See: 9.3.2.1)
			if e.Type == internal.HardwareDevice && e.Subtype == 0x1 {
				seenPCI = true
			}
			// subtype 0x8 corresponds to "relative offset range" (See: 9.3.6.8)
			if seenPCI && e.Type == internal.MediaDevice && e.Subtype == 0x8 {
				out.DriverLoadSourceHints = append(out.DriverLoadSourceHints, PciMmioSource)
				continue sourceLoop
			}
		}
		out.DriverLoadSourceHints = append(out.DriverLoadSourceHints, UnknownSource)
	}

	if !out.Enabled {
		return &out, nil
	}

	if !seenAuthority {
		return nil, errors.New("secure boot was enabled but no key was used")
	}
	if len(out.PlatformKeys) == 0 && len(out.PlatformKeyHashes) == 0 {
		return nil, errors.New("secure boot was enabled but no platform keys were known")
	}
	if len(out.ExchangeKeys) == 0 && len(out.ExchangeKeyHashes) == 0 {
		return nil, errors.New("secure boot was enabled but no key exchange keys were known")
	}
	if len(out.PermittedKeys) == 0 && len(out.PermittedHashes) == 0 {
		return nil, errors.New("secure boot was enabled but no keys or hashes were permitted")
	}
	return &out, nil
}
