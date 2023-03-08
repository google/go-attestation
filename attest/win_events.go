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
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"

	"github.com/google/go-attestation/attest/internal"
)

type windowsEvent uint32

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

type WinCSPAlg uint32

// Valid CSP Algorithm IDs.
const (
	WinAlgMD4    WinCSPAlg = 0x02
	WinAlgMD5    WinCSPAlg = 0x03
	WinAlgSHA1   WinCSPAlg = 0x04
	WinAlgSHA256 WinCSPAlg = 0x0c
	WinAlgSHA384 WinCSPAlg = 0x0d
	WinAlgSHA512 WinCSPAlg = 0x0e
)

// BitlockerStatus describes the status of BitLocker on a Windows system.
type BitlockerStatus uint8

// Valid BitlockerStatus values.
const (
	BitlockerStatusCached   = 0x01
	BitlockerStatusMedia    = 0x02
	BitlockerStatusTPM      = 0x04
	BitlockerStatusPin      = 0x10
	BitlockerStatusExternal = 0x20
	BitlockerStatusRecovery = 0x40
)

// Ternary describes a boolean value that can additionally be unknown.
type Ternary uint8

// Valid Ternary values.
const (
	TernaryUnknown Ternary = iota
	TernaryTrue
	TernaryFalse
)

// WinEvents describes information from the event log recorded during
// bootup of Microsoft Windows.
type WinEvents struct {
	// ColdBoot is set to true if the system was not resuming from hibernation.
	ColdBoot bool
	// BootCount contains the value of the monotonic boot counter. This
	// value is not set for TPM 1.2 devices and some TPMs with buggy
	// implementations of monotonic counters.
	BootCount uint64
	// LoadedModules contains authenticode hashes for binaries which
	// were loaded during boot.
	LoadedModules map[string]WinModuleLoad
	// ELAM describes the configuration of each Early Launch AntiMalware driver,
	// for each AV Vendor key.
	ELAM map[string]WinELAM
	// BootDebuggingEnabled is true if boot debugging was ever reported
	// as enabled.
	BootDebuggingEnabled bool
	// KernelDebugEnabled is true if kernel debugging was recorded as
	// enabled at any point during boot.
	KernelDebugEnabled bool
	// DEPEnabled is true if NX (Data Execution Prevention) was consistently
	// reported as enabled.
	DEPEnabled Ternary
	// CodeIntegrityEnabled is true if code integrity was consistently
	// reported as enabled.
	CodeIntegrityEnabled Ternary
	// TestSigningEnabled is true if test-mode signature verification was
	// ever reported as enabled.
	TestSigningEnabled bool
	// BitlockerUnlocks reports the bitlocker status for every instance of
	// a disk unlock, where bitlocker was used to secure the disk.
	BitlockerUnlocks []BitlockerStatus
}

// WinModuleLoad describes a module which was loaded while
// Windows booted.
type WinModuleLoad struct {
	// FilePath represents the path from which the module was loaded. This
	// information is not always present.
	FilePath string
	// AuthenticodeHash contains the authenticode hash of the binary
	// blob which was loaded.
	AuthenticodeHash []byte
	// ImageBase describes all the addresses to which the the blob was loaded.
	ImageBase []uint64
	// ImageSize describes the size of the image in bytes. This information
	// is not always present.
	ImageSize uint64
	// HashAlgorithm describes the hash algorithm used.
	HashAlgorithm WinCSPAlg
	// ImageValidated is set if the post-boot loader validated the image.
	ImageValidated bool

	// AuthorityIssuer identifies the issuer of the certificate which certifies
	// the signature on this module.
	AuthorityIssuer string
	// AuthorityPublisher identifies the publisher of the certificate which
	// certifies the signature on this module.
	AuthorityPublisher string
	// AuthoritySerial contains the serial of the certificate certifying this
	// module.
	AuthoritySerial []byte
	// AuthoritySHA1 is the SHA1 hash of the certificate thumbprint.
	AuthoritySHA1 []byte
}

// WinELAM describes the configuration of an Early Launch AntiMalware driver.
// These values represent the 3 measured registry values stored in the ELAM
// hive for the driver.
type WinELAM struct {
	Measured []byte
	Config   []byte
	Policy   []byte
}

// ParseWinEvents parses a series of events to extract information about
// the bringup of Microsoft Windows. This information is not trustworthy
// unless the integrity of platform & bootloader events has already been
// established.
func ParseWinEvents(events []Event) (*WinEvents, error) {
	var (
		out = WinEvents{
			LoadedModules: map[string]WinModuleLoad{},
			ELAM:          map[string]WinELAM{},
		}
		seenSeparator struct {
			PCR12 bool
			PCR13 bool
		}
	)

	for _, e := range events {
		if e.Index != 12 && e.Index != 13 {
			continue
		}

		et, err := internal.UntrustedParseEventType(uint32(e.Type))
		if err != nil {
			return nil, fmt.Errorf("unrecognised event type: %v", err)
		}

		digestVerify := e.digestEquals(e.Data)

		switch e.Index {
		case 12: // 'early boot' events
			switch et {
			case internal.EventTag:
				if seenSeparator.PCR12 {
					continue
				}
				s, err := internal.ParseTaggedEventData(e.Data)
				if err != nil {
					return nil, fmt.Errorf("invalid tagged event structure at event %d: %w", e.sequence, err)
				}
				if digestVerify != nil {
					return nil, fmt.Errorf("invalid digest for tagged event %d: %w", e.sequence, digestVerify)
				}
				if err := out.readWinEventBlock(s, e.Index); err != nil {
					return nil, fmt.Errorf("invalid SIPA events in event %d: %w", e.sequence, err)
				}
			case internal.Separator:
				if seenSeparator.PCR12 {
					return nil, fmt.Errorf("duplicate WBCL separator at event %d", e.sequence)
				}
				seenSeparator.PCR12 = true
				if !bytes.Equal(e.Data, []byte("WBCL")) {
					return nil, fmt.Errorf("invalid WBCL separator data at event %d: %v", e.sequence, e.Data)
				}
				if digestVerify != nil {
					return nil, fmt.Errorf("invalid separator digest at event %d: %v", e.sequence, digestVerify)
				}

			default:
				return nil, fmt.Errorf("unexpected (PCR12) event type: %v", et)
			}
		case 13: // Post 'early boot' events
			switch et {
			case internal.EventTag:
				if seenSeparator.PCR13 {
					continue
				}
				s, err := internal.ParseTaggedEventData(e.Data)
				if err != nil {
					return nil, fmt.Errorf("invalid tagged event structure at event %d: %w", e.sequence, err)
				}
				if digestVerify != nil {
					return nil, fmt.Errorf("invalid digest for tagged event %d: %w", e.sequence, digestVerify)
				}
				if err := out.readWinEventBlock(s, e.Index); err != nil {
					return nil, fmt.Errorf("invalid SIPA events in event %d: %w", e.sequence, err)
				}
			case internal.Separator:
				if seenSeparator.PCR13 {
					return nil, fmt.Errorf("duplicate WBCL separator at event %d", e.sequence)
				}
				seenSeparator.PCR13 = true
				if !bytes.Equal(e.Data, []byte("WBCL")) {
					return nil, fmt.Errorf("invalid WBCL separator data at event %d: %v", e.sequence, e.Data)
				}
				if digestVerify != nil {
					return nil, fmt.Errorf("invalid separator digest at event %d: %v", e.sequence, digestVerify)
				}

			default:
				return nil, fmt.Errorf("unexpected (PCR13) event type: %v", et)
			}
		}
	}
	return &out, nil
}

type microsoftEventHeader struct {
	Type windowsEvent
	Size uint32
}

// unknownSIPAEvent is returned by parseSIPAEvent if the event type is
// not handled. Unlike other events in the TCG log, it is safe to skip
// unhandled SIPA events, as they are embedded within EventTag structures,
// and these structures should match the event digest.
var unknownSIPAEvent = errors.New("unknown event")

func (w *WinEvents) readBooleanInt64Event(header microsoftEventHeader, r *bytes.Reader) error {
	if header.Size != 8 {
		return fmt.Errorf("payload was %d bytes, want 8", header.Size)
	}
	var num uint64
	if err := binary.Read(r, binary.LittleEndian, &num); err != nil {
		return fmt.Errorf("reading u64: %w", err)
	}
	isSet := num != 0

	switch header.Type {
	// Boolean signals that latch off if the are ever false (ie: attributes
	// that represent a stronger security state when set).
	case dataExecutionPrevention:
		if isSet && w.DEPEnabled == TernaryUnknown {
			w.DEPEnabled = TernaryTrue
		} else if !isSet {
			w.DEPEnabled = TernaryFalse
		}
	}
	return nil
}

func (w *WinEvents) readBooleanByteEvent(header microsoftEventHeader, r *bytes.Reader) error {
	if header.Size != 1 {
		return fmt.Errorf("payload was %d bytes, want 1", header.Size)
	}
	var b byte
	if err := binary.Read(r, binary.LittleEndian, &b); err != nil {
		return fmt.Errorf("reading byte: %w", err)
	}
	isSet := b != 0

	switch header.Type {
	// Boolean signals that latch on if they are ever true (ie: attributes
	// that represent a weaker security state when set).
	case osKernelDebug:
		w.KernelDebugEnabled = w.KernelDebugEnabled || isSet
	case bootDebugging:
		w.BootDebuggingEnabled = w.BootDebuggingEnabled || isSet
	case testSigning:
		w.TestSigningEnabled = w.TestSigningEnabled || isSet

	// Boolean signals that latch off if the are ever false (ie: attributes
	// that represent a stronger security state when set).
	case codeIntegrity:
		if isSet && w.CodeIntegrityEnabled == TernaryUnknown {
			w.CodeIntegrityEnabled = TernaryTrue
		} else if !isSet {
			w.CodeIntegrityEnabled = TernaryFalse
		}
	}
	return nil
}

func (w *WinEvents) readUint32(header microsoftEventHeader, r io.Reader) (uint32, error) {
	if header.Size != 4 {
		return 0, fmt.Errorf("integer size not uint32 (%d bytes)", header.Size)
	}

	data := make([]uint8, header.Size)
	if err := binary.Read(r, binary.LittleEndian, &data); err != nil {
		return 0, fmt.Errorf("reading u32: %w", err)
	}
	i := binary.LittleEndian.Uint32(data)

	return i, nil
}

func (w *WinEvents) readUint64(header microsoftEventHeader, r io.Reader) (uint64, error) {
	if header.Size != 8 {
		return 0, fmt.Errorf("integer size not uint64 (%d bytes)", header.Size)
	}

	data := make([]uint8, header.Size)
	if err := binary.Read(r, binary.LittleEndian, &data); err != nil {
		return 0, fmt.Errorf("reading u64: %w", err)
	}
	i := binary.LittleEndian.Uint64(data)

	return i, nil
}

func (w *WinEvents) readBootCounter(header microsoftEventHeader, r *bytes.Reader) error {
	i, err := w.readUint64(header, r)
	if err != nil {
		return fmt.Errorf("boot counter: %v", err)
	}

	if w.BootCount > 0 && w.BootCount != i {
		return fmt.Errorf("conflicting values for boot counter: %d != %d", i, w.BootCount)
	}
	w.BootCount = i
	return nil
}

func (w *WinEvents) readTransferControl(header microsoftEventHeader, r *bytes.Reader) error {
	i, err := w.readUint32(header, r)
	if err != nil {
		return fmt.Errorf("transfer control: %v", err)
	}

	// A transferControl event with a value of 1 indicates that bootmngr
	// launched WinLoad. A different (unknown) value is set if WinResume
	// is launched.
	w.ColdBoot = i == 0x1
	return nil
}

func (w *WinEvents) readBitlockerUnlock(header microsoftEventHeader, r *bytes.Reader, pcr int) error {
	if header.Size > 8 {
		return fmt.Errorf("bitlocker data too large (%d bytes)", header.Size)
	}
	data := make([]uint8, header.Size)
	if err := binary.Read(r, binary.LittleEndian, &data); err != nil {
		return fmt.Errorf("reading u%d: %w", header.Size<<8, err)
	}
	i, n := binary.Uvarint(data)
	if n <= 0 {
		return fmt.Errorf("reading u%d: invalid varint", header.Size<<8)
	}

	if pcr == 13 {
		// The bitlocker status is duplicated across both PCRs. As such,
		// we prefer the earlier one, and bail here to prevent duplicate
		// records.
		return nil
	}

	w.BitlockerUnlocks = append(w.BitlockerUnlocks, BitlockerStatus(i))
	return nil
}

func (w *WinEvents) parseImageValidated(header microsoftEventHeader, r io.Reader) (bool, error) {
	if header.Size != 1 {
		return false, fmt.Errorf("payload was %d bytes, want 1", header.Size)
	}
	var num byte
	if err := binary.Read(r, binary.LittleEndian, &num); err != nil {
		return false, fmt.Errorf("reading u8: %w", err)
	}
	return num == 1, nil
}

func (w *WinEvents) parseHashAlgID(header microsoftEventHeader, r io.Reader) (WinCSPAlg, error) {
	i, err := w.readUint32(header, r)
	if err != nil {
		return 0, fmt.Errorf("hash algorithm ID: %v", err)
	}

	switch alg := WinCSPAlg(i & 0xff); alg {
	case WinAlgMD4, WinAlgMD5, WinAlgSHA1, WinAlgSHA256, WinAlgSHA384, WinAlgSHA512:
		return alg, nil
	default:
		return 0, fmt.Errorf("unknown algorithm ID: %x", i)
	}
}

func (w *WinEvents) parseAuthoritySerial(header microsoftEventHeader, r io.Reader) ([]byte, error) {
	if header.Size > 128 {
		return nil, fmt.Errorf("authority serial is too long (%d bytes)", header.Size)
	}
	data := make([]byte, header.Size)
	if err := binary.Read(r, binary.LittleEndian, &data); err != nil {
		return nil, fmt.Errorf("reading bytes: %w", err)
	}
	return data, nil
}

func (w *WinEvents) parseAuthoritySHA1(header microsoftEventHeader, r io.Reader) ([]byte, error) {
	if header.Size > 20 {
		return nil, fmt.Errorf("authority thumbprint is too long (%d bytes)", header.Size)
	}
	data := make([]byte, header.Size)
	if err := binary.Read(r, binary.LittleEndian, &data); err != nil {
		return nil, fmt.Errorf("reading bytes: %w", err)
	}
	return data, nil
}

func (w *WinEvents) parseImageBase(header microsoftEventHeader, r io.Reader) (uint64, error) {
	if header.Size != 8 {
		return 0, fmt.Errorf("payload was %d bytes, want 8", header.Size)
	}
	var num uint64
	if err := binary.Read(r, binary.LittleEndian, &num); err != nil {
		return 0, fmt.Errorf("reading u64: %w", err)
	}
	return num, nil
}

func (w *WinEvents) parseAuthenticodeHash(header microsoftEventHeader, r io.Reader) ([]byte, error) {
	if header.Size > 32 {
		return nil, fmt.Errorf("authenticode hash data exceeds the size of any valid hash (%d bytes)", header.Size)
	}
	data := make([]byte, header.Size)
	if err := binary.Read(r, binary.LittleEndian, &data); err != nil {
		return nil, fmt.Errorf("reading bytes: %w", err)
	}
	return data, nil
}

func (w *WinEvents) readLoadedModuleAggregation(rdr *bytes.Reader, header microsoftEventHeader) error {
	var (
		r                   = &io.LimitedReader{R: rdr, N: int64(header.Size)}
		codeHash            []byte
		imgBase, imgSize    uint64
		fPath               string
		algID               WinCSPAlg
		imgValidated        bool
		aIssuer, aPublisher string
		aSerial, aSHA1      []byte
	)

	for r.N > 0 {
		var h microsoftEventHeader
		if err := binary.Read(r, binary.LittleEndian, &h); err != nil {
			return fmt.Errorf("parsing LMA sub-event: %v", err)
		}
		if int64(h.Size) > r.N {
			return fmt.Errorf("LMA sub-event is larger than available data: %d > %d", h.Size, r.N)
		}

		var err error
		switch h.Type {
		case imageBase:
			if imgBase != 0 {
				return errors.New("duplicate image base data in LMA event")
			}
			if imgBase, err = w.parseImageBase(h, r); err != nil {
				return err
			}
		case authenticodeHash:
			if codeHash != nil {
				return errors.New("duplicate authenticode hash structure in LMA event")
			}
			if codeHash, err = w.parseAuthenticodeHash(h, r); err != nil {
				return err
			}
		case filePath:
			if fPath != "" {
				return errors.New("duplicate file path in LMA event")
			}
			if fPath, err = w.parseUTF16(h, r); err != nil {
				return err
			}
		case imageSize:
			if imgSize != 0 {
				return errors.New("duplicate image size in LMA event")
			}
			if imgSize, err = w.readUint64(h, r); err != nil {
				return err
			}
		case hashAlgorithmID:
			if algID != 0 {
				return errors.New("duplicate hash algorithm ID in LMA event")
			}
			if algID, err = w.parseHashAlgID(h, r); err != nil {
				return err
			}
		case imageValidated:
			if imgValidated {
				return errors.New("duplicate image validated field in LMA event")
			}
			if imgValidated, err = w.parseImageValidated(h, r); err != nil {
				return err
			}
		case authorityIssuer:
			if aIssuer != "" {
				return errors.New("duplicate authority issuer in LMA event")
			}
			if aIssuer, err = w.parseUTF16(h, r); err != nil {
				return err
			}
		case authorityPublisher:
			if aPublisher != "" {
				return errors.New("duplicate authority publisher in LMA event")
			}
			if aPublisher, err = w.parseUTF16(h, r); err != nil {
				return err
			}
		case authoritySerial:
			if aSerial != nil {
				return errors.New("duplicate authority serial in LMA event")
			}
			if aSerial, err = w.parseAuthoritySerial(h, r); err != nil {
				return err
			}
		case authoritySHA1Thumbprint:
			if aSHA1 != nil {
				return errors.New("duplicate authority SHA1 thumbprint in LMA event")
			}
			if aSHA1, err = w.parseAuthoritySHA1(h, r); err != nil {
				return err
			}
		case moduleSVN:
			// Ignore - consume value.
			b := make([]byte, h.Size)
			if err := binary.Read(r, binary.LittleEndian, &b); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown event in LMA aggregation: %v", h.Type)
		}
	}

	var iBase []uint64
	if imgBase != 0 {
		iBase = []uint64{imgBase}
	}

	l := WinModuleLoad{
		FilePath:           fPath,
		AuthenticodeHash:   codeHash,
		ImageBase:          iBase,
		ImageSize:          imgSize,
		ImageValidated:     imgValidated,
		HashAlgorithm:      algID,
		AuthorityIssuer:    aIssuer,
		AuthorityPublisher: aPublisher,
		AuthoritySerial:    aSerial,
		AuthoritySHA1:      aSHA1,
	}
	hashHex := hex.EncodeToString(l.AuthenticodeHash)
	l.ImageBase = append(l.ImageBase, w.LoadedModules[hashHex].ImageBase...)
	w.LoadedModules[hashHex] = l
	return nil
}

// parseUTF16 decodes data representing a UTF16 string. It is assumed the
// caller has validated that the data size is within allowable bounds.
func (w *WinEvents) parseUTF16(header microsoftEventHeader, r io.Reader) (string, error) {
	data := make([]uint16, header.Size/2)
	if err := binary.Read(r, binary.LittleEndian, &data); err != nil {
		return "", err
	}
	return strings.TrimSuffix(string(utf16.Decode(data)), "\x00"), nil
}

func (w *WinEvents) readELAMAggregation(rdr io.Reader, header microsoftEventHeader) error {
	var (
		r          = &io.LimitedReader{R: rdr, N: int64(header.Size)}
		driverName string
		measured   []byte
		policy     []byte
		config     []byte
	)

	for r.N > 0 {
		var h microsoftEventHeader
		if err := binary.Read(r, binary.LittleEndian, &h); err != nil {
			return fmt.Errorf("parsing ELAM aggregation sub-event: %v", err)
		}
		if int64(h.Size) > r.N {
			return fmt.Errorf("ELAM aggregation sub-event is larger than available data: %d > %d", h.Size, r.N)
		}

		var err error
		switch h.Type {
		case elamAggregation:
			w.readELAMAggregation(r, h)
			if r.N == 0 {
				return nil
			}
		case elamKeyname:
			if driverName != "" {
				return errors.New("duplicate driver name in ELAM aggregation event")
			}
			if driverName, err = w.parseUTF16(h, r); err != nil {
				return fmt.Errorf("parsing ELAM driver name: %v", err)
			}
		case elamMeasured:
			if measured != nil {
				return errors.New("duplicate measured data in ELAM aggregation event")
			}
			measured = make([]byte, h.Size)
			if err := binary.Read(r, binary.LittleEndian, &measured); err != nil {
				return fmt.Errorf("reading ELAM measured value: %v", err)
			}
		case elamPolicy:
			if policy != nil {
				return errors.New("duplicate policy data in ELAM aggregation event")
			}
			policy = make([]byte, h.Size)
			if err := binary.Read(r, binary.LittleEndian, &policy); err != nil {
				return fmt.Errorf("reading ELAM policy value: %v", err)
			}
		case elamConfiguration:
			if config != nil {
				return errors.New("duplicate config data in ELAM aggregation event")
			}
			config = make([]byte, h.Size)
			if err := binary.Read(r, binary.LittleEndian, &config); err != nil {
				return fmt.Errorf("reading ELAM config value: %v", err)
			}
		default:
			return fmt.Errorf("unknown event in LMA aggregation: %v", h.Type)
		}
	}

	if driverName == "" {
		return errors.New("ELAM driver name not specified")
	}
	w.ELAM[driverName] = WinELAM{
		Measured: measured,
		Config:   config,
		Policy:   policy,
	}
	return nil
}

func (w *WinEvents) readSIPAEvent(r *bytes.Reader, pcr int) error {
	var header microsoftEventHeader
	if err := binary.Read(r, binary.LittleEndian, &header); err != nil {
		return err
	}

	switch header.Type {
	case elamAggregation:
		return w.readELAMAggregation(r, header)
	case loadedModuleAggregation:
		return w.readLoadedModuleAggregation(r, header)
	case bootCounter:
		return w.readBootCounter(header, r)
	case bitlockerUnlock:
		return w.readBitlockerUnlock(header, r, pcr)
	case transferControl:
		return w.readTransferControl(header, r)

	case osKernelDebug, codeIntegrity, bootDebugging, testSigning: // Parse boolean values.
		return w.readBooleanByteEvent(header, r)
	case dataExecutionPrevention: // Parse booleans represented as uint64's.
		return w.readBooleanInt64Event(header, r)

	default:
		// Event type was not handled, consume the data.
		if int(header.Size) > r.Len() {
			return fmt.Errorf("event data len (%d bytes) larger than event length (%d bytes)", header.Size, r.Len())
		}
		tmp := make([]byte, header.Size)
		if err := binary.Read(r, binary.LittleEndian, &tmp); err != nil {
			return fmt.Errorf("reading unknown data section of length %d: %w", header.Size, err)
		}

		return unknownSIPAEvent
	}
}

// readWinEventBlock extracts boot configuration from SIPA events contained in
// the given tagged event.
func (w *WinEvents) readWinEventBlock(evt *internal.TaggedEventData, pcr int) error {
	r := bytes.NewReader(evt.Data)

	// All windows information should be sub events in an enclosing SIPA
	// container event.
	if (windowsEvent(evt.ID) & sipaTypeMask) != sipaContainer {
		return fmt.Errorf("expected container event, got %v", windowsEvent(evt.ID))
	}

	for r.Len() > 0 {
		if err := w.readSIPAEvent(r, pcr); err != nil {
			if errors.Is(err, unknownSIPAEvent) {
				// Unknown SIPA events are okay as all TCG events are verifiable.
				continue
			}
			return err
		}
	}
	return nil
}
