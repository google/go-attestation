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

// BitlockerStatus describes the status of BitLocker on a Windows system.
type BitlockerStatus uint8

// Valid BitlockerStatus values.
const (
	BitlockerStatusCached   = 0x01
	bBitlockerStatusMedia   = 0x02
	BitlockerStatusTPM      = 0x04
	BitlockerStatusPin      = 0x10
	BitlockerStatusExternal = 0x20
	BitlockerStatusRecovery = 0x40
)

// WinEvents describes information from the event log recorded during
// bootup of Microsoft Windows.
type WinEvents struct {
	// BootCount contains the value of the monotonic boot counter. This
	// value is not set for TPM 1.2 devices and some TPMs with buggy
	// implementations of monotonic counters.
	BootCount int
	// LoadedModules contains authenticode hashes for binaries which
	// were loaded during boot.
	LoadedModules map[string]WinModuleLoad
	// BootDebuggingEnabled is true if boot debugging was ever reported
	// as enabled.
	BootDebuggingEnabled bool
	// KernelDebugEnabled is true if kernel debugging was recorded as
	// enabled at any point during boot.
	KernelDebugEnabled bool
	// DEPEnabled is true if NX (Data Execution Prevention) was consistently
	// reported as enabled.
	DEPEnabled bool
	// CodeIntegrityEnabled is true if code integrity was consistently
	// reported as enabled.
	CodeIntegrityEnabled bool
	// TestSigningEnabled is true if test-mode signature verification was
	// ever reported as enabled.
	TestSigningEnabled bool
	// BitlockerStatus reports the status of bitlocker.
	BitlockerStatus BitlockerStatus

	seenDep           bool
	seenCodeIntegrity bool
	seenBitlocker     bool
}

// WinModuleLoad describes a module which was loaded while
// Windows booted.
type WinModuleLoad struct {
	// AuthenticodeHash contains the authenticode hash of the binary
	// blob which was loaded.
	AuthenticodeHash []byte
	// ImageBase describes all the addresses to which the the blob was loaded.
	ImageBase []uint64
}

// ParseWinEvents parses a series of events to extract information about
// the bringup of Microsoft Windows. This information is not trustworthy
// unless the integrity of platform & bootloader events has already been
// established.
func ParseWinEvents(events []Event) (*WinEvents, error) {
	var (
		out           = WinEvents{LoadedModules: map[string]WinModuleLoad{}}
		seenSeparator bool
	)

	for _, e := range events {
		if e.Index != 12 {
			continue
		}

		et, err := internal.UntrustedParseEventType(uint32(e.Type))
		if err != nil {
			return nil, fmt.Errorf("unrecognised event type: %v", err)
		}

		digestVerify := e.digestEquals(e.Data)
		switch et {
		case internal.EventTag:
			s, err := internal.ParseTaggedEventData(e.Data)
			if err != nil {
				return nil, fmt.Errorf("invalid tagged event structure at event %d: %w", e.sequence, err)
			}
			if digestVerify != nil {
				return nil, fmt.Errorf("invalid digest for tagged event %d: %w", e.sequence, err)
			}
			if err := out.readWinEventBlock(s); err != nil {
				return nil, fmt.Errorf("invalid SIPA events in event %d: %w", e.sequence, err)
			}
		case internal.Separator:
			if seenSeparator {
				return nil, fmt.Errorf("duplicate WBCL separator at event %d", e.sequence)
			}
			seenSeparator = true
			if !bytes.Equal(e.Data, []byte("WBCL")) {
				return nil, fmt.Errorf("invalid WBCL separator data at event %d: %v", e.sequence, e.Data)
			}
			if digestVerify != nil {
				return nil, fmt.Errorf("invalid separator digest at event %d: %v", e.sequence, digestVerify)
			}

		default:
			return nil, fmt.Errorf("unexpected event type: %v", et)
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
		w.DEPEnabled = isSet && !(w.DEPEnabled != isSet && w.seenDep)
		w.seenDep = true
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
		w.CodeIntegrityEnabled = isSet && !(w.CodeIntegrityEnabled != isSet && w.seenCodeIntegrity)
		w.seenCodeIntegrity = true
	}
	return nil
}

func (w *WinEvents) readBootCounter(header microsoftEventHeader, r *bytes.Reader) error {
	if header.Size > 8 {
		return fmt.Errorf("boot counter data too large (%d bytes)", header.Size)
	}
	data := make([]uint8, header.Size)
	if err := binary.Read(r, binary.LittleEndian, &data); err != nil {
		return fmt.Errorf("reading u%d: %w", header.Size<<8, err)
	}
	i, n := binary.Uvarint(data)
	if n <= 0 {
		return fmt.Errorf("reading u%d: invalid varint", header.Size<<8)
	}

	if w.BootCount > 0 && w.BootCount != int(i) {
		return fmt.Errorf("conflicting values for boot counter: %d != %d", i, w.BootCount)
	}
	w.BootCount = int(i)
	return nil
}

func (w *WinEvents) readBitlockerUnlock(header microsoftEventHeader, r *bytes.Reader) error {
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

	s := BitlockerStatus(i)
	if w.seenBitlocker && w.BitlockerStatus != s {
		return fmt.Errorf("conflicting values for bitlocker status: %v != %v", s, w.BitlockerStatus)
	}
	w.BitlockerStatus = s
	w.seenBitlocker = true
	return nil
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
		r        = io.LimitReader(rdr, int64(header.Size))
		codeHash []byte
		imgBase  uint64
	)

eventLoop:
	for {
		var header microsoftEventHeader
		if err := binary.Read(r, binary.LittleEndian, &header); err != nil {
			if errors.Is(err, io.EOF) {
				break eventLoop
			}
			return fmt.Errorf("parsing LMA sub-event: %v", err)
		}

		var err error
		switch header.Type {
		case imageBase:
			if imgBase != 0 {
				return errors.New("duplicate image base data in LMA event")
			}
			if imgBase, err = w.parseImageBase(header, r); err != nil {
				return err
			}
		case authenticodeHash:
			if codeHash != nil {
				return errors.New("duplicate authenticode hash structure in LMA event")
			}
			if codeHash, err = w.parseAuthenticodeHash(header, r); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown event in LMA aggregation: %v", header.Type)
		}
	}

	l := WinModuleLoad{
		AuthenticodeHash: codeHash,
		ImageBase:        []uint64{imgBase},
	}
	hashHex := hex.EncodeToString(l.AuthenticodeHash)
	l.ImageBase = append(l.ImageBase, w.LoadedModules[hashHex].ImageBase...)
	w.LoadedModules[hashHex] = l
	return nil
}

func (w *WinEvents) readSIPAEvent(r *bytes.Reader) error {
	var header microsoftEventHeader
	if err := binary.Read(r, binary.LittleEndian, &header); err != nil {
		return err
	}

	switch header.Type {
	case loadedModuleAggregation:
		return w.readLoadedModuleAggregation(r, header)
	case bootCounter:
		return w.readBootCounter(header, r)
	case bitlockerUnlock:
		return w.readBitlockerUnlock(header, r)

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
func (w *WinEvents) readWinEventBlock(evt *internal.TaggedEventData) error {
	r := bytes.NewReader(evt.Data)

	// All windows information should be sub events in an enclosing SIPA
	// container event.
	if (windowsEvent(evt.ID) & sipaTypeMask) != sipaContainer {
		return fmt.Errorf("expected container event, got %v", windowsEvent(evt.ID))
	}

	for r.Len() > 0 {
		if err := w.readSIPAEvent(r); err != nil {
			if errors.Is(err, unknownSIPAEvent) {
				// Unknown SIPA events are okay as all TCG events are verifiable.
				continue
			}
			return err
		}
	}
	return nil
}
