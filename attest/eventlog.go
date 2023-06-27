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

package attest

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	// Ensure hashes are available.
	_ "crypto/sha256"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// ReplayError describes the parsed events that failed to verify against
// a particular PCR.
type ReplayError struct {
	Events []Event
	// InvalidPCRs reports the set of PCRs where the event log replay failed.
	InvalidPCRs []int
}

func (e ReplayError) affected(pcr int) bool {
	for _, p := range e.InvalidPCRs {
		if p == pcr {
			return true
		}
	}
	return false
}

// Error returns a human-friendly description of replay failures.
func (e ReplayError) Error() string {
	return fmt.Sprintf("event log failed to verify: the following registers failed to replay: %v", e.InvalidPCRs)
}

// EventType indicates what kind of data an event is reporting.
//
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf#page=103
type EventType uint32

var eventTypeStrings = map[uint32]string{
	0x00000000: "EV_PREBOOT_CERT",
	0x00000001: "EV_POST_CODE",
	0x00000002: "EV_UNUSED",
	0x00000003: "EV_NO_ACTION",
	0x00000004: "EV_SEPARATOR",
	0x00000005: "EV_ACTION",
	0x00000006: "EV_EVENT_TAG",
	0x00000007: "EV_S_CRTM_CONTENTS",
	0x00000008: "EV_S_CRTM_VERSION",
	0x00000009: "EV_CPU_MICROCODE",
	0x0000000A: "EV_PLATFORM_CONFIG_FLAGS",
	0x0000000B: "EV_TABLE_OF_DEVICES",
	0x0000000C: "EV_COMPACT_HASH",
	0x0000000D: "EV_IPL",
	0x0000000E: "EV_IPL_PARTITION_DATA",
	0x0000000F: "EV_NONHOST_CODE",
	0x00000010: "EV_NONHOST_CONFIG",
	0x00000011: "EV_NONHOST_INFO",
	0x00000012: "EV_OMIT_BOOT_DEVICE_EVENTS",
	0x80000000: "EV_EFI_EVENT_BASE",
	0x80000001: "EV_EFI_VARIABLE_DRIVER_CONFIG",
	0x80000002: "EV_EFI_VARIABLE_BOOT",
	0x80000003: "EV_EFI_BOOT_SERVICES_APPLICATION",
	0x80000004: "EV_EFI_BOOT_SERVICES_DRIVER",
	0x80000005: "EV_EFI_RUNTIME_SERVICES_DRIVER",
	0x80000006: "EV_EFI_GPT_EVENT",
	0x80000007: "EV_EFI_ACTION",
	0x80000008: "EV_EFI_PLATFORM_FIRMWARE_BLOB",
	0x80000009: "EV_EFI_HANDOFF_TABLES",
	0x80000010: "EV_EFI_HCRTM_EVENT",
	0x800000E0: "EV_EFI_VARIABLE_AUTHORITY",
}

// String returns the Spec name of the EventType, for example "EV_ACTION". If
// unknown, it returns a formatted string of the EventType value.
func (e EventType) String() string {
	if s, ok := eventTypeStrings[uint32(e)]; ok {
		return s
	}
	// NOTE: 0x00000013-0x0000FFFF are reserverd. Should we include that
	// information in the formatting?
	return fmt.Sprintf("EventType(0x%08x)", uint32(e))
}

// Event is a single event from a TCG event log. This reports descrete items such
// as BIOS measurements or EFI states.
//
// There are many pitfalls for using event log events correctly to determine the
// state of a machine[1]. In general it's much safer to only rely on the raw PCR
// values and use the event log for debugging.
//
// [1] https://github.com/google/go-attestation/blob/master/docs/event-log-disclosure.md
type Event struct {
	// order of the event in the event log.
	sequence int
	// Index of the PCR that this event was replayed against.
	Index int
	// Untrusted type of the event. This value is not verified by event log replays
	// and can be tampered with. It should NOT be used without additional context,
	// and unrecognized event types should result in errors.
	Type EventType

	// Data of the event. For certain kinds of events, this must match the event
	// digest to be valid.
	Data []byte
	// Digest is the verified digest of the event data. While an event can have
	// multiple for different hash values, this is the one that was matched to the
	// PCR value.
	Digest []byte

	// TODO(ericchiang): Provide examples or links for which event types must
	// match their data to their digest.
}

func (e *Event) digestEquals(b []byte) error {
	if len(e.Digest) == 0 {
		return errors.New("no digests present")
	}

	switch len(e.Digest) {
	case crypto.SHA256.Size():
		s := sha256.Sum256(b)
		if bytes.Equal(s[:], e.Digest) {
			return nil
		}
	case crypto.SHA1.Size():
		s := sha1.Sum(b)
		if bytes.Equal(s[:], e.Digest) {
			return nil
		}
	default:
		return fmt.Errorf("cannot compare hash of length %d", len(e.Digest))
	}

	return fmt.Errorf("digest (len %d) does not match", len(e.Digest))
}

// EventLog is a parsed measurement log. This contains unverified data representing
// boot events that must be replayed against PCR values to determine authenticity.
type EventLog struct {
	// Algs holds the set of algorithms that the event log uses.
	Algs []HashAlg

	rawEvents   []rawEvent
	specIDEvent *specIDEvent
}

func (e *EventLog) clone() *EventLog {
	out := EventLog{
		Algs:      make([]HashAlg, len(e.Algs)),
		rawEvents: make([]rawEvent, len(e.rawEvents)),
	}
	copy(out.Algs, e.Algs)
	copy(out.rawEvents, e.rawEvents)
	if e.specIDEvent != nil {
		dupe := *e.specIDEvent
		out.specIDEvent = &dupe
	}

	return &out
}

// Events returns events that have not been replayed against the PCR values and
// are therefore unverified. The returned events contain the digest that matches
// the provided hash algorithm, or are empty if that event didn't contain a
// digest for that hash.
//
// This method is insecure and should only be used for debugging.
func (e *EventLog) Events(hash HashAlg) []Event {
	var events []Event
	for _, re := range e.rawEvents {
		ev := Event{
			Index: re.index,
			Type:  re.typ,
			Data:  re.data,
		}

		for _, digest := range re.digests {
			if hash.cryptoHash() != digest.hash {
				continue
			}
			ev.Digest = digest.data
			break
		}
		events = append(events, ev)
	}
	return events
}

// Verify replays the event log against a TPM's PCR values, returning the
// events which could be matched to a provided PCR value.
//
// PCRs provide no security guarantees unless they're attested to have been
// generated by a TPM. Verify does not perform these checks.
//
// An error is returned if the replayed digest for events with a given PCR
// index do not match any provided value for that PCR index.
func (e *EventLog) Verify(pcrs []PCR) ([]Event, error) {
	events, err := e.verify(pcrs)
	// If there were any issues replaying the PCRs, try each of the workarounds
	// in turn.
	// TODO(jsonp): Allow workarounds to be combined.
	if rErr, isReplayErr := err.(ReplayError); isReplayErr {
		for _, wkrd := range eventlogWorkarounds {
			if !rErr.affected(wkrd.affectedPCR) {
				continue
			}
			el := e.clone()
			if err := wkrd.apply(el); err != nil {
				return nil, fmt.Errorf("failed applying workaround %q: %v", wkrd.id, err)
			}
			if events, err := el.verify(pcrs); err == nil {
				return events, nil
			}
		}
	}

	return events, err
}

func (e *EventLog) verify(pcrs []PCR) ([]Event, error) {
	events, err := replayEvents(e.rawEvents, pcrs)
	if err != nil {
		if _, isReplayErr := err.(ReplayError); isReplayErr {
			return nil, err
		}
		return nil, fmt.Errorf("pcrs failed to replay: %v", err)
	}
	return events, nil
}

type rawAttestationData struct {
	Version [4]byte  // This MUST be 1.1.0.0
	Fixed   [4]byte  // This SHALL always be the string ‘QUOT’
	Digest  [20]byte // PCR Composite Hash
	Nonce   [20]byte // Nonce Hash
}

var (
	fixedQuote = [4]byte{'Q', 'U', 'O', 'T'}
)

type rawPCRComposite struct {
	Size    uint16 // always 3
	PCRMask [3]byte
	Values  tpmutil.U32Bytes
}

func (a *AKPublic) validate12Quote(quote Quote, pcrs []PCR, nonce []byte) error {
	pub, ok := a.Public.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("unsupported public key type: %T", a.Public)
	}
	qHash := sha1.Sum(quote.Quote)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA1, qHash[:], quote.Signature); err != nil {
		return fmt.Errorf("invalid quote signature: %v", err)
	}

	var att rawAttestationData
	if _, err := tpmutil.Unpack(quote.Quote, &att); err != nil {
		return fmt.Errorf("parsing quote: %v", err)
	}
	// TODO(ericchiang): validate Version field.
	if att.Nonce != sha1.Sum(nonce) {
		return fmt.Errorf("invalid nonce")
	}
	if att.Fixed != fixedQuote {
		return fmt.Errorf("quote wasn't a QUOT object: %x", att.Fixed)
	}

	// See 5.4.1 Creating a PCR composite hash
	sort.Slice(pcrs, func(i, j int) bool { return pcrs[i].Index < pcrs[j].Index })
	var (
		pcrMask [3]byte // bitmap indicating which PCRs are active
		values  []byte  // appended values of all PCRs
	)
	for _, pcr := range pcrs {
		if pcr.Index < 0 || pcr.Index >= 24 {
			return fmt.Errorf("invalid PCR index: %d", pcr.Index)
		}
		pcrMask[pcr.Index/8] |= 1 << uint(pcr.Index%8)
		values = append(values, pcr.Digest...)
	}
	composite, err := tpmutil.Pack(rawPCRComposite{3, pcrMask, values})
	if err != nil {
		return fmt.Errorf("marshaling PCRs: %v", err)
	}
	if att.Digest != sha1.Sum(composite) {
		return fmt.Errorf("PCRs passed didn't match quote: %v", err)
	}

	// All provided PCRs are used to construct the composite hash which
	// is verified against the quote (for TPM 1.2), so if we got this far,
	// all PCR values are verified.
	for i := range pcrs {
		pcrs[i].quoteVerified = true
	}
	return nil
}

func (a *AKPublic) validate20Quote(quote Quote, pcrs []PCR, nonce []byte) error {
	sig, err := tpm2.DecodeSignature(bytes.NewBuffer(quote.Signature))
	if err != nil {
		return fmt.Errorf("parse quote signature: %v", err)
	}

	sigHash := a.Hash.New()
	sigHash.Write(quote.Quote)

	switch pub := a.Public.(type) {
	case *rsa.PublicKey:
		if sig.RSA == nil {
			return fmt.Errorf("rsa public key provided for ec signature")
		}
		sigBytes := []byte(sig.RSA.Signature)
		if err := rsa.VerifyPKCS1v15(pub, a.Hash, sigHash.Sum(nil), sigBytes); err != nil {
			return fmt.Errorf("invalid quote signature: %v", err)
		}
	default:
		// TODO(ericchiang): support ecdsa
		return fmt.Errorf("unsupported public key type %T", pub)
	}

	att, err := tpm2.DecodeAttestationData(quote.Quote)
	if err != nil {
		return fmt.Errorf("parsing quote signature: %v", err)
	}
	if att.Type != tpm2.TagAttestQuote {
		return fmt.Errorf("attestation isn't a quote, tag of type 0x%x", att.Type)
	}
	if !bytes.Equal([]byte(att.ExtraData), nonce) {
		return fmt.Errorf("nonce = %#v, want %#v", []byte(att.ExtraData), nonce)
	}

	pcrByIndex := map[int][]byte{}
	pcrDigestAlg := HashAlg(att.AttestedQuoteInfo.PCRSelection.Hash).cryptoHash()
	for _, pcr := range pcrs {
		if pcr.DigestAlg == pcrDigestAlg {
			pcrByIndex[pcr.Index] = pcr.Digest
		}
	}

	sigHash.Reset()
	quotePCRs := make(map[int]struct{}, len(att.AttestedQuoteInfo.PCRSelection.PCRs))
	for _, index := range att.AttestedQuoteInfo.PCRSelection.PCRs {
		digest, ok := pcrByIndex[index]
		if !ok {
			return fmt.Errorf("quote was over PCR %d which wasn't provided", index)
		}
		quotePCRs[index] = struct{}{}
		sigHash.Write(digest)
	}

	for index := range pcrByIndex {
		if _, exists := quotePCRs[index]; !exists {
			return fmt.Errorf("provided PCR %d was not included in quote", index)
		}
	}

	if !bytes.Equal(sigHash.Sum(nil), att.AttestedQuoteInfo.PCRDigest) {
		return fmt.Errorf("quote digest didn't match pcrs provided")
	}

	// If we got this far, all included PCRs with a digest algorithm matching that
	// of the quote are verified. As such, we set their quoteVerified bit.
	for i, pcr := range pcrs {
		if _, exists := quotePCRs[pcr.Index]; exists && pcr.DigestAlg == pcrDigestAlg {
			pcrs[i].quoteVerified = true
		}
	}
	return nil
}

func extend(pcr PCR, replay []byte, e rawEvent, locality byte) (pcrDigest []byte, eventDigest []byte, err error) {
	h := pcr.DigestAlg

	for _, digest := range e.digests {
		if digest.hash != pcr.DigestAlg {
			continue
		}
		if len(digest.data) != len(pcr.Digest) {
			return nil, nil, fmt.Errorf("digest data length (%d) doesn't match PCR digest length (%d)", len(digest.data), len(pcr.Digest))
		}
		hash := h.New()
		if len(replay) != 0 {
			hash.Write(replay)
		} else {
			b := make([]byte, h.Size())
			b[h.Size()-1] = locality
			hash.Write(b)
		}
		hash.Write(digest.data)
		return hash.Sum(nil), digest.data, nil
	}
	return nil, nil, fmt.Errorf("no event digest matches pcr algorithm: %v", pcr.DigestAlg)
}

// replayPCR replays the event log for a specific PCR, using pcr and
// event digests with the algorithm in pcr. An error is returned if the
// replayed values do not match the final PCR digest, or any event tagged
// with that PCR does not possess an event digest with the specified algorithm.
func replayPCR(rawEvents []rawEvent, pcr PCR) ([]Event, bool) {
	var (
		replay    []byte
		outEvents []Event
		locality  byte
	)

	for _, e := range rawEvents {
		if e.index != pcr.Index {
			continue
		}
		// If TXT is enabled then the first event for PCR0
		// should be a StartupLocality event. The final byte
		// of this event indicates the locality from which
		// TPM2_Startup() was issued. The initial value of
		// PCR0 is equal to the locality.
		if e.typ == eventTypeNoAction {
			if pcr.Index == 0 && len(e.data) == 17 && strings.HasPrefix(string(e.data), "StartupLocality") {
				locality = e.data[len(e.data)-1]
			}
			continue
		}
		replayValue, digest, err := extend(pcr, replay, e, locality)
		if err != nil {
			return nil, false
		}
		replay = replayValue
		outEvents = append(outEvents, Event{sequence: e.sequence, Data: e.data, Digest: digest, Index: pcr.Index, Type: e.typ})
	}

	if len(outEvents) > 0 && !bytes.Equal(replay, pcr.Digest) {
		return nil, false
	}
	return outEvents, true
}

type pcrReplayResult struct {
	events     []Event
	successful bool
}

func replayEvents(rawEvents []rawEvent, pcrs []PCR) ([]Event, error) {
	var (
		invalidReplays []int
		verifiedEvents []Event
		allPCRReplays  = map[int][]pcrReplayResult{}
	)

	// Replay the event log for every PCR and digest algorithm combination.
	for _, pcr := range pcrs {
		events, ok := replayPCR(rawEvents, pcr)
		allPCRReplays[pcr.Index] = append(allPCRReplays[pcr.Index], pcrReplayResult{events, ok})
	}

	// Record PCR indices which do not have any successful replay. Record the
	// events for a successful replay.
pcrLoop:
	for i, replaysForPCR := range allPCRReplays {
		for _, replay := range replaysForPCR {
			if replay.successful {
				// We consider the PCR verified at this stage: The replay of values with
				// one digest algorithm matched a provided value.
				// As such, we save the PCR's events, and proceed to the next PCR.
				verifiedEvents = append(verifiedEvents, replay.events...)
				continue pcrLoop
			}
		}
		invalidReplays = append(invalidReplays, i)
	}

	if len(invalidReplays) > 0 {
		events := make([]Event, 0, len(rawEvents))
		for _, e := range rawEvents {
			events = append(events, Event{e.sequence, e.index, e.typ, e.data, nil})
		}
		return nil, ReplayError{
			Events:      events,
			InvalidPCRs: invalidReplays,
		}
	}

	sort.Slice(verifiedEvents, func(i int, j int) bool {
		return verifiedEvents[i].sequence < verifiedEvents[j].sequence
	})
	return verifiedEvents, nil
}

// EV_NO_ACTION is a special event type that indicates information to the parser
// instead of holding a measurement. For TPM 2.0, this event type is used to signal
// switching from SHA1 format to a variable length digest.
//
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf#page=110
const eventTypeNoAction = 0x03

// ParseEventLog parses an unverified measurement log.
func ParseEventLog(measurementLog []byte) (*EventLog, error) {
	var specID *specIDEvent
	r := bytes.NewBuffer(measurementLog)
	parseFn := parseRawEvent
	var el EventLog
	e, err := parseFn(r, specID)
	if err != nil {
		return nil, fmt.Errorf("parse first event: %v", err)
	}
	if e.typ == eventTypeNoAction && len(e.data) >= binary.Size(specIDEventHeader{}) {
		specID, err = parseSpecIDEvent(e.data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse spec ID event: %v", err)
		}
		for _, alg := range specID.algs {
			switch tpm2.Algorithm(alg.ID) {
			case tpm2.AlgSHA1:
				el.Algs = append(el.Algs, HashSHA1)
			case tpm2.AlgSHA256:
				el.Algs = append(el.Algs, HashSHA256)
			}
		}
		if len(el.Algs) == 0 {
			return nil, fmt.Errorf("measurement log didn't use sha1 or sha256 digests")
		}
		// Switch to parsing crypto agile events. Don't include this in the
		// replayed events since it intentionally doesn't extend the PCRs.
		//
		// Note that this doesn't actually guarantee that events have SHA256
		// digests.
		parseFn = parseRawEvent2
		el.specIDEvent = specID
	} else {
		el.Algs = []HashAlg{HashSHA1}
		el.rawEvents = append(el.rawEvents, e)
	}
	sequence := 1
	for r.Len() != 0 {
		e, err := parseFn(r, specID)
		if err != nil {
			return nil, err
		}
		e.sequence = sequence
		sequence++
		el.rawEvents = append(el.rawEvents, e)
	}
	return &el, nil
}

type specIDEvent struct {
	algs []specAlgSize
}

type specAlgSize struct {
	ID   uint16
	Size uint16
}

// Expected values for various Spec ID Event fields.
// https://trustedcomputinggroup.org/wp-content/uploads/EFI-Protocol-Specification-rev13-160330final.pdf#page=19
var wantSignature = [16]byte{0x53, 0x70,
	0x65, 0x63, 0x20, 0x49,
	0x44, 0x20, 0x45, 0x76,
	0x65, 0x6e, 0x74, 0x30,
	0x33, 0x00} // "Spec ID Event03\0"

const (
	wantMajor  = 2
	wantMinor  = 0
	wantErrata = 0
)

type specIDEventHeader struct {
	Signature     [16]byte
	PlatformClass uint32
	VersionMinor  uint8
	VersionMajor  uint8
	Errata        uint8
	UintnSize     uint8
	NumAlgs       uint32
}

// parseSpecIDEvent parses a TCG_EfiSpecIDEventStruct structure from the reader.
//
// https://trustedcomputinggroup.org/wp-content/uploads/EFI-Protocol-Specification-rev13-160330final.pdf#page=18
func parseSpecIDEvent(b []byte) (*specIDEvent, error) {
	r := bytes.NewReader(b)
	var header specIDEventHeader
	if err := binary.Read(r, binary.LittleEndian, &header); err != nil {
		return nil, fmt.Errorf("reading event header: %w: %X", err, b)
	}
	if header.Signature != wantSignature {
		return nil, fmt.Errorf("invalid spec id signature: %x", header.Signature)
	}
	if header.VersionMajor != wantMajor {
		return nil, fmt.Errorf("invalid spec major version, got %02x, wanted %02x",
			header.VersionMajor, wantMajor)
	}
	if header.VersionMinor != wantMinor {
		return nil, fmt.Errorf("invalid spec minor version, got %02x, wanted %02x",
			header.VersionMajor, wantMinor)
	}

	// TODO(ericchiang): Check errata? Or do we expect that to change in ways
	// we're okay with?

	specAlg := specAlgSize{}
	e := specIDEvent{}
	for i := 0; i < int(header.NumAlgs); i++ {
		if err := binary.Read(r, binary.LittleEndian, &specAlg); err != nil {
			return nil, fmt.Errorf("reading algorithm: %v", err)
		}
		e.algs = append(e.algs, specAlg)
	}

	var vendorInfoSize uint8
	if err := binary.Read(r, binary.LittleEndian, &vendorInfoSize); err != nil {
		return nil, fmt.Errorf("reading vender info size: %v", err)
	}
	if r.Len() != int(vendorInfoSize) {
		return nil, fmt.Errorf("reading vendor info, expected %d remaining bytes, got %d", vendorInfoSize, r.Len())
	}
	return &e, nil
}

type digest struct {
	hash crypto.Hash
	data []byte
}

type rawEvent struct {
	sequence int
	index    int
	typ      EventType
	data     []byte
	digests  []digest
}

// TPM 1.2 event log format. See "5.1 SHA1 Event Log Entry Format"
// https://trustedcomputinggroup.org/wp-content/uploads/EFI-Protocol-Specification-rev13-160330final.pdf#page=15
type rawEventHeader struct {
	PCRIndex  uint32
	Type      uint32
	Digest    [20]byte
	EventSize uint32
}

type eventSizeErr struct {
	eventSize uint32
	logSize   int
}

func (e *eventSizeErr) Error() string {
	return fmt.Sprintf("event data size (%d bytes) is greater than remaining measurement log (%d bytes)", e.eventSize, e.logSize)
}

func parseRawEvent(r *bytes.Buffer, specID *specIDEvent) (event rawEvent, err error) {
	var h rawEventHeader
	if err = binary.Read(r, binary.LittleEndian, &h); err != nil {
		return event, fmt.Errorf("header deserialization error: %w", err)
	}
	if h.EventSize > uint32(r.Len()) {
		return event, &eventSizeErr{h.EventSize, r.Len()}
	}

	data := make([]byte, int(h.EventSize))
	if _, err := io.ReadFull(r, data); err != nil {
		return event, fmt.Errorf("reading data error: %w", err)
	}

	digests := []digest{{hash: crypto.SHA1, data: h.Digest[:]}}

	return rawEvent{
		typ:     EventType(h.Type),
		data:    data,
		index:   int(h.PCRIndex),
		digests: digests,
	}, nil
}

// TPM 2.0 event log format. See "5.2 Crypto Agile Log Entry Format"
// https://trustedcomputinggroup.org/wp-content/uploads/EFI-Protocol-Specification-rev13-160330final.pdf#page=15
type rawEvent2Header struct {
	PCRIndex uint32
	Type     uint32
}

func parseRawEvent2(r *bytes.Buffer, specID *specIDEvent) (event rawEvent, err error) {
	var h rawEvent2Header

	if err = binary.Read(r, binary.LittleEndian, &h); err != nil {
		return event, err
	}
	event.typ = EventType(h.Type)
	event.index = int(h.PCRIndex)

	// parse the event digests
	var numDigests uint32
	if err := binary.Read(r, binary.LittleEndian, &numDigests); err != nil {
		return event, err
	}

	for i := 0; i < int(numDigests); i++ {
		var algID uint16
		if err := binary.Read(r, binary.LittleEndian, &algID); err != nil {
			return event, err
		}
		var digest digest

		for _, alg := range specID.algs {
			if alg.ID != algID {
				continue
			}
			if r.Len() < int(alg.Size) {
				return event, fmt.Errorf("reading digest: %v", io.ErrUnexpectedEOF)
			}
			digest.data = make([]byte, alg.Size)
			digest.hash = HashAlg(alg.ID).cryptoHash()
		}
		if len(digest.data) == 0 {
			return event, fmt.Errorf("unknown algorithm ID %x", algID)
		}
		if _, err := io.ReadFull(r, digest.data); err != nil {
			return event, err
		}
		event.digests = append(event.digests, digest)
	}

	// parse event data
	var eventSize uint32
	if err = binary.Read(r, binary.LittleEndian, &eventSize); err != nil {
		return event, err
	}
	if eventSize > uint32(r.Len()) {
		return event, &eventSizeErr{eventSize, r.Len()}
	}
	event.data = make([]byte, int(eventSize))
	if _, err := io.ReadFull(r, event.data); err != nil {
		return event, err
	}
	return event, err
}

// AppendEvents takes a series of TPM 2.0 event logs and combines
// them into a single sequence of events with a single header.
//
// Additional logs must not use a digest algorithm which was not
// present in the original log.
func AppendEvents(base []byte, additional ...[]byte) ([]byte, error) {
	baseLog, err := ParseEventLog(base)
	if err != nil {
		return nil, fmt.Errorf("base: %v", err)
	}
	if baseLog.specIDEvent == nil {
		return nil, errors.New("tpm 1.2 event logs cannot be combined")
	}

	outBuff := make([]byte, len(base))
	copy(outBuff, base)
	out := bytes.NewBuffer(outBuff)

	for i, l := range additional {
		log, err := ParseEventLog(l)
		if err != nil {
			return nil, fmt.Errorf("log %d: %v", i, err)
		}
		if log.specIDEvent == nil {
			return nil, fmt.Errorf("log %d: cannot use tpm 1.2 event log as a source", i)
		}

	algCheck:
		for _, alg := range log.specIDEvent.algs {
			for _, baseAlg := range baseLog.specIDEvent.algs {
				if baseAlg == alg {
					continue algCheck
				}
			}
			return nil, fmt.Errorf("log %d: cannot use digest (%+v) not present in base log", i, alg)
		}

		for x, e := range log.rawEvents {
			// Serialize header (PCR index, event type, number of digests)
			binary.Write(out, binary.LittleEndian, rawEvent2Header{
				PCRIndex: uint32(e.index),
				Type:     uint32(e.typ),
			})
			binary.Write(out, binary.LittleEndian, uint32(len(e.digests)))

			// Serialize digests
			for _, d := range e.digests {
				var algID uint16
				switch d.hash {
				case crypto.SHA256:
					algID = uint16(HashSHA256)
				case crypto.SHA1:
					algID = uint16(HashSHA1)
				default:
					return nil, fmt.Errorf("log %d: event %d: unhandled hash function %v", i, x, d.hash)
				}

				binary.Write(out, binary.LittleEndian, algID)
				out.Write(d.data)
			}

			// Serialize event data
			binary.Write(out, binary.LittleEndian, uint32(len(e.data)))
			out.Write(e.data)
		}
	}

	return out.Bytes(), nil
}
