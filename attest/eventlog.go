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
	"encoding/binary"
	"fmt"
	"io"
	"sort"

	// Ensure hashes are available.
	"crypto/rsa"
	"crypto/sha1"
	_ "crypto/sha256"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// TPM algorithms. See the TPM 2.0 specification section 6.3.
//
// https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf#page=42
const (
	algSHA1   uint16 = 0x0004
	algSHA256 uint16 = 0x000B
)

// EventType indicates what kind of data an event is reporting.
type EventType uint32

// Event is a single event from a TCG event log. This reports descrete items such
// as BIOs measurements or EFI states.
type Event struct {
	// PCR index of the event.
	Index int
	// Type of the event.
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

// EventLog is a parsed measurement log. This contains unverified data representing
// boot events that must be replayed against PCR values to determine authenticity.
type EventLog struct {
	// Algs holds the set of algorithms that the event log uses.
	Algs []HashAlg

	rawEvents []rawEvent
}

// Verify replays the event log against a TPM's PCR values, returning events
// from the event log, or an error if the replayed PCR values did not match the
// provided PCR values.
func (e *EventLog) Verify(pcrs []PCR) ([]Event, error) {
	events, err := replayEvents(e.rawEvents, pcrs)
	if err != nil {
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

func (a *AIKPublic) validate12Quote(quote Quote, pcrs []PCR, nonce []byte) error {
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
	return nil
}

func (a *AIKPublic) validate20Quote(quote Quote, pcrs []PCR, nonce []byte) error {
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
		return fmt.Errorf("nonce didn't match: %v", err)
	}

	pcrByIndex := map[int][]byte{}
	for _, pcr := range pcrs {
		pcrByIndex[pcr.Index] = pcr.Digest
	}

	n := len(att.AttestedQuoteInfo.PCRDigest)
	hash, ok := hashBySize[n]
	if !ok {
		return fmt.Errorf("quote used unsupported hash algorithm length: %d", n)
	}

	h := hash.New()
	for _, index := range att.AttestedQuoteInfo.PCRSelection.PCRs {
		digest, ok := pcrByIndex[index]
		if !ok {
			return fmt.Errorf("quote was over PCR %d which wasn't provided", index)
		}
		h.Write(digest)
	}

	if !bytes.Equal(h.Sum(nil), att.AttestedQuoteInfo.PCRDigest) {
		return fmt.Errorf("quote digest didn't match pcrs provided")
	}
	return nil
}

var hashBySize = map[int]crypto.Hash{
	crypto.SHA1.Size():   crypto.SHA1,
	crypto.SHA256.Size(): crypto.SHA256,
}

func extend(pcr, replay []byte, e rawEvent) ([]byte, Event, error) {
	h, ok := hashBySize[len(pcr)]
	if !ok {
		return nil, Event{}, fmt.Errorf("pcr %d was not a known hash size: %d", e.index, len(pcr))
	}
	for _, digest := range e.digests {
		if len(digest) != len(pcr) {
			continue
		}
		hash := h.New()
		if len(replay) != 0 {
			hash.Write(replay)
		} else {
			b := make([]byte, h.Size())
			hash.Write(b)
		}
		hash.Write(digest)
		return hash.Sum(nil), Event{e.index, e.typ, e.data, digest}, nil
	}
	return nil, Event{}, fmt.Errorf("no event digest matches pcr length: %d", len(pcr))
}

func replayEvents(rawEvents []rawEvent, pcrs []PCR) ([]Event, error) {
	events := []Event{}
	replay := map[int][]byte{}
	pcrByIndex := map[int][]byte{}
	for _, pcr := range pcrs {
		pcrByIndex[pcr.Index] = pcr.Digest
	}

	for i, e := range rawEvents {
		pcrValue, ok := pcrByIndex[e.index]
		if !ok {
			// Ignore events for PCRs that weren't included in the quote.
			continue
		}
		replayValue, event, err := extend(pcrValue, replay[e.index], e)
		if err != nil {
			return nil, fmt.Errorf("replaying event %d: %v", i, err)
		}
		replay[e.index] = replayValue
		events = append(events, event)
	}

	var invalidReplays []int
	for i, value := range replay {
		if !bytes.Equal(value, pcrByIndex[i]) {
			invalidReplays = append(invalidReplays, i)
		}
	}
	if len(invalidReplays) > 0 {
		return nil, fmt.Errorf("the following registers failed to replay: %d", invalidReplays)
	}
	return events, nil
}

// EV_NO_ACTION is a special event type that indicates information to the parser
// instead of holding a measurement. For TPM 2.0, this event type is used to signal
// switching from SHA1 format to a variable length digest.
//
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf#page=110
const eventTypeNoAction = 0x03

// ParseEventLog parses an unverified measurement log.
func ParseEventLog(measurementLog []byte) (*EventLog, error) {
	r := bytes.NewBuffer(measurementLog)
	parseFn := parseRawEvent
	var el EventLog
	e, err := parseFn(r)
	if err != nil {
		return nil, fmt.Errorf("parse first event: %v", err)
	}
	if e.typ == eventTypeNoAction {
		specID, err := parseSpecIDEvent(e.data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse spec ID event: %v", err)
		}
		for _, alg := range specID.algs {
			switch tpm2.Algorithm(alg) {
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
		// Note that this doesn't actually guarentee that events have SHA256
		// digests.
		parseFn = parseRawEvent2
	} else {
		el.Algs = []HashAlg{HashSHA1}
		el.rawEvents = append(el.rawEvents, e)
	}
	for r.Len() != 0 {
		e, err := parseFn(r)
		if err != nil {
			return nil, err
		}
		el.rawEvents = append(el.rawEvents, e)
	}
	return &el, nil
}

type specIDEvent struct {
	algs []uint16
}

type specAlgSize struct {
	ID   uint16
	Size uint16
}

var (
	// Expected values for various Spec ID Event fields.
	// https://trustedcomputinggroup.org/wp-content/uploads/EFI-Protocol-Specification-rev13-160330final.pdf#page=19
	wantSignature = [16]byte{0x53, 0x70,
		0x65, 0x63, 0x20, 0x49,
		0x44, 0x20, 0x45, 0x76,
		0x65, 0x6e, 0x74, 0x30,
		0x33, 0x00} // "Spec ID Event03\0"
	wantMajor  uint8 = 2
	wantMinor  uint8 = 0
	wantErrata       = 0
)

// parseSpecIDEvent parses a TCG_EfiSpecIDEventStruct structure from the reader.
//
// https://trustedcomputinggroup.org/wp-content/uploads/EFI-Protocol-Specification-rev13-160330final.pdf#page=18
func parseSpecIDEvent(b []byte) (*specIDEvent, error) {
	r := bytes.NewReader(b)
	var header struct {
		Signature     [16]byte
		PlatformClass uint32
		VersionMinor  uint8
		VersionMajor  uint8
		Errata        uint8
		UintnSize     uint8
		NumAlgs       uint32
	}
	if err := binary.Read(r, binary.LittleEndian, &header); err != nil {
		return nil, fmt.Errorf("reading event header: %v", err)
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

	algs := make([]specAlgSize, header.NumAlgs)
	if err := binary.Read(r, binary.LittleEndian, &algs); err != nil {
		return nil, fmt.Errorf("reading algorithms: %v", err)
	}

	var vendorInfoSize uint8
	if err := binary.Read(r, binary.LittleEndian, &vendorInfoSize); err != nil {
		return nil, fmt.Errorf("reading vender info size: %v", err)
	}
	if r.Len() != int(vendorInfoSize) {
		return nil, fmt.Errorf("reading vendor info, expected %d remaining bytes, got %d", vendorInfoSize, r.Len())
	}
	var e specIDEvent
	for _, alg := range algs {
		e.algs = append(e.algs, alg.ID)
	}
	return &e, nil
}

type rawEvent struct {
	index   int
	typ     EventType
	data    []byte
	digests [][]byte
}

// TPM 1.2 event log format. See "5.1 SHA1 Event Log Entry Format"
// https://trustedcomputinggroup.org/wp-content/uploads/EFI-Protocol-Specification-rev13-160330final.pdf#page=15
type rawEventHeader struct {
	PCRIndex  uint32
	Type      uint32
	Digest    [20]byte
	EventSize uint32
}

func parseRawEvent(r io.Reader) (event rawEvent, err error) {
	var h rawEventHeader
	if err = binary.Read(r, binary.LittleEndian, &h); err != nil {
		return event, err
	}
	data := make([]byte, int(h.EventSize))
	if _, err := io.ReadFull(r, data); err != nil {
		return event, err
	}
	return rawEvent{
		typ:     EventType(h.Type),
		data:    data,
		index:   int(h.PCRIndex),
		digests: [][]byte{h.Digest[:]},
	}, nil
}

// TPM 2.0 event log format. See "5.2 Crypto Agile Log Entry Format"
// https://trustedcomputinggroup.org/wp-content/uploads/EFI-Protocol-Specification-rev13-160330final.pdf#page=15
type rawEvent2Header struct {
	PCRIndex uint32
	Type     uint32
}

func parseRawEvent2(r io.Reader) (event rawEvent, err error) {
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
		var digest []byte
		switch algID {
		case algSHA1:
			digest = make([]byte, crypto.SHA1.Size())
		case algSHA256:
			digest = make([]byte, crypto.SHA256.Size())
		default:
			// ignore signatures that aren't SHA1 or SHA256
			continue
		}
		if _, err := io.ReadFull(r, digest); err != nil {
			return event, err
		}
		event.digests = append(event.digests, digest)
	}

	// parse event data
	var eventSize uint32
	if err = binary.Read(r, binary.LittleEndian, &eventSize); err != nil {
		return event, err
	}
	event.data = make([]byte, int(eventSize))
	if _, err := io.ReadFull(r, event.data); err != nil {
		return event, err
	}
	return event, err
}
