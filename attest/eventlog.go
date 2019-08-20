package attest

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"
	"sort"

	// Ensure hashes are available.
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

// EventLog contains the data required to parse and validate an event log.
type EventLog struct {
	// AIKPublic is the activated public key that has been proven to be under the
	// control of the TPM.
	AIKPublic crypto.PublicKey
	// AIKHash is the hash used to generate the quote.
	AIKHash crypto.Hash

	// Quote is a signature over the values of a PCR.
	Quote *Quote
	// PCRs are the hash values in a given number of registers.
	PCRs []PCR
	// Nonce is additional data used to validate the quote signature. It's used
	// by the server to prevent clients from re-playing quotes.
	Nonce []byte

	// MeasurementLog contains the raw event log data, which is matched against
	// the PCRs for validation.
	MeasurementLog []byte
}

// Validate verifies the signature of the quote agains the public key, that the
// quote matches the PCRs, parses the measurement log, and replays the PCRs.
//
// Events for PCRs not in the quote are dropped.
func (e *EventLog) Validate() (events []Event, err error) {
	var pcrs []PCR
	switch e.Quote.Version {
	case TPMVersion12:
		pcrs, err = e.validate12Quote()
	case TPMVersion20:
		pcrs, err = e.validate20Quote()
	default:
		return nil, fmt.Errorf("quote used unknown tpm version 0x%x", e.Quote.Version)
	}
	if err != nil {
		return nil, fmt.Errorf("invalid quote: %v", err)
	}
	rawEvents, err := parseEventLog(e.MeasurementLog)
	if err != nil {
		return nil, fmt.Errorf("parsing measurement log: %v", err)
	}
	events, err = replayEvents(rawEvents, pcrs)
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

func (e *EventLog) validate12Quote() (pcrs []PCR, err error) {
	pub, ok := e.AIKPublic.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unsupported public key type: %T", e.AIKPublic)
	}
	quote := sha1.Sum(e.Quote.Quote)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA1, quote[:], e.Quote.Signature); err != nil {
		return nil, fmt.Errorf("invalid quote signature: %v", err)
	}

	var att rawAttestationData
	if _, err := tpmutil.Unpack(e.Quote.Quote, &att); err != nil {
		return nil, fmt.Errorf("parsing quote: %v", err)
	}
	// TODO(ericchiang): validate Version field.
	if att.Nonce != sha1.Sum(e.Nonce) {
		return nil, fmt.Errorf("invalid nonce")
	}
	if att.Fixed != fixedQuote {
		return nil, fmt.Errorf("quote wasn't a QUOT object: %x", att.Fixed)
	}

	// See 5.4.1 Creating a PCR composite hash
	sort.Slice(e.PCRs, func(i, j int) bool { return e.PCRs[i].Index < e.PCRs[j].Index })
	var (
		pcrMask [3]byte // bitmap indicating which PCRs are active
		values  []byte  // appended values of all PCRs
	)
	for _, pcr := range e.PCRs {
		if pcr.Index < 0 || pcr.Index >= 24 {
			return nil, fmt.Errorf("invalid PCR index: %d", pcr.Index)
		}
		pcrMask[pcr.Index/8] |= 1 << uint(pcr.Index%8)
		values = append(values, pcr.Digest...)
	}
	composite, err := tpmutil.Pack(rawPCRComposite{3, pcrMask, values})
	if err != nil {
		return nil, fmt.Errorf("marshaling PCRss: %v", err)
	}
	if att.Digest != sha1.Sum(composite) {
		return nil, fmt.Errorf("PCRs passed didn't match quote: %v", err)
	}
	return e.PCRs, nil
}

func (e *EventLog) validate20Quote() (pcrs []PCR, err error) {
	sig, err := tpm2.DecodeSignature(bytes.NewBuffer(e.Quote.Signature))
	if err != nil {
		return nil, fmt.Errorf("parse quote signature: %v", err)
	}

	sigHash := e.AIKHash.New()
	sigHash.Write(e.Quote.Quote)

	switch pub := e.AIKPublic.(type) {
	case *rsa.PublicKey:
		if sig.RSA == nil {
			return nil, fmt.Errorf("rsa public key provided for ec signature")
		}
		sigBytes := []byte(sig.RSA.Signature)
		if err := rsa.VerifyPKCS1v15(pub, e.AIKHash, sigHash.Sum(nil), sigBytes); err != nil {
			return nil, fmt.Errorf("invalid quote signature: %v", err)
		}
	default:
		// TODO(ericchiang): support ecdsa
		return nil, fmt.Errorf("unsupported public key type %T", pub)
	}

	att, err := tpm2.DecodeAttestationData(e.Quote.Quote)
	if err != nil {
		return nil, fmt.Errorf("parsing quote signature: %v", err)
	}
	if att.Type != tpm2.TagAttestQuote {
		return nil, fmt.Errorf("attestation isn't a quote, tag of type 0x%x", att.Type)
	}
	if !bytes.Equal([]byte(att.ExtraData), e.Nonce) {
		return nil, fmt.Errorf("nonce didn't match: %v", err)
	}

	pcrByIndex := map[int][]byte{}
	for _, pcr := range e.PCRs {
		pcrByIndex[pcr.Index] = pcr.Digest
	}

	n := len(att.AttestedQuoteInfo.PCRDigest)
	hash, ok := hashBySize[n]
	if !ok {
		return nil, fmt.Errorf("quote used unsupported hash algorithm length: %d", n)
	}
	var validatedPCRs []PCR
	h := hash.New()
	for _, index := range att.AttestedQuoteInfo.PCRSelection.PCRs {
		digest, ok := pcrByIndex[index]
		if !ok {
			return nil, fmt.Errorf("quote was over PCR %d which wasn't provided", index)
		}
		if len(digest) != hash.Size() {
			return nil, fmt.Errorf("mismatch pcr and quote hash, pcr hash length=%d, quote hash length=%d", len(digest), hash.Size())
		}
		h.Write(digest)
		validatedPCRs = append(validatedPCRs, PCR{Index: index, Digest: digest})
	}

	if !bytes.Equal(h.Sum(nil), att.AttestedQuoteInfo.PCRDigest) {
		return nil, fmt.Errorf("quote digest didn't match pcrs provided")
	}
	return validatedPCRs, nil
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

func parseEventLog(b []byte) ([]rawEvent, error) {
	r := bytes.NewBuffer(b)
	parseFn := parseRawEvent
	e, err := parseFn(r)
	if err != nil {
		return nil, fmt.Errorf("parse first event: %v", err)
	}
	var events []rawEvent
	if e.typ == eventTypeNoAction {
		// Switch to parsing crypto agile events. Don't include this in the
		// replayed events since it's intentionally switching from SHA1 to
		// SHA256 and will fail to extend a SHA256 PCR value.
		//
		// NOTE(ericchiang): to be strict, we could parse the event data as a
		// TCG_EfiSpecIDEventStruct and validate the algorithms. But for now,
		// assume this indicates a switch from SHA1 format to SHA1/SHA256.
		//
		// https://trustedcomputinggroup.org/wp-content/uploads/EFI-Protocol-Specification-rev13-160330final.pdf#page=18
		parseFn = parseRawEvent2
	} else {
		events = append(events, e)
	}
	for r.Len() != 0 {
		e, err := parseFn(r)
		if err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	return events, nil
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
