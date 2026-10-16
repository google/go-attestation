package attest

import (
	"bytes"
	"encoding/binary"
	"io"
)

// fakeCmdChannel returns a fake TPM command channel that
// returns a measurement log with the algorithms that are present in the PCR banks.
type fakeCmdChannel struct {
	io.ReadWriteCloser
}

// MeasurementLog implements CommandChannelTPM20.
func (cc *fakeCmdChannel) MeasurementLog() ([]byte, error) {
	algs, err := pcrbanks(cc.ReadWriteCloser)
	if err != nil {
		return nil, err
	}
	return generateMeasurementLog(algs), nil
}

func generateMeasurementLog(algs []HashAlg) []byte {
	var specAlgs []specAlgSize
	for _, alg := range algs {
		hash, err := alg.cryptoHash()
		if err != nil {
			panic(err)
		}
		specAlgs = append(specAlgs, specAlgSize{ID: uint16(alg), Size: uint16(hash.Size())})
	}
	return generateSpecIDEventLog(specAlgs...)
}

// generateSpecIDEventLog declares algs verbatim, so tests can declare sizes a
// TPM never would.
func generateSpecIDEventLog(algs ...specAlgSize) []byte {
	specIDEventHeader := generateSpecIDEventHeader(algs)
	raw := rawEventHeader{
		PCRIndex:  0,
		Type:      eventTypeNoAction,
		Digest:    [20]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		EventSize: uint32(len(specIDEventHeader)),
	}
	var rawBytes bytes.Buffer

	if err := binary.Write(&rawBytes, binary.LittleEndian, &raw); err != nil {
		panic(err)
	}
	if err := binary.Write(&rawBytes, binary.LittleEndian, specIDEventHeader); err != nil {
		panic(err)
	}
	return rawBytes.Bytes()
}

func generateSpecIDEventHeader(algs []specAlgSize) []byte {
	specIDEventHeader := specIDEventHeader{
		NumAlgs:       uint32(len(algs)),
		Signature:     wantSignature,
		VersionMajor:  wantMajor,
		VersionMinor:  wantMinor,
		Errata:        wantErrata,
		UintnSize:     0,
		PlatformClass: 0,
	}

	// Write out the header.
	var specIDEventHeaderBytes bytes.Buffer
	if err := binary.Write(&specIDEventHeaderBytes, binary.LittleEndian, &specIDEventHeader); err != nil {
		panic(err)
	}
	// Write out the Algs.
	for _, alg := range algs {
		if err := binary.Write(&specIDEventHeaderBytes, binary.LittleEndian, alg); err != nil {
			panic(err)
		}
	}
	// No vendor info.
	vendorInfoSize := uint8(0)
	if err := binary.Write(&specIDEventHeaderBytes, binary.LittleEndian, &vendorInfoSize); err != nil {
		panic(err)
	}

	return specIDEventHeaderBytes.Bytes()
}
