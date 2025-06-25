package attest

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
)

const (
	ekBlobTag         = 0x000c
	ekBlobActivateTag = 0x002b
	ekTypeActivate    = 0x0001

	algXOR = 0x0000000a

	schemeESNone = 0x0001
)

type symKeyHeader struct {
	Alg     uint32
	Scheme  uint16
	KeySize uint16
}

type activationBlobHeader struct {
	Tag       uint16
	KeyHeader symKeyHeader
}

func makeEmptyPCRInfo() []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, uint16(3)) // SIZE_OF_SELECT
	b.Write([]byte{0x00, 0x00, 0x00})             // empty bitfield for 3 PCRs
	b.Write([]byte{0x01})                         // TPM_LOCALITY_SELECTION = TPM_LOC_ZERO
	b.Write(bytes.Repeat([]byte{0}, sha1.Size))   // TPM_COMPOSITE_HASH
	return b.Bytes()
}

func makeActivationBlob(symKey, akpub []byte) (blob []byte, err error) {
	akHash := sha1.Sum(akpub)

	var out bytes.Buffer
	if err := binary.Write(&out, binary.BigEndian, activationBlobHeader{
		Tag: ekBlobActivateTag,
		KeyHeader: symKeyHeader{
			Alg:     algXOR,
			Scheme:  schemeESNone,
			KeySize: uint16(len(symKey)),
		},
	}); err != nil {
		return nil, err
	}

	out.Write(symKey)
	out.Write(akHash[:])
	out.Write(makeEmptyPCRInfo())
	return out.Bytes(), nil
}
