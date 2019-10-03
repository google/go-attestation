package attest

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"
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

type ekBlobHeader struct {
	Tag     uint16
	EkType  uint16
	BlobLen uint32
}

func makeEkBlob(activationBlob []byte) []byte {
	var out bytes.Buffer
	binary.Write(&out, binary.BigEndian, ekBlobHeader{
		Tag:     ekBlobTag,
		EkType:  ekTypeActivate,
		BlobLen: uint32(len(activationBlob)),
	})
	out.Write(activationBlob)

	return out.Bytes()
}

func pad(plaintext []byte, bsize int) []byte {
	pad := bsize - (len(plaintext) % bsize)
	if pad == 0 {
		pad = bsize
	}
	for i := 0; i < pad; i++ {
		plaintext = append(plaintext, byte(pad))
	}
	return plaintext
}

// generateChallenge12 generates a TPM_EK_BLOB challenge for a TPM 1.2 device.
// This process is defined in section 15.1 of the TPM 1.2 commands spec,
// available at: https://trustedcomputinggroup.org/wp-content/uploads/TPM-Main-Part-3-Commands_v1.2_rev116_01032011.pdf
//
// asymenc is a TPM_EK_BLOB structure containing a TPM_EK_BLOB_ACTIVATE structure,
// encrypted with the EK of the TPM. The contained credential is the aes key
// for symenc.
// symenc is a structure with TPM_SYM_MODE_CBC leading, then the IV, and then
// the secret encrypted with the session key credential contained in asymenc.
// To use this, pass asymenc as the input to the TPM_ActivateIdentity command.
// Use the returned credential as the aes key to decode the secret in symenc.
func generateChallenge12(rand io.Reader, pubkey *rsa.PublicKey, akpub, secret []byte) (asymenc []byte, symenc []byte, err error) {
	aeskey := make([]byte, 16)
	iv := make([]byte, 16)
	if _, err = io.ReadFull(rand, aeskey); err != nil {
		return nil, nil, err
	}
	if _, err = io.ReadFull(rand, iv); err != nil {
		return nil, nil, err
	}

	activationBlob, err := makeActivationBlob(aeskey, akpub)
	if err != nil {
		return nil, nil, err
	}
	label := []byte{'T', 'C', 'P', 'A'}
	asymenc, err = rsa.EncryptOAEP(sha1.New(), rand, pubkey, makeEkBlob(activationBlob), label)
	if err != nil {
		return nil, nil, fmt.Errorf("EncryptOAEP() failed: %v", err)
	}

	block, err := aes.NewCipher(aeskey)
	if err != nil {
		return nil, nil, err
	}
	cbc := cipher.NewCBCEncrypter(block, iv)
	secret = pad(secret, len(iv))
	symenc = make([]byte, len(secret))
	cbc.CryptBlocks(symenc, secret)

	var symOut bytes.Buffer
	binary.Write(&symOut, binary.BigEndian, uint32(0x02)) // TPM_SYM_MODE_CBC
	symOut.Write(iv)
	symOut.Write(symenc)

	return asymenc, symOut.Bytes(), nil
}
