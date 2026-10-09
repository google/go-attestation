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
	"encoding/binary"
	"fmt"
	"io"
)

const (
	// PCP key magic
	pcpKeyMagic = 0x4D504350
)

// keyBlobHeaderSize is the number of bytes a [keyBlobHeader] occupies on the
// wire, and thus the smallest valid value of its HeaderSize field.
var keyBlobHeaderSize = binary.Size(keyBlobHeader{})

type keyProperties struct {
	pub  []byte
	priv []byte
}

// keyBlobHeader is the fixed-size, little endian header of a PCP_20_KEY_BLOB.
// Its fields mirror the PCP_20_KEY_BLOB structure defined by the TPM Platform
// Crypto Provider.
type keyBlobHeader struct {
	Magic              uint32
	HeaderSize         uint32
	TPMType            uint32
	Flags              uint32
	PubLen             uint32
	PrivLen            uint32
	PubMigrationLen    uint32
	PrivMigrationLen   uint32
	PolicyDigestLen    uint32
	PCRBindingLen      uint32
	PCRDigestLen       uint32
	EncryptedSecretLen uint32
	TPM12HostageLen    uint32
}

// decodeKeyBlob parses a PCP_20_KEY_BLOB, as returned by NCryptExportKey for
// the "OpaqueKeyBlob" type, returning the public and private areas of the key
// it describes wrapped in [*keyProperties].
func decodeKeyBlob(keyBlob []byte) (*keyProperties, error) {
	r := bytes.NewReader(keyBlob)

	var header keyBlobHeader
	if err := binary.Read(r, binary.LittleEndian, &header); err != nil {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}
	if header.Magic != pcpKeyMagic {
		return nil, fmt.Errorf("invalid header magic %X", header.Magic)
	}
	// A header smaller than the fields just read would seek backwards into the
	// header itself, and the bytes it contains would be mistaken for key data.
	if header.HeaderSize < uint32(keyBlobHeaderSize) {
		return nil, fmt.Errorf("invalid header size %d; expected at least %d", header.HeaderSize, keyBlobHeaderSize)
	}

	// Skip over any padding
	if _, err := r.Seek(int64(header.HeaderSize), io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to skip header padding: %w", err)
	}

	pubKey, err := readArea(r, header.PubLen, "public key")
	if err != nil {
		return nil, err
	}

	privBlob, err := readArea(r, header.PrivLen, "private blob")
	if err != nil {
		return nil, err
	}

	return &keyProperties{
		pub:  pubKey,
		priv: privBlob,
	}, nil
}

// readArea reads the next length bytes from r as a sized area, returning its
// contents without the leading two bytes that encode the length of the area.
func readArea(r *bytes.Reader, length uint32, name string) ([]byte, error) {
	if length < 2 {
		return nil, fmt.Errorf("invalid %s length %d; expected at least 2", name, length)
	}
	if int64(length) > int64(r.Len()) {
		return nil, fmt.Errorf("invalid %s length %d; only %d bytes remaining", name, length, r.Len())
	}

	area := make([]byte, length)
	if _, err := io.ReadFull(r, area); err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", name, err)
	}

	return area[2:], nil
}

func convertKeyParameters(alg Algorithm, size int) (Algorithm, uint32, error) {
	switch alg {
	case RSA:
		return RSA, uint32(size), nil
	case ECDSA:
		switch size {
		case 256:
			return P256, 0, nil
		case 384:
			return P384, 0, nil
		case 521:
			return P521, 0, nil
		default:
			return "", 0, fmt.Errorf("unsupported ECDSA key size: %v", size)
		}
	case P256, P384, P521:
		if size > 0 && size != alg.Size() {
			return "", 0, fmt.Errorf("requested size %v does not match curve size %v", size, alg.Size())
		}
		return alg, 0, nil
	default:
		return "", 0, fmt.Errorf("unsupported algorithm type: %q", alg)
	}
}
