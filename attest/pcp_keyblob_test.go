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
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/google/go-tpm/legacy/tpm2"
)

func Test_decodeKeyBlob(t *testing.T) {
	t.Run("ec", func(t *testing.T) {
		keyBlob, err := hex.DecodeString("5043504d3800000002000000020000007a000000600000000000000000000000b0000000000000000000000000000000000000000000000000780023000b0005047200209dffcbf36c383ae699fb9868dc6dcb89d7153884be2803922c124158bfad22ae0010001800040003001000204840871a2c3a17f0f4179136e31d8b946b74642157aaa5da60563bb27226d70b0020de3e38cdd66824f314fdf1c2b5e8584cc62cca99e02e59f17d849c41ce9cb1fa005e0020ba6e79db313d693284336cbf4e06f3cba14fa323d777979d6096c3c0e3a9bd2b00100af95d11f1d0d333e4b8ac45b8f5797df55ba79967d0f9d6bb20e6a8739724e8da960ab915ee7b0e9e1f1d9bd6387f5215cf2276bfffc0c03ea20000000600208fcd2169ab92694e0c633f1ab772842b8241bbc20288981fc7ac1eddc1fddb0e0020e529f5d6112872954e8ed6605117b757e237c6e19513a949fee1f204c458023a0020af2ca569699c436a21006f1cb8a2756c98bc1c765a3559c5fe1c3f5e7228a7e70020c413a847b11112b1cbddd4eca4daaa15a1852c1c3bba57461d257605f3d5af5300000020048e9a3ace08583f79f344ff785bbea9f07ac7fa3325b3d49a21dd5194c65850")
		if err != nil {
			t.Fatalf("decoding EC key blob failed: %v", err)
		}

		ecKey, err := decodeKeyBlob(keyBlob)
		if err != nil {
			t.Fatalf("decodeKeyBlob returned unexpected error: %v", err)
		}

		tpmPub, err := tpm2.DecodePublic(ecKey.pub)
		if err != nil {
			t.Fatalf("tpm2.DecodePublic() returned unexpected error: %v", err)
		}

		pub, err := tpmPub.Key()
		if err != nil {
			t.Fatalf("tpmPub.Key() returned unexpected error: %v", err)
		}

		if _, ok := pub.(*ecdsa.PublicKey); !ok {
			t.Fatalf("expected *ecdsa.PublicKey; got %T", pub)
		}

		if len(ecKey.priv) != 94 {
			t.Fatalf("expected EC private key blob to be 94 bytes; got %d bytes", len(ecKey.priv))
		}
	})

	t.Run("rsa", func(t *testing.T) {
		keyBlob, err := hex.DecodeString("5043504d3800000002000000020000003a010000c00000000000000000000000b0000000000000000000000000000000000000000000000001380001000b0005047200209dffcbf36c383ae699fb9868dc6dcb89d7153884be2803922c124158bfad22ae0010001400040800000000000100bfe0b258d7183265e4817653f2b619c86712cfca6e4d761e36498785cd7df222d8f64d18931ee79a0dc783ad33277cc96ca54d1409afecef62e2954efc6ddd449f3c9df182d04e4678bec4e0f865ec4ce23789a9c346afd098c89caf58d091c6099f4326da1cddb331f63bc5442e1d244d87bdd1d2bdf0a27fa8dc7f3b242679c27daebbe0515092fca38b0f33103a05e2a892c74a8e36181b896b5ce41f187ee8e3fa0e5d324d2aa52a00cc6f7d30e7afd648e6d509e62450975c9a20dcdb2b5d2b57c2430598e733373225d92f8b8a827ae2f23e14d7b8a52a1d48ecaf713773501e08ffc903878b0a3843e9b6af93497adbac8b509b5ddad4b0b4b8809bc100be0020bbdde4b61dbb8f71ddbb32626c43546643ce88fd9aed7f6f45f33fda43da7b4f00108b40bb832e0d11956f344b43c5525b0af620965fd308d341fc65763ea650a1f24e94693dd8306ec6fa49bcdf1ca71dc1e5c55759b3d7e933ac259c06438ec3ed3ef5903316f65f3b8ca3c3a4bb86f551911a535108979a007828d8f1020a596d63f36db8b438b114f21dab31299c081d9e450415c81940248dce63a9faee2e23fc03db16e0c4af2626a9f09beb5f07f945e6e52f8acd4bef393d0000000600208fcd2169ab92694e0c633f1ab772842b8241bbc20288981fc7ac1eddc1fddb0e0020e529f5d6112872954e8ed6605117b757e237c6e19513a949fee1f204c458023a0020af2ca569699c436a21006f1cb8a2756c98bc1c765a3559c5fe1c3f5e7228a7e70020c413a847b11112b1cbddd4eca4daaa15a1852c1c3bba57461d257605f3d5af5300000020048e9a3ace08583f79f344ff785bbea9f07ac7fa3325b3d49a21dd5194c65850")
		if err != nil {
			t.Fatalf("decoding RSA key blob failed: %v", err)
		}

		rsaKey, err := decodeKeyBlob(keyBlob)
		if err != nil {
			t.Fatalf("decodeKeyBlob returned unexpected error: %v", err)
		}

		tpmPub, err := tpm2.DecodePublic(rsaKey.pub)
		if err != nil {
			t.Fatalf("tpm2.DecodePublic() returned unexpected error: %v", err)
		}

		pub, err := tpmPub.Key()
		if err != nil {
			t.Fatalf("tpmPub.Key() returned unexpected error: %v", err)
		}

		if _, ok := pub.(*rsa.PublicKey); !ok {
			t.Fatalf("expected *rsa.PublicKey; got %T", pub)
		}

		if len(rsaKey.priv) != 190 {
			t.Fatalf("expected RSA private key blob to be 190 bytes; got %d bytes", len(rsaKey.priv))
		}
	})
}

func newKeyBlob(t *testing.T, header keyBlobHeader, body []byte) []byte {
	t.Helper()

	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, header); err != nil {
		t.Fatalf("binary.Write() returned unexpected error: %v", err)
	}
	buf.Write(body)

	return buf.Bytes()
}

func Test_decodeKeyBlob_errors(t *testing.T) {
	// validHeader describes a blob with a 4 byte gap between the header and the
	// public area, mirroring the padding the real key blobs contain.
	validHeader := keyBlobHeader{
		Magic:      pcpKeyMagic,
		HeaderSize: uint32(keyBlobHeaderSize) + 4,
		PubLen:     6,
		PrivLen:    6,
	}
	validBody := make([]byte, 4+6+6)

	// Guard against the negative cases below passing for the wrong reason.
	if _, err := decodeKeyBlob(newKeyBlob(t, validHeader, validBody)); err != nil {
		t.Fatalf("decodeKeyBlob returned unexpected error for valid blob: %v", err)
	}

	withHeader := func(mutate func(*keyBlobHeader)) keyBlobHeader {
		header := validHeader
		mutate(&header)
		return header
	}

	tests := []struct {
		name    string
		keyBlob []byte
		wantErr string
	}{
		{
			name:    "empty",
			keyBlob: nil,
			wantErr: "failed to read header",
		},
		{
			name:    "truncated-header",
			keyBlob: newKeyBlob(t, validHeader, nil)[:keyBlobHeaderSize-1],
			wantErr: "failed to read header",
		},
		{
			name:    "invalid-magic",
			keyBlob: newKeyBlob(t, withHeader(func(h *keyBlobHeader) { h.Magic = 0xDEADBEEF }), validBody),
			wantErr: "invalid header magic DEADBEEF",
		},
		{
			// A header size below keyBlobHeaderSize used to seek backwards, so
			// that the header itself was returned as key material.
			name:    "header-size-too-small",
			keyBlob: newKeyBlob(t, withHeader(func(h *keyBlobHeader) { h.HeaderSize = 0 }), validBody),
			wantErr: "invalid header size 0; expected at least 52",
		},
		{
			name:    "public-key-length-too-small",
			keyBlob: newKeyBlob(t, withHeader(func(h *keyBlobHeader) { h.PubLen = 1 }), validBody),
			wantErr: "invalid public key length 1; expected at least 2",
		},
		{
			// Used to allocate a buffer of the declared size before discovering
			// the blob could not possibly contain that many bytes.
			name:    "public-key-length-too-large",
			keyBlob: newKeyBlob(t, withHeader(func(h *keyBlobHeader) { h.PubLen = 1 << 30 }), validBody),
			wantErr: "invalid public key length 1073741824; only 12 bytes remaining",
		},
		{
			name:    "private-blob-length-too-small",
			keyBlob: newKeyBlob(t, withHeader(func(h *keyBlobHeader) { h.PrivLen = 1 }), validBody),
			wantErr: "invalid private blob length 1; expected at least 2",
		},
		{
			name:    "private-blob-length-too-large",
			keyBlob: newKeyBlob(t, withHeader(func(h *keyBlobHeader) { h.PrivLen = 1 << 30 }), validBody),
			wantErr: "invalid private blob length 1073741824; only 6 bytes remaining",
		},
		{
			name:    "truncated-body",
			keyBlob: newKeyBlob(t, validHeader, validBody[:len(validBody)-1]),
			wantErr: "invalid private blob length 6; only 5 bytes remaining",
		},
		{
			name:    "header-size-past-end",
			keyBlob: newKeyBlob(t, withHeader(func(h *keyBlobHeader) { h.HeaderSize = 1 << 30 }), validBody),
			wantErr: "invalid public key length 6; only 0 bytes remaining",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			kp, err := decodeKeyBlob(tc.keyBlob)
			if err == nil {
				t.Fatalf("decodeKeyBlob returned %+v; want error %q", kp, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("decodeKeyBlob returned error %q; want it to contain %q", err, tc.wantErr)
			}
			if kp != nil {
				t.Errorf("decodeKeyBlob returned %+v alongside an error; want nil", kp)
			}
		})
	}
}
