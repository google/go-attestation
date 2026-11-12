// Copyright 2026 Google Inc.
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
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

// newLeadingZeroP256PublicKey returns a deterministic NIST P-256 public key
// (for scalar 0xc0c6 = 49350, the smallest positive P-256 scalar whose base
// point multiple has X[0] == 0x00 and Y[0] == 0x00) to exercise fixed-width
// 32-byte big-endian coordinate slicing for google/go-attestation#561.
func newLeadingZeroP256PublicKey(t *testing.T) (*ecdsa.PublicKey, []byte) {
	t.Helper()
	var scalar [32]byte
	scalar[30] = 0xc0
	scalar[31] = 0xc6
	ecdhPriv, err := ecdh.P256().NewPrivateKey(scalar[:])
	if err != nil {
		t.Fatalf("ecdh.P256().NewPrivateKey() failed: %v", err)
	}
	uncompressed := ecdhPriv.PublicKey().Bytes()
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), uncompressed)
	if err != nil {
		t.Fatalf("ecdsa.ParseUncompressedPublicKey() failed: %v", err)
	}
	return pub, uncompressed
}

func TestECDSAPublicKeyToTPMSECCPoint(t *testing.T) {
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey(P256) failed: %v", err)
	}
	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey(P384) failed: %v", err)
	}
	p521Key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey(P521) failed: %v", err)
	}
	p224Key, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey(P224) failed: %v", err)
	}
	leadingZeroP256Pub, leadingZeroRaw := newLeadingZeroP256PublicKey(t)

	mismatchedCurvePub := p256Key.PublicKey
	mismatchedCurvePub.Curve = elliptic.P384()

	for _, tc := range []struct {
		name        string
		pub         *ecdsa.PublicKey
		wantCurveID tpm2.TPMECCCurve
		wantSize    int
		wantX       []byte
		wantY       []byte
		wantErr     bool
	}{
		{
			name:        "ECC_P256",
			pub:         &p256Key.PublicKey,
			wantCurveID: tpm2.TPMECCNistP256,
			wantSize:    32,
		},
		{
			name:        "ECC_P256_LeadingZeroXY",
			pub:         leadingZeroP256Pub,
			wantCurveID: tpm2.TPMECCNistP256,
			wantSize:    32,
			wantX:       leadingZeroRaw[1:33],
			wantY:       leadingZeroRaw[33:65],
		},
		{
			name:        "ECC_P384",
			pub:         &p384Key.PublicKey,
			wantCurveID: tpm2.TPMECCNistP384,
			wantSize:    48,
		},
		{
			name:        "ECC_P521",
			pub:         &p521Key.PublicKey,
			wantCurveID: tpm2.TPMECCNistP521,
			wantSize:    66,
		},
		{name: "UnsupportedCurve_P224", pub: &p224Key.PublicKey, wantErr: true},
		{name: "InvalidPointNotOnCurve", pub: &mismatchedCurvePub, wantErr: true},
		{name: "NilECCCurve", pub: &ecdsa.PublicKey{}, wantErr: true},
		{name: "NilKey", pub: nil, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pt, curveID, err := ecdsaPublicKeyToTPMSECCPoint(tc.pub)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ecdsaPublicKeyToTPMSECCPoint() succeeded, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("ecdsaPublicKeyToTPMSECCPoint() failed: %v", err)
			}
			if curveID != tc.wantCurveID {
				t.Errorf("curveID = %v, want %v", curveID, tc.wantCurveID)
			}
			if len(pt.X.Buffer) != tc.wantSize || len(pt.Y.Buffer) != tc.wantSize {
				t.Fatalf("len(X)=%d len(Y)=%d, want %d", len(pt.X.Buffer), len(pt.Y.Buffer), tc.wantSize)
			}
			if cap(pt.X.Buffer) != len(pt.X.Buffer) {
				t.Errorf("cap(X.Buffer) = %d, want %d (must not alias Y.Buffer)", cap(pt.X.Buffer), len(pt.X.Buffer))
			}
			if tc.wantX != nil && !bytes.Equal(pt.X.Buffer, tc.wantX) {
				t.Errorf("X.Buffer = %x, want %x", pt.X.Buffer, tc.wantX)
			}
			if tc.wantY != nil && !bytes.Equal(pt.Y.Buffer, tc.wantY) {
				t.Errorf("Y.Buffer = %x, want %x", pt.Y.Buffer, tc.wantY)
			}
		})
	}
}

func TestGenerateEkChallenge(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() failed: %v", err)
	}
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey(P256) failed: %v", err)
	}
	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey(P384) failed: %v", err)
	}
	p521Key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey(P521) failed: %v", err)
	}
	p224Key, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey(P224) failed: %v", err)
	}
	leadingZeroP256Pub, _ := newLeadingZeroP256PublicKey(t)

	mismatchedCurvePub := p256Key.PublicKey
	mismatchedCurvePub.Curve = elliptic.P384()

	for _, tc := range []struct {
		name    string
		pub     crypto.PublicKey
		wantErr bool
	}{
		{name: "RSA2048", pub: &rsaKey.PublicKey},
		{name: "ECC_P256", pub: &p256Key.PublicKey},
		{name: "ECC_P256_LeadingZeroXY", pub: leadingZeroP256Pub},
		{name: "ECC_P384", pub: &p384Key.PublicKey},
		{name: "ECC_P521", pub: &p521Key.PublicKey},
		{name: "UnsupportedCurve_P224", pub: &p224Key.PublicKey, wantErr: true},
		{name: "InvalidPointNotOnCurve", pub: &mismatchedCurvePub, wantErr: true},
		{name: "NilECCCurve", pub: &ecdsa.PublicKey{}, wantErr: true},
		{name: "TypedNilECCKey", pub: (*ecdsa.PublicKey)(nil), wantErr: true},
		{name: "NilPublicKey", pub: nil, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			challenge, hmacKey, err := GenerateEkChallenge(tc.pub)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("GenerateEkChallenge() succeeded, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("GenerateEkChallenge() failed: %v", err)
			}
			if challenge == nil || len(challenge.ObjectPublic) == 0 || len(challenge.Duplicate) == 0 || len(challenge.InSymSeed) == 0 {
				t.Fatalf("GenerateEkChallenge() returned incomplete challenge: %+v", challenge)
			}
			if hmacKey == nil {
				t.Fatalf("GenerateEkChallenge() returned nil hmacKey")
			}
		})
	}
}
