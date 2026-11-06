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
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

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

	// Deterministic P-256 point whose X and Y coordinates both start with 0x00,
	// exercising fixed-width 32-byte big-endian coordinate slicing.
	var leadingZeroScalar [32]byte
	leadingZeroScalar[30] = 0xc0
	leadingZeroScalar[31] = 0xc6
	ecdhPriv, err := ecdh.P256().NewPrivateKey(leadingZeroScalar[:])
	if err != nil {
		t.Fatalf("ecdh.P256().NewPrivateKey() failed: %v", err)
	}
	leadingZeroP256Pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), ecdhPriv.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("ecdsa.ParseUncompressedPublicKey() failed: %v", err)
	}

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
