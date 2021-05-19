// Copyright 2021 Google Inc.
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

// +build !localtest !tpm12
// +build cgo

// NOTE: simulator requires cgo, hence the build tag.

package attest

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"testing"
)

func TestSimTPM20KeyCreateAndLoad(t *testing.T) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()
	testKeyCreateAndLoad(t, tpm)
}

func TestTPM20KeyCreateAndLoad(t *testing.T) {
	if !*testLocal {
		t.SkipNow()
	}
	tpm, err := OpenTPM(nil)
	if err != nil {
		t.Fatalf("OpenTPM() failed: %v", err)
	}
	defer tpm.Close()
	testKeyCreateAndLoad(t, tpm)
}

func testKeyCreateAndLoad(t *testing.T, tpm *TPM) {
	ak, err := tpm.NewAK(nil)
	if err != nil {
		t.Fatalf("NewAK() failed: %v", err)
	}
	for _, test := range []struct {
		name string
		opts *KeyConfig
	}{
		{
			name: "default",
			opts: nil,
		},
		{
			name: "ECDSAP256-SHA256",
			opts: &KeyConfig{
				Algorithm: EC,
				Size:      256,
			},
		},
		{
			name: "ECDSAP384-SHA384",
			opts: &KeyConfig{
				Algorithm: EC,
				Size:      384,
			},
		},
		{
			name: "ECDSAP521-SHA512",
			opts: &KeyConfig{
				Algorithm: EC,
				Size:      521,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			sk, err := tpm.NewKey(ak, nil)
			if err != nil {
				t.Fatalf("NewKey() failed: %v", err)
			}
			defer sk.Close()

			enc, err := sk.Marshal()
			if err != nil {
				t.Fatalf("sk.Marshal() failed: %v", err)
			}
			if err := sk.Close(); err != nil {
				t.Fatalf("sk.Close() failed: %v", err)
			}

			loaded, err := tpm.LoadKey(enc)
			if err != nil {
				t.Fatalf("LoadKey() failed: %v", err)
			}
			defer loaded.Close()

			k1, k2 := sk.key.(*wrappedKey20), loaded.key.(*wrappedKey20)
			if !bytes.Equal(k1.public, k2.public) {
				t.Error("Original & loaded Key public blobs did not match.")
				t.Logf("Original = %v", k1.public)
				t.Logf("Loaded   = %v", k2.public)
			}

			priv1, err := sk.Private(sk.Public())
			if err != nil {
				t.Fatalf("sk.Private() failed: %v", err)
			}
			signer1, ok := priv1.(crypto.Signer)
			if !ok {
				t.Fatalf("want crypto.Signer, got %T", priv1)
			}
			pk1, err := x509.MarshalPKIXPublicKey(signer1.Public())
			if err != nil {
				t.Fatalf("cannot marshal public key: %v", err)
			}

			priv2, err := loaded.Private(loaded.Public())
			if err != nil {
				t.Fatalf("loaded.Private() failed: %v", err)
			}
			signer2, ok := priv2.(crypto.Signer)
			if !ok {
				t.Fatalf("want crypto.Signer, got %T", priv2)
			}
			pk2, err := x509.MarshalPKIXPublicKey(signer2.Public())
			if err != nil {
				t.Fatalf("cannot marshal public key: %v", err)
			}

			if !bytes.Equal(pk1, pk2) {
				t.Error("public keys do not match")
			}
		})
	}
}

func TestSimTPM20KeySign(t *testing.T) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()
	testKeySign(t, tpm)
}

func TestTPM20KeySign(t *testing.T) {
	if !*testLocal {
		t.SkipNow()
	}
	tpm, err := OpenTPM(nil)
	if err != nil {
		t.Fatalf("OpenTPM() failed: %v", err)
	}
	defer tpm.Close()
	testKeySign(t, tpm)
}

func testKeySign(t *testing.T, tpm *TPM) {
	ak, err := tpm.NewAK(nil)
	if err != nil {
		t.Fatalf("NewAK() failed: %v", err)
	}
	for _, test := range []struct {
		name   string
		opts   *KeyConfig
		digest []byte
	}{
		{
			name:   "default",
			opts:   nil,
			digest: []byte("12345678901234567890123456789012"),
		},
		{
			name: "ECDSAP256-SHA256",
			opts: &KeyConfig{
				Algorithm: EC,
				Size:      256,
			},
			digest: []byte("12345678901234567890123456789012"),
		},
		{
			name: "ECDSAP384-SHA384",
			opts: &KeyConfig{
				Algorithm: EC,
				Size:      384,
			},
			digest: []byte("123456789012345678901234567890121234567890123456"),
		},
		{
			name: "ECDSAP521-SHA512",
			opts: &KeyConfig{
				Algorithm: EC,
				Size:      521,
			},
			digest: []byte("1234567890123456789012345678901212345678901234567890123456789012"),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			sk, err := tpm.NewKey(ak, test.opts)
			if err != nil {
				t.Fatalf("NewKey() failed: %v", err)
			}
			defer sk.Close()

			pub := sk.Public()
			priv, err := sk.Private(pub)
			if err != nil {
				t.Fatalf("sk.Private() failed: %v", err)
			}
			signer, ok := priv.(crypto.Signer)
			if !ok {
				t.Fatalf("want crypto.Signer, got %T", priv)
			}
			sig, err := signer.Sign(rand.Reader, test.digest, nil)
			if err != nil {
				t.Fatalf("signer.Sign() failed: %v", err)
			}

			verifyECDSA(t, pub, test.digest, sig)
		})
	}
}

func verifyECDSA(t *testing.T, pub crypto.PublicKey, digest, sig []byte) {
	t.Helper()
	parsed := struct{ R, S *big.Int }{}
	_, err := asn1.Unmarshal(sig, &parsed)
	if err != nil {
		t.Fatalf("signature parsing failed: %v", err)
	}
	pubECDSA, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("want *ecdsa.PublicKey, got %T", pub)
	}
	if !ecdsa.Verify(pubECDSA, digest[:], parsed.R, parsed.S) {
		t.Fatalf("ecdsa.Verify() failed")
	}
}

func TestSimTPM20KeyOpts(t *testing.T) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()
	testKeyOpts(t, tpm)
}

func TestTPM20KeyOpts(t *testing.T) {
	if !*testLocal {
		t.SkipNow()
	}
	tpm, err := OpenTPM(nil)
	if err != nil {
		t.Fatalf("OpenTPM() failed: %v", err)
	}
	defer tpm.Close()
	testKeyOpts(t, tpm)
}

func testKeyOpts(t *testing.T, tpm *TPM) {
	ak, err := tpm.NewAK(nil)
	if err != nil {
		t.Fatalf("NewAK() failed: %v", err)
	}
	for _, test := range []struct {
		name string
		opts *KeyConfig
		err  bool
	}{
		{
			name: "wrong alg",
			opts: &KeyConfig{
				Algorithm: "fake alg",
			},
			err: true,
		},
		{
			name: "wrong size",
			opts: &KeyConfig{
				Algorithm: EC,
				Size:      1234,
			},
			err: true,
		},
		{
			name: "default",
			opts: nil,
			err:  false,
		},
		{
			name: "ECDSAP256",
			opts: &KeyConfig{
				Algorithm: EC,
				Size:      256,
			},
			err: false,
		},
		{
			name: "ECDSAP384",
			opts: &KeyConfig{
				Algorithm: EC,
				Size:      384,
			},
			err: false,
		},
		{
			name: "ECDSAP521",
			opts: &KeyConfig{
				Algorithm: EC,
				Size:      521,
			},
			err: false,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			sk, err := tpm.NewKey(ak, test.opts)
			if !test.err && err != nil {
				t.Fatalf("NewKey() failed: %v", err)
			}
			if test.err {
				if err == nil {
					sk.Close()
					t.Fatalf("NewKey(): expected err != nil")
				}
				return
			}
			defer sk.Close()

			expected := test.opts
			if expected == nil {
				expected = &DefaultConfig
			}

			pub := sk.Public()
			switch pub.(type) {
			case *ecdsa.PublicKey:
				if expected.Algorithm != EC {
					t.Errorf("incorrect key type generated, expected %q, got EC", expected.Algorithm)
				}
				sizeToCurve := map[int]elliptic.Curve{
					256: elliptic.P256(),
					384: elliptic.P384(),
					521: elliptic.P521(),
				}
				expectedCurve, ok := sizeToCurve[expected.Size]
				if !ok {
					t.Fatalf("cannot match curve to key size %d", expected.Size)
				}
				curve := pub.(*ecdsa.PublicKey).Curve
				if expectedCurve != curve {
					t.Errorf("incorrect curve, expected %v, got %v", expectedCurve, curve)
				}
			case *rsa.PublicKey:
				if expected.Algorithm != RSA {
					t.Errorf("incorrect key type, expected %q, got RSA", expected.Algorithm)
				}
				if pub.(*rsa.PublicKey).Size()*8 != expected.Size {
					t.Errorf("incorrect key size, expected %d, got %d", expected.Size, pub.(*rsa.PublicKey).Size()*8)
				}
			default:
				t.Errorf("unsupported key type: %T", pub)
			}
		})
	}
}
