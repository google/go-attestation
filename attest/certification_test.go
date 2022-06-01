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

//go:build (!localtest || !tpm12) && cgo && !gofuzz
// +build !localtest !tpm12
// +build cgo
// +build !gofuzz

package attest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/go-tpm/tpm2"
)

func TestSimTPM20CertificationParameters(t *testing.T) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()
	testCertificationParameters(t, tpm)
}

func TestTPM20CertificationParameters(t *testing.T) {
	if !*testLocal {
		t.SkipNow()
	}
	tpm, err := OpenTPM(nil)
	if err != nil {
		t.Fatalf("OpenTPM() failed: %v", err)
	}
	defer tpm.Close()
	testCertificationParameters(t, tpm)
}

func testCertificationParameters(t *testing.T, tpm *TPM) {
	ak, err := tpm.NewAK(nil)
	if err != nil {
		t.Fatal(err)
	}
	akAttestParams := ak.AttestationParameters()
	pub, err := tpm2.DecodePublic(akAttestParams.Public)
	if err != nil {
		t.Fatal(err)
	}
	if pub.Type != tpm2.AlgRSA {
		t.Fatal("non-RSA verifying key")
	}

	pk := &rsa.PublicKey{E: int(pub.RSAParameters.Exponent()), N: pub.RSAParameters.Modulus()}
	hash, err := pub.RSAParameters.Sign.Hash.Hash()
	if err != nil {
		t.Fatal(err)
	}
	correctOpts := VerifyOpts{
		Public: pk,
		Hash:   hash,
	}

	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	wrongHash := crypto.SHA512_256
	if wrongHash == correctOpts.Hash {
		wrongHash = crypto.SHA256
	}

	sk, err := tpm.NewKey(ak, nil)
	if err != nil {
		t.Fatal(err)
	}
	skCertParams := sk.CertificationParameters()

	for _, test := range []struct {
		name string
		p    *CertificationParameters
		opts VerifyOpts
		err  error
	}{
		{
			name: "OK",
			p:    &skCertParams,
			opts: correctOpts,
			err:  nil,
		},
		{
			name: "wrong public key",
			p:    &skCertParams,
			opts: VerifyOpts{
				Public: wrongKey.Public,
				Hash:   correctOpts.Hash,
			},
			err: cmpopts.AnyError,
		},
		{
			name: "wrong hash function",
			p:    &skCertParams,
			opts: VerifyOpts{
				Public: correctOpts.Public,
				Hash:   wrongHash,
			},
			err: cmpopts.AnyError,
		},
		{
			name: "unavailable hash function",
			p:    &skCertParams,
			opts: VerifyOpts{
				Public: correctOpts.Public,
				Hash:   crypto.BLAKE2b_384,
			},
			err: cmpopts.AnyError,
		},
		{
			name: "modified Public",
			p: &CertificationParameters{
				Public:            akAttestParams.Public,
				CreateAttestation: skCertParams.CreateAttestation,
				CreateSignature:   skCertParams.CreateSignature,
			},
			opts: correctOpts,
			err:  cmpopts.AnyError,
		},
		{
			name: "modified CreateAttestation",
			p: &CertificationParameters{
				Public:            skCertParams.Public,
				CreateAttestation: akAttestParams.CreateAttestation,
				CreateSignature:   skCertParams.CreateSignature,
			},
			opts: correctOpts,
			err:  cmpopts.AnyError,
		},
		{
			name: "modified CreateSignature",
			p: &CertificationParameters{
				Public:            skCertParams.Public,
				CreateAttestation: skCertParams.CreateAttestation,
				CreateSignature:   akAttestParams.CreateSignature,
			},
			opts: correctOpts,
			err:  cmpopts.AnyError,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := test.p.Verify(test.opts)
			if test.err == nil && err == nil {
				return
			}
			if got, want := err, test.err; !cmp.Equal(got, want, cmpopts.EquateErrors()) {
				t.Errorf("p.Verify() err = %v, want = %v", got, want)
			}
		})
	}
}

func TestSimTPM20KeyCertification(t *testing.T) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()
	testKeyCertification(t, tpm)
}

func TestTPM20KeyCertification(t *testing.T) {
	if !*testLocal {
		t.SkipNow()
	}
	tpm, err := OpenTPM(nil)
	if err != nil {
		t.Fatalf("OpenTPM() failed: %v", err)
	}
	defer tpm.Close()
	testKeyCertification(t, tpm)
}

func testKeyCertification(t *testing.T, tpm *TPM) {
	ak, err := tpm.NewAK(nil)
	if err != nil {
		t.Fatalf("NewAK() failed: %v", err)
	}
	akAttestParams := ak.AttestationParameters()
	pub, err := tpm2.DecodePublic(akAttestParams.Public)
	if err != nil {
		t.Fatalf("DecodePublic() failed: %v", err)
	}
	pk := &rsa.PublicKey{E: int(pub.RSAParameters.Exponent()), N: pub.RSAParameters.Modulus()}
	hash, err := pub.RSAParameters.Sign.Hash.Hash()
	if err != nil {
		t.Fatalf("cannot access AK's hash function: %v", err)
	}
	verifyOpts := VerifyOpts{
		Public: pk,
		Hash:   hash,
	}
	for _, test := range []struct {
		name string
		opts *KeyConfig
		err  error
	}{
		{
			name: "default",
			opts: nil,
			err:  nil,
		},
		{
			name: "ECDSAP256-SHA256",
			opts: &KeyConfig{
				Algorithm: ECDSA,
				Size:      256,
			},
			err: nil,
		},
		{
			name: "ECDSAP384-SHA384",
			opts: &KeyConfig{
				Algorithm: ECDSA,
				Size:      384,
			},
			err: nil,
		},
		{
			name: "ECDSAP521-SHA512",
			opts: &KeyConfig{
				Algorithm: ECDSA,
				Size:      521,
			},
			err: nil,
		},
		{
			name: "RSA-1024, key too short",
			opts: &KeyConfig{
				Algorithm: RSA,
				Size:      1024,
			},
			err: cmpopts.AnyError,
		},
		{
			name: "RSA-2048",
			opts: &KeyConfig{
				Algorithm: RSA,
				Size:      2048,
			},
			err: nil,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			sk, err := tpm.NewKey(ak, test.opts)
			if err != nil {
				t.Fatalf("NewKey() failed: %v", err)
			}
			defer sk.Close()
			p := sk.CertificationParameters()
			err = p.Verify(verifyOpts)
			if test.err == nil && err == nil {
				return
			}
			if got, want := err, test.err; !cmp.Equal(got, want, cmpopts.EquateErrors()) {
				t.Errorf("p.Verify() err = %v, want = %v", got, want)
			}
		})
	}
}
