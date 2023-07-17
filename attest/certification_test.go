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
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/go-tpm/legacy/tpm2"
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

func TestKeyActivationTPM20(t *testing.T) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()

	ak, err := tpm.NewAK(nil)
	if err != nil {
		t.Fatalf("error creating a new AK using simulated TPM: %v", err)
	}
	akAttestParams := ak.AttestationParameters()
	pub, err := tpm2.DecodePublic(akAttestParams.Public)
	if err != nil {
		t.Fatalf("unable to decode public struct from AK attestation params: %v", err)
	}
	if pub.Type != tpm2.AlgRSA {
		t.Fatal("non-RSA verifying key")
	}

	eks, err := tpm.EKs()
	if err != nil {
		t.Fatalf("unexpected error retrieving EK from tpm: %v", err)
	}

	if len(eks) == 0 {
		t.Fatal("expected at least one EK from the simulated TPM")
	}

	pk := &rsa.PublicKey{E: int(pub.RSAParameters.Exponent()), N: pub.RSAParameters.Modulus()}
	hash, err := pub.RSAParameters.Sign.Hash.Hash()
	if err != nil {
		t.Fatalf("unable to compute hash signature from verifying key's RSA parameters: %v", err)
	}
	verifyOpts := VerifyOpts{
		Public: pk,
		Hash:   hash,
	}

	sk, err := tpm.NewKey(ak, nil)
	if err != nil {
		t.Fatalf("unable to create a new TPM-backed key to certify: %v", err)
	}

	skCertParams := sk.CertificationParameters()
	activateOpts, err := NewActivateOpts(pub, eks[0].Public)
	if err != nil {
		t.Fatalf("unable to create new ActivateOpts: %v", err)
	}

	wrongPub, err := tpm2.DecodePublic(skCertParams.Public)
	if err != nil {
		t.Fatalf("unable to decode public struct from CertificationParameters: %v", err)
	}

	wrongActivateOpts, err := NewActivateOpts(wrongPub, eks[0].Public)
	if err != nil {
		t.Fatalf("unable to create wrong ActivateOpts: %v", err)
	}

	for _, test := range []struct {
		name         string
		p            *CertificationParameters
		verifyOpts   VerifyOpts
		activateOpts ActivateOpts
		generateErr  error
		activateErr  error
	}{
		{
			name:         "OK",
			p:            &skCertParams,
			verifyOpts:   verifyOpts,
			activateOpts: *activateOpts,
			generateErr:  nil,
			activateErr:  nil,
		},
		{
			name:         "invalid verify opts",
			p:            &skCertParams,
			verifyOpts:   VerifyOpts{},
			activateOpts: *activateOpts,
			generateErr:  cmpopts.AnyError,
			activateErr:  nil,
		},
		{
			name:         "invalid activate opts",
			p:            &skCertParams,
			verifyOpts:   verifyOpts,
			activateOpts: *wrongActivateOpts,
			generateErr:  nil,
			activateErr:  cmpopts.AnyError,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			expectedSecret, encryptedCredentials, err := test.p.Generate(rand.Reader, test.verifyOpts, test.activateOpts)
			if test.generateErr != nil {
				if got, want := err, test.generateErr; !cmp.Equal(got, want, cmpopts.EquateErrors()) {
					t.Errorf("p.Generate() err = %v, want = %v", got, want)
				}

				return
			} else if err != nil {
				t.Errorf("unexpected p.Generate() error: %v", err)
				return
			}

			actualSecret, err := ak.ActivateCredential(tpm, *encryptedCredentials)
			if test.activateErr != nil {
				if got, want := err, test.activateErr; !cmp.Equal(got, want, cmpopts.EquateErrors()) {
					t.Errorf("p.ActivateCredential() err = %v, want = %v", got, want)
				}

				return
			} else if err != nil {
				t.Errorf("unexpected p.ActivateCredential() error: %v", err)
				return
			}

			if !bytes.Equal(expectedSecret, actualSecret) {
				t.Fatalf("Unexpected bytes decoded, expected %x, but got %x", expectedSecret, actualSecret)
			}
		})
	}
}
