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

//go:build !localtest && cgo && !gofuzz && !windows
// +build !localtest,cgo,!gofuzz,!windows

// NOTE: simulator requires cgo, hence the build tag. The simulator does not
// build on Windows.

package attest

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/go-tpm/legacy/tpm2"
)

func TestSimCertificationParametersRSA(t *testing.T) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()
	testCertificationParameters(t, tpm, RSA)
}

func TestSimCertificationParametersECC(t *testing.T) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()
	testCertificationParameters(t, tpm, ECDSA)
}

func TestSimKeyCertificationRSA(t *testing.T) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()
	testKeyCertification(t, tpm, RSA)
}

func TestSimKeyCertificationECC(t *testing.T) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()
	testKeyCertification(t, tpm, ECDSA)
}

func TestSimKeyCertificationQualifyingDataRSA(t *testing.T) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()
	testKeyCertificationQualifyingData(t, tpm, RSA)
}

func TestSimKeyCertificationQualifyingDataECC(t *testing.T) {
	sim, tpm := setupSimulatedTPM(t)
	defer sim.Close()
	testKeyCertificationQualifyingData(t, tpm, ECDSA)
}

// testKeyCertificationQualifyingData checks that Verify matches the qualifying
// data embedded in a certification against VerifyOpts.QualifyingData so a
// verifier can bind a certification to a challenge it issued.
func testKeyCertificationQualifyingData(t *testing.T, tpm *TPM, akAlg Algorithm) {
	ak, err := tpm.NewAK(&AKConfig{Algorithm: akAlg})
	if err != nil {
		t.Fatalf("NewAK() failed: %v", err)
	}
	pub, err := tpm2.DecodePublic(ak.AttestationParameters().Public)
	if err != nil {
		t.Fatalf("DecodePublic() failed: %v", err)
	}
	pk, err := pub.Key()
	if err != nil {
		t.Fatalf("pub.Key() failed: %v", err)
	}
	hash, err := pub.NameAlg.Hash()
	if err != nil {
		t.Fatalf("cannot access AK's hash function: %v", err)
	}

	nonce := []byte("verifier issued challenge")
	sk, err := tpm.NewKey(ak, &KeyConfig{Algorithm: ECDSA, Size: 256, QualifyingData: nonce})
	if err != nil {
		t.Fatalf("NewKey() failed: %v", err)
	}
	defer sk.Close()
	p := sk.CertificationParameters()

	for _, test := range []struct {
		name           string
		qualifyingData []byte
		err            error
	}{
		{name: "unchecked", qualifyingData: nil, err: nil},
		{name: "matches", qualifyingData: nonce, err: nil},
		{name: "mismatch", qualifyingData: []byte("different challenge"), err: cmpopts.AnyError},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := p.Verify(VerifyOpts{Public: pk, Hash: hash, QualifyingData: test.qualifyingData})
			if got, want := err, test.err; !cmp.Equal(got, want, cmpopts.EquateErrors()) {
				t.Errorf("p.Verify() err = %v, want = %v", got, want)
			}
		})
	}
}

func TestKeyActivation(t *testing.T) {
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
			}
			if err != nil {
				t.Errorf("unexpected p.Generate() error: %v", err)
				return
			}

			actualSecret, err := ak.ActivateCredential(tpm, *encryptedCredentials)
			if test.activateErr != nil {
				if got, want := err, test.activateErr; !cmp.Equal(got, want, cmpopts.EquateErrors()) {
					t.Errorf("p.ActivateCredential() err = %v, want = %v", got, want)
				}

				return
			}
			if err != nil {
				t.Errorf("unexpected p.ActivateCredential() error: %v", err)
				return
			}

			if !bytes.Equal(expectedSecret, actualSecret) {
				t.Fatalf("Unexpected bytes decoded, expected %x, but got %x", expectedSecret, actualSecret)
			}
		})
	}
}
