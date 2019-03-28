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

// +build windows

package attest

import (
	"crypto"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	tpmtbs "github.com/google/go-tpm/tpmutil/tbs"
)

// TPM interfaces with a TPM device on the system.
type TPM struct {
	version TPMVersion
	pcp     *winPCP
}

func probeSystemTPMs() ([]probedTPM, error) {
	// Windows systems appear to only support a single abstracted TPM.
	// If we fail to initialize the Platform Crypto Provider, we assume
	// a TPM is not present.
	pcp, err := openPCP()
	if err != nil {
		return nil, nil
	}
	defer pcp.Close()

	info, err := pcp.TPMInfo()
	if err != nil {
		return nil, err
	}

	var out probedTPM
	out.Version, err = tbsConvertVersion(info.TBSInfo)
	if err != nil {
		return nil, err
	}

	return []probedTPM{out}, nil
}

func tbsConvertVersion(info tbsDeviceInfo) (TPMVersion, error) {
	switch info.TPMVersion {
	case 1:
		return TPMVersion12, nil
	case 2:
		return TPMVersion20, nil
	default:
		return TPMVersionAgnostic, fmt.Errorf("TBSInfo.TPMVersion %d unsupported", info.TPMVersion)
	}
}

func openTPM(tpm probedTPM) (*TPM, error) {
	pcp, err := openPCP()
	if err != nil {
		return nil, err
	}

	info, err := pcp.TPMInfo()
	if err != nil {
		return nil, err
	}
	vers, err := tbsConvertVersion(info.TBSInfo)
	if err != nil {
		return nil, err
	}

	return &TPM{
		pcp:     pcp,
		version: vers,
	}, nil
}

// Close shuts down the connection to the TPM.
func (t *TPM) Close() error {
	return t.pcp.Close()
}

// Info returns information about the TPM.
func (t *TPM) Info() (*TPMInfo, error) {
	if t.version != TPMVersion20 {
		return nil, ErrTPM12NotImplemented
	}

	tpm, err := t.pcp.TPMCommandInterface()
	if err != nil {
		return nil, err
	}
	manufacturer, vendorInfo, err := readTPM2VendorAttributes(tpm)
	if err != nil {
		return nil, err
	}

	return &TPMInfo{
		Version:      t.version,
		Interface:    TPMInterfaceKernelManaged,
		VendorInfo:   vendorInfo,
		Manufacturer: manufacturer,
	}, nil
}

// EKs returns the Endorsement Keys burned-in to the platform.
func (t *TPM) EKs() ([]PlatformEK, error) {
	ekCerts, err := t.pcp.EKCerts()
	if err != nil {
		return nil, fmt.Errorf("could not read EKCerts from PCP: %v", err)
	}

	var out []PlatformEK
	for _, cert := range ekCerts {
		out = append(out, PlatformEK{cert, cert.PublicKey})
	}

	// TODO(jsonp): Fallback to reading PCP_RSA_EKPUB/PCP_ECC_EKPUB, and maybe direct.
	// if len(out) == 0 {
	//   ...
	// }

	return out, nil
}

// Key represents a key bound to the TPM.
type Key struct {
	hnd         uintptr
	KeyEncoding KeyEncoding
	TPMVersion  TPMVersion
	Purpose     KeyPurpose

	PCPKeyName        string
	Public            []byte
	CreateData        []byte
	CreateAttestation []byte
	CreateSignature   []byte
}

// Marshal represents the key in a persistent format which may be
// loaded at a later time using tpm.LoadKey().
func (k *Key) Marshal() ([]byte, error) {
	return json.Marshal(k)
}

// ActivateCredential decrypts the specified credential using key.
// This operation is synonymous with TPM2_ActivateCredential.
func (k *Key) ActivateCredential(tpm *TPM, in EncryptedCredential) ([]byte, error) {
	if tpm.version != TPMVersion20 {
		return nil, ErrTPM12NotImplemented
	}
	return tpm.pcp.ActivateCredential(k.hnd, append(in.Credential, in.Secret...))
}

// Quote returns a quote over the platform state, signed by the key.
func (k *Key) Quote(t *TPM, nonce []byte, alg tpm2.Algorithm) (*Quote, error) {
	if t.version != TPMVersion20 {
		return nil, ErrTPM12NotImplemented
	}
	tpm, err := t.pcp.TPMCommandInterface()
	if err != nil {
		return nil, fmt.Errorf("TPMCommandInterface() failed: %v", err)
	}
	tpmKeyHnd, err := t.pcp.TPMKeyHandle(k.hnd)
	if err != nil {
		return nil, fmt.Errorf("TPMKeyHandle() failed: %v", err)
	}
	return quote20(tpm, tpmKeyHnd, alg, nonce)
}

// Close frees any resources associated with the key.
func (k *Key) Close(tpm *TPM) error {
	return closeNCryptObject(k.hnd)
}

// MintAIK creates a persistent attestation key. The returned key must be
// closed with a call to key.Close() when the caller has finished using it.
func (t *TPM) MintAIK(opts *MintOptions) (*Key, error) {
	if t.version != TPMVersion20 {
		return nil, ErrTPM12NotImplemented
	}

	nameHex := make([]byte, 5)
	if n, err := rand.Read(nameHex); err != nil || n != len(nameHex) {
		return nil, fmt.Errorf("rand.Read() failed with %d/%d bytes read and error: %v", n, len(nameHex), err)
	}
	name := fmt.Sprintf("aik-%x", nameHex)

	kh, err := t.pcp.MintAIK(name)
	if err != nil {
		return nil, fmt.Errorf("pcp failed to mint attestation key: %v", err)
	}
	props, err := t.pcp.AIKProperties(kh)
	if err != nil {
		closeNCryptObject(kh)
		return nil, fmt.Errorf("pcp failed to read attestation key properties: %v", err)
	}

	return &Key{
		hnd:               kh,
		KeyEncoding:       KeyEncodingOSManaged,
		TPMVersion:        t.version,
		Purpose:           AttestationKey,
		PCPKeyName:        name,
		Public:            props.RawPublic,
		CreateData:        props.RawCreationData,
		CreateAttestation: props.RawAttest,
		CreateSignature:   props.RawSignature,
	}, nil
}

// LoadKey loads a previously-created key into the TPM for use.
// A key loaded via this function needs to be closed with .Close().
func (t *TPM) LoadKey(opaqueBlob []byte) (*Key, error) {
	var k Key
	var err error
	if err = json.Unmarshal(opaqueBlob, &k); err != nil {
		return nil, fmt.Errorf("Unmarshal failed: %v", err)
	}

	if k.TPMVersion != t.version {
		return nil, errors.New("key TPM version does not match opened TPM")
	}
	if k.KeyEncoding != KeyEncodingOSManaged {
		return nil, fmt.Errorf("unsupported key encoding: %x", k.KeyEncoding)
	}
	if k.Purpose != AttestationKey {
		return nil, fmt.Errorf("unsupported key kind: %x", k.Purpose)
	}

	if k.hnd, err = t.pcp.LoadKeyByName(k.PCPKeyName); err != nil {
		return nil, fmt.Errorf("pcp failed to load key: %v", err)
	}
	return &k, nil
}

// PCRs returns the present value of all Platform Configuration Registers.
func (t *TPM) PCRs() (map[int]PCR, tpm2.Algorithm, error) {
	if t.version != TPMVersion20 {
		return nil, 0, ErrTPM12NotImplemented
	}
	tpm, err := t.pcp.TPMCommandInterface()
	if err != nil {
		return nil, 0, fmt.Errorf("TPMCommandInterface() failed: %v", err)
	}
	PCRs, alg, err := allPCRs20(tpm)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read PCRs: %v", err)
	}

	out := map[int]PCR{}
	var lastAlg crypto.Hash
	for index, digest := range PCRs {
		out[int(index)] = PCR{
			Index:     int(index),
			Digest:    digest,
			DigestAlg: alg,
		}
		lastAlg = alg
	}

	switch lastAlg {
	case crypto.SHA1:
		return out, tpm2.AlgSHA1, nil
	case crypto.SHA256:
		return out, tpm2.AlgSHA256, nil
	default:
		return nil, 0, fmt.Errorf("unexpected algorithm: %v", lastAlg)
	}
}

// MeasurementLog returns the present value of the System Measurement Log.
func (t *TPM) MeasurementLog() ([]byte, error) {
	context, err := tpmtbs.CreateContext(tpmtbs.TPMVersion20, tpmtbs.IncludeTPM20)
	if err != nil {
		return nil, err
	}
	defer context.Close()

	// Run command first with nil buffer to get required buffer size.
	logLen, err := context.GetTCGLog(nil)
	if err != nil {
		return nil, err
	}
	logBuffer := make([]byte, logLen)
	if _, err = context.GetTCGLog(logBuffer); err != nil {
		return nil, err
	}
	return logBuffer, nil
}
