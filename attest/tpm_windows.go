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
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/google/certificate-transparency-go/x509"
	tpm1 "github.com/google/go-tpm/tpm"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	tpmtbs "github.com/google/go-tpm/tpmutil/tbs"
	"golang.org/x/sys/windows/registry"
)

var wellKnownAuth [20]byte

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
		return nil, fmt.Errorf("TPMInfo() failed: %v", err)
	}

	var out probedTPM
	out.Version, err = tbsConvertVersion(info.TBSInfo)
	if err != nil {
		return nil, fmt.Errorf("tbsConvertVersion(%v) failed: %v", info.TBSInfo.TPMVersion, err)
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
		return nil, fmt.Errorf("openPCP() failed: %v", err)
	}

	info, err := pcp.TPMInfo()
	if err != nil {
		return nil, fmt.Errorf("TPMInfo() failed: %v", err)
	}
	vers, err := tbsConvertVersion(info.TBSInfo)
	if err != nil {
		return nil, fmt.Errorf("tbsConvertVersion(%v) failed: %v", info.TBSInfo.TPMVersion, err)
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

func readTPM12VendorAttributes(tpm io.ReadWriter) (TCGVendorID, string, error) {
	vendor, err := tpm1.GetManufacturer(tpm)
	if err != nil {
		return TCGVendorID(0), "", fmt.Errorf("tpm1.GetCapability failed: %v", err)
	}
	vendorID := TCGVendorID(binary.BigEndian.Uint32(vendor))
	return vendorID, vendorID.String(), nil
}

// Info returns information about the TPM.
func (t *TPM) Info() (*TPMInfo, error) {
	var manufacturer TCGVendorID
	var vendorInfo string
	var err error
	tpm, err := t.pcp.TPMCommandInterface()
	if err != nil {
		return nil, err
	}
	switch t.version {
	case TPMVersion12:
		manufacturer, vendorInfo, err = readTPM12VendorAttributes(tpm)
	case TPMVersion20:
		manufacturer, vendorInfo, err = readTPM2VendorAttributes(tpm)
	default:
		return nil, fmt.Errorf("unsupported TPM version: %x", t.version)
	}
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

func getOwnerAuth() ([20]byte, error) {
	var ret [20]byte
	regkey, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI\\Admin`, registry.QUERY_VALUE)
	if err != nil {
		return ret, err
	}
	defer regkey.Close()

	ownerAuthUTF16, _, err := regkey.GetStringValue("OwnerAuthFull")
	if err != nil {
		return ret, err
	}
	ownerAuthBytes, err := base64.StdEncoding.DecodeString(ownerAuthUTF16)
	if err != nil {
		return ret, err
	}
	if size := len(ownerAuthBytes); size != 20 {
		return ret, fmt.Errorf("OwnerAuth is an unexpected size: %d", size)
	}
	// Check OwnerAuthStatus first maybe?
	for i := range ret {
		ret[i] = ownerAuthBytes[i]
	}
	return ret, nil
}

func (t *TPM) readEKCert12() ([]*x509.Certificate, error) {
	tpm, err := t.pcp.TPMCommandInterface()
	if err != nil {
		return nil, err
	}
	ownAuth, err := getOwnerAuth()
	if err != nil {
		return nil, err
	}
	ekcert, err := tpm1.ReadEKCert(tpm, ownAuth)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(ekcert)
	if err != nil {
		return nil, err
	}
	return []*x509.Certificate{cert}, nil
}

// EKs returns the Endorsement Keys burned-in to the platform.
func (t *TPM) EKs() ([]PlatformEK, error) {
	var ekCerts []*x509.Certificate
	var err error
	switch t.version {
	case TPMVersion12:
		ekCerts, err = t.readEKCert12()

	case TPMVersion20:
		ekCerts, err = t.pcp.EKCerts()

	default:
		return nil, fmt.Errorf("unsupported TPM version: %x", t.version)
	}
	if err != nil {
		return nil, fmt.Errorf("could not read EKCerts: %v", err)
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
	hnd12       tpmutil.Handle
	KeyEncoding KeyEncoding
	TPMVersion  TPMVersion
	Purpose     KeyPurpose

	PCPKeyName        string
	KeyBlob           []byte
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
// This operation is synonymous with TPM2_ActivateCredential for TPM2.0
// and TPM_ActivateIdentity for TPM1.2.
func (k *Key) ActivateCredential(tpm *TPM, in EncryptedCredential) ([]byte, error) {
	if k.TPMVersion != tpm.version {
		return nil, fmt.Errorf("tpm and key version mismatch")
	}
	switch tpm.version {
	case TPMVersion12:
		rw, err := tpm.pcp.TPMCommandInterface()
		if err != nil {
			return nil, fmt.Errorf("pcp.TPMCommandInterface() failed: %v", err)
		}
		ownAuth, err := getOwnerAuth()
		if err != nil {
			return nil, fmt.Errorf("getOwnerAuth failed: %v", err)
		}
		return tpm1.ActivateIdentity(rw, wellKnownAuth[:], ownAuth[:], k.hnd12, in.Credential, in.Secret)
	case TPMVersion20:
		return tpm.pcp.ActivateCredential(k.hnd, append(in.Credential, in.Secret...))
	default:
		return nil, fmt.Errorf("unsupported TPM version: %x", tpm.version)
	}
}

func (k *Key) quote12(tpm io.ReadWriter, nonce []byte) (*Quote, error) {
	selectedPCRs := make([]int, 24)
	for _, pcr := range selectedPCRs {
		selectedPCRs[pcr] = pcr
	}

	sig, quote, err := tpm1.Quote(tpm, k.hnd12, nonce, selectedPCRs[:], wellKnownAuth[:])
	if err != nil {
		return nil, fmt.Errorf("Quote() failed: %v", err)
	}
	return &Quote{
		Quote:     quote,
		Signature: sig,
	}, nil
}

// Quote returns a quote over the platform state, signed by the key.
func (k *Key) Quote(t *TPM, nonce []byte, alg tpm2.Algorithm) (*Quote, error) {
	switch t.version {
	case TPMVersion12:
		tpm, err := t.pcp.TPMCommandInterface()
		if err != nil {
			return nil, fmt.Errorf("TPMCommandInterface() failed: %v", err)
		}
		return k.quote12(tpm, nonce)

	case TPMVersion20:
		tpm, err := t.pcp.TPMCommandInterface()
		if err != nil {
			return nil, fmt.Errorf("TPMCommandInterface() failed: %v", err)
		}
		tpmKeyHnd, err := t.pcp.TPMKeyHandle(k.hnd)
		if err != nil {
			return nil, fmt.Errorf("TPMKeyHandle() failed: %v", err)
		}
		return quote20(tpm, tpmKeyHnd, alg, nonce)

	default:
		return nil, fmt.Errorf("unsupported TPM version: %x", t.version)
	}
}

// Close frees any resources associated with the key.
func (k *Key) Close(tpm *TPM) error {
	switch tpm.version {
	case TPMVersion12:
		return nil
	case TPMVersion20:
		return closeNCryptObject(k.hnd)
	default:
		return fmt.Errorf("unsupported TPM version: %x", tpm.version)
	}
}

// MintAIK creates a persistent attestation key. The returned key must be
// closed with a call to key.Close() when the caller has finished using it.
func (t *TPM) MintAIK(opts *MintOptions) (*Key, error) {
	switch t.version {
	case TPMVersion12:
		tpm, err := t.pcp.TPMCommandInterface()
		if err != nil {
			return nil, err
		}
		ownAuth, err := getOwnerAuth()
		if err != nil {
			return nil, err
		}
		blob, err := tpm1.MakeIdentity(tpm, wellKnownAuth[:], ownAuth[:], wellKnownAuth[:], nil, nil)
		if err != nil {
			return nil, fmt.Errorf("MakeIdentityEx failed: %v", err)
		}
		hnd, err := tpm1.LoadKey2(tpm, blob, wellKnownAuth[:])
		if err != nil {
			return nil, fmt.Errorf("LoadKey2 failed: %v", err)
		}
		pub, err := tpm1.GetPubKey(tpm, hnd, wellKnownAuth[:])
		if err != nil {
			return nil, fmt.Errorf("GetPubKey failed: %v", err)
		}

		return &Key{
			hnd12:       hnd,
			KeyEncoding: KeyEncodingOSManaged,
			TPMVersion:  t.version,
			Purpose:     AttestationKey,
			KeyBlob:     blob,
			Public:      pub,
		}, nil

	case TPMVersion20:
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

	default:
		return nil, fmt.Errorf("unsupported TPM version: %x", t.version)
	}
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

	switch t.version {
	case TPMVersion12:
		tpm, err := t.pcp.TPMCommandInterface()
		if err != nil {
			return nil, fmt.Errorf("failed to get interface to TPM: %v", err)
		}
		if k.hnd12, err = tpm1.LoadKey2(tpm, k.KeyBlob, wellKnownAuth[:]); err != nil {
			return nil, fmt.Errorf("go-tpm failed to load key: %v", err)
		}

	case TPMVersion20:
		if k.hnd, err = t.pcp.LoadKeyByName(k.PCPKeyName); err != nil {
			return nil, fmt.Errorf("pcp failed to load key: %v", err)
		}

	default:
		return nil, fmt.Errorf("unsupported TPM version: %x", t.version)
	}
	return &k, nil
}

func allPCRs12(tpm io.ReadWriter) (map[uint32][]byte, error) {
	numPCRs := 24
	out := map[uint32][]byte{}

	for pcr := 0; pcr < numPCRs; pcr++ {
		pcrval, err := tpm1.ReadPCR(tpm, uint32(pcr))
		if err != nil {
			return nil, fmt.Errorf("tpm.ReadPCR() failed with err: %v", err)
		}
		out[uint32(pcr)] = pcrval
	}

	if len(out) != numPCRs {
		return nil, fmt.Errorf("failed to read all PCRs, only read %d", len(out))
	}

	return out, nil
}

// PCRs returns the present value of all Platform Configuration Registers.
func (t *TPM) PCRs() (map[int]PCR, tpm2.Algorithm, error) {
	var PCRs map[uint32][]byte
	var alg crypto.Hash
	switch t.version {
	case TPMVersion12:
		alg = crypto.SHA1
		tpm, err := t.pcp.TPMCommandInterface()
		if err != nil {
			return nil, 0, fmt.Errorf("TPMCommandInterface() failed: %v", err)
		}
		PCRs, err = allPCRs12(tpm)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to read PCRs: %v", err)
		}

	case TPMVersion20:
		tpm, err := t.pcp.TPMCommandInterface()
		if err != nil {
			return nil, 0, fmt.Errorf("TPMCommandInterface() failed: %v", err)
		}
		PCRs, alg, err = allPCRs20(tpm)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to read PCRs: %v", err)
		}

	default:
		return nil, 0, fmt.Errorf("unsupported TPM version: %x", t.version)
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
	context, err := tpmtbs.CreateContext(tpmtbs.TPMVersion20, tpmtbs.IncludeTPM20|tpmtbs.IncludeTPM12)
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
