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
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"

	tpm1 "github.com/google/go-tpm/tpm"
	"github.com/google/go-tpm/tpm2"
	tpmtbs "github.com/google/go-tpm/tpmutil/tbs"
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

// Version returns the version of the TPM.
func (t *TPM) Version() TPMVersion {
	return t.version
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
	tInfo := TPMInfo{
		Version:   t.version,
		Interface: TPMInterfaceKernelManaged,
	}
	tpm, err := t.pcp.TPMCommandInterface()
	if err != nil {
		return nil, err
	}

	switch t.version {
	case TPMVersion12:
		tInfo.Manufacturer, tInfo.VendorInfo, err = readTPM12VendorAttributes(tpm)
	case TPMVersion20:
		var t2Info tpm20Info
		t2Info, err = readTPM2VendorAttributes(tpm)
		tInfo.Manufacturer = t2Info.manufacturer
		tInfo.VendorInfo = t2Info.vendor
		tInfo.FirmwareVersionMajor = t2Info.fwMajor
		tInfo.FirmwareVersionMinor = t2Info.fwMinor
	default:
		return nil, fmt.Errorf("unsupported TPM version: %x", t.version)
	}
	if err != nil {
		return nil, err
	}

	return &tInfo, nil
}

// EKs returns the Endorsement Keys burned-in to the platform.
func (t *TPM) EKs() ([]PlatformEK, error) {
	ekCerts, err := t.pcp.EKCerts()
	if err != nil {
		return nil, fmt.Errorf("could not read EKCerts: %v", err)
	}

	var out []PlatformEK
	for _, cert := range ekCerts {
		out = append(out, PlatformEK{cert, cert.PublicKey})
	}

	if len(out) == 0 {
		i, err := t.Info()
		if err != nil {
			return nil, err
		}
		if i.Manufacturer.String() == "Intel" {
			eks, err := t.readEKCertFromServer("https://ekop.intel.com/ekcertservice/")
			if err != nil {
				return nil, err
			}
			out = append(out, eks...)
		}
	}

	return out, nil
}

func (t *TPM) readEKCertFromServer(url string) ([]PlatformEK, error) {
	p, err := t.pcp.EKPub()
	if err != nil {
		return nil, fmt.Errorf("could not read ekpub: %v", err)
	}
	ekPub, err := decodeWindowsBcryptRSABlob(p)
	if err != nil {
		return nil, fmt.Errorf("could not decode ekpub: %v", err)
	}
	pubHash := sha256.New()
	pubHash.Write(ekPub.N.Bytes())
	pubHash.Write([]byte{0x1, 0x00, 0x01})

	resp, err := http.Get(url + base64.URLEncoding.EncodeToString(pubHash.Sum(nil)))
	if err != nil {
		return nil, fmt.Errorf("request failed: %v")
	}
	defer resp.Body.Close()
	d, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed reading EKCert from network: %v")
	}

	cert, err := parseCert(d)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %v", err)
	}
	return []PlatformEK{{Cert: cert}}, nil
}

type bcryptRSABlobHeader struct {
	Magic       uint32
	BitLength   uint32
	ExponentLen uint32
	ModulusLen  uint32
	Prime1Len   uint32
	Prime2Len   uint32
}

func decodeWindowsBcryptRSABlob(b []byte) (*rsa.PublicKey, error) {
	var (
		r      = bytes.NewReader(b)
		header = &bcryptRSABlobHeader{}
		exp    = make([]byte, 8)
		mod    = []byte("")
	)
	if err := binary.Read(r, binary.LittleEndian, header); err != nil {
		return nil, err
	}

	if header.Magic != 0x31415352 { // "RSA1"
		return nil, fmt.Errorf("invalid header magic %x", header.Magic)
	}
	if header.ExponentLen > 8 {
		return nil, errors.New("exponent too large")
	}

	if _, err := r.Read(exp[8-header.ExponentLen:]); err != nil {
		return nil, fmt.Errorf("failed to read public exponent: %v", err)
	}

	mod = make([]byte, header.ModulusLen)
	if n, err := r.Read(mod); n != int(header.ModulusLen) || err != nil {
		return nil, fmt.Errorf("failed to read modulus (%d, %v)", n, err)
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(mod),
		E: int(binary.BigEndian.Uint64(exp)),
	}, nil
}

func decryptCredential(secretKey, blob []byte) ([]byte, error) {
	var scheme uint32
	symbuf := bytes.NewReader(blob)
	if err := binary.Read(symbuf, binary.BigEndian, &scheme); err != nil {
		return nil, fmt.Errorf("reading scheme: %v", err)
	}
	if scheme != 0x00000002 {
		return nil, fmt.Errorf("can only handle CBC schemes")
	}

	iv := make([]byte, 16)
	if err := binary.Read(symbuf, binary.BigEndian, &iv); err != nil {
		return nil, err
	}
	cipherText := make([]byte, len(blob)-20)
	if err := binary.Read(symbuf, binary.BigEndian, &cipherText); err != nil {
		return nil, fmt.Errorf("reading ciphertext: %v", err)
	}

	// Decrypt the credential.
	var (
		block  cipher.Block
		secret []byte
		err    error
	)
	block, err = aes.NewCipher(secretKey)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher failed: %v", err)
	}
	secret = cipherText

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(secret, cipherText)
	// Remove PKCS5 padding.
	padlen := int(secret[len(secret)-1])
	secret = secret[:len(secret)-padlen]
	return secret, nil
}

// MintAIK creates a persistent attestation key. The returned key must be
// closed with a call to key.Close() when the caller has finished using it.
func (t *TPM) MintAIK(opts *MintOptions) (*AIK, error) {
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

	switch t.version {
	case TPMVersion12:
		aik, err := newKey12(kh, name, props.RawPublic)
		if err != nil {
			return nil, fmt.Errorf("unpacking aik: %v", err)
		}
		return &AIK{aik: aik}, nil
	case TPMVersion20:
		aik, err := newKey20(kh, name, props.RawPublic, props.RawCreationData, props.RawAttest, props.RawSignature)
		if err != nil {
			return nil, fmt.Errorf("unpacking aik: %v", err)
		}
		return &AIK{aik: aik}, nil
	default:
		return nil, fmt.Errorf("cannot handle TPM version: %v", t.version)
	}
}

func (t *TPM) loadAIK(opaqueBlob []byte) (*AIK, error) {
	sKey, err := deserializeKey(opaqueBlob, t.version)
	if err != nil {
		return nil, fmt.Errorf("deserializeKey() failed: %v", err)
	}
	if sKey.Encoding != keyEncodingOSManaged {
		return nil, fmt.Errorf("unsupported key encoding: %x", sKey.Encoding)
	}

	hnd, err := t.pcp.LoadKeyByName(sKey.Name)
	if err != nil {
		return nil, fmt.Errorf("pcp failed to load key: %v", err)
	}

	switch t.version {
	case TPMVersion12:
		aik, err := newKey12(hnd, sKey.Name, sKey.Public)
		if err != nil {
			return nil, fmt.Errorf("unpacking aik: %v", err)
		}
		return &AIK{aik: aik}, nil
	case TPMVersion20:
		aik, err := newKey20(hnd, sKey.Name, sKey.Public, sKey.CreateData, sKey.CreateAttestation, sKey.CreateSignature)
		if err != nil {
			return nil, fmt.Errorf("unpacking aik: %v", err)
		}
		return &AIK{aik: aik}, nil
	default:
		return nil, fmt.Errorf("cannot handle TPM version: %v", t.version)
	}
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
