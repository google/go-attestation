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
	"github.com/google/go-tpm/tpmutil"
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

// Key represents a key bound to the TPM.
type Key struct {
	hnd        uintptr
	TPMVersion TPMVersion

	PCPKeyName        string
	Public            []byte
	CreateData        []byte
	CreateAttestation []byte
	CreateSignature   []byte
}

// Marshal represents the key in a persistent format which may be
// loaded at a later time using tpm.LoadKey().
func (k *Key) Marshal() ([]byte, error) {
	out := serializedKey{
		Encoding:   KeyEncodingOSManaged,
		Purpose:    AttestationKey,
		TPMVersion: k.TPMVersion,
		Name:       k.PCPKeyName,

		Public:            k.Public,
		CreateData:        k.CreateData,
		CreateAttestation: k.CreateAttestation,
		CreateSignature:   k.CreateSignature,
	}
	return out.Serialize()
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

// ActivateCredential decrypts the specified credential using key.
// This operation is synonymous with TPM2_ActivateCredential for TPM2.0
// and TPM_ActivateIdentity with the trousers daemon for TPM1.2.
func (k *Key) ActivateCredential(tpm *TPM, in EncryptedCredential) ([]byte, error) {
	if k.TPMVersion != tpm.version {
		return nil, fmt.Errorf("tpm and key version mismatch")
	}

	switch tpm.version {
	case TPMVersion12:
		secretKey, err := tpm.pcp.ActivateCredential(k.hnd, in.Credential)
		if err != nil {
			return nil, err
		}
		return decryptCredential(secretKey, in.Secret)
	case TPMVersion20:
		return tpm.pcp.ActivateCredential(k.hnd, append(in.Credential, in.Secret...))
	default:
		return nil, fmt.Errorf("invalid TPM version: %v", tpm.version)
	}
}

func (k *Key) quote12(tpm io.ReadWriter, hnd tpmutil.Handle, nonce []byte) (*Quote, error) {
	selectedPCRs := make([]int, 24)
	for pcr, _ := range selectedPCRs {
		selectedPCRs[pcr] = pcr
	}

	sig, pcrc, err := tpm1.Quote(tpm, hnd, nonce, selectedPCRs[:], wellKnownAuth[:])
	if err != nil {
		return nil, fmt.Errorf("Quote() failed: %v", err)
	}
	// Construct and return TPM_QUOTE_INFO
	// Returning TPM_QUOTE_INFO allows us to verify the Quote at a higher resolution
	// and matches what go-tspi returns.
	quote, err := tpm1.NewQuoteInfo(nonce, selectedPCRs[:], pcrc)
	if err != nil {
		return nil, fmt.Errorf("failed to construct Quote Info: %v", err)
	}
	return &Quote{
		Quote:     quote,
		Signature: sig,
	}, nil
}

// Quote returns a quote over the platform state, signed by the key.
func (k *Key) Quote(t *TPM, nonce []byte, alg tpm2.Algorithm) (*Quote, error) {
	tpmKeyHnd, err := t.pcp.TPMKeyHandle(k.hnd)
	if err != nil {
		return nil, fmt.Errorf("TPMKeyHandle() failed: %v", err)
	}

	switch t.version {
	case TPMVersion12:
		tpm, err := t.pcp.TPMCommandInterface()
		if err != nil {
			return nil, fmt.Errorf("TPMCommandInterface() failed: %v", err)
		}
		return k.quote12(tpm, tpmKeyHnd, nonce)

	case TPMVersion20:
		tpm, err := t.pcp.TPMCommandInterface()
		if err != nil {
			return nil, fmt.Errorf("TPMCommandInterface() failed: %v", err)
		}
		return quote20(tpm, tpmKeyHnd, alg, nonce)

	default:
		return nil, fmt.Errorf("unsupported TPM version: %x", t.version)
	}
}

// Close frees any resources associated with the key.
func (k *Key) Close(tpm *TPM) error {
	return closeNCryptObject(k.hnd)
}

// Delete permenantly removes the key from the system. This method
// invalidates Key and any further method invocations are invalid.
func (k *Key) Delete(tpm *TPM) error {
	return tpm.pcp.DeleteKey(k.hnd)
}

// MintAIK creates a persistent attestation key. The returned key must be
// closed with a call to key.Close() when the caller has finished using it.
func (t *TPM) MintAIK(opts *MintOptions) (*Key, error) {
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
		TPMVersion:        t.version,
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
	sKey, err := deserializeKey(opaqueBlob, t.version)
	if err != nil {
		return nil, fmt.Errorf("deserializeKey() failed: %v", err)
	}
	if sKey.Purpose != AttestationKey {
		return nil, fmt.Errorf("unsupported key kind: %x", sKey.Purpose)
	}
	if sKey.Encoding != KeyEncodingOSManaged {
		return nil, fmt.Errorf("unsupported key encoding: %x", sKey.Encoding)
	}

	k := Key{
		TPMVersion:        sKey.TPMVersion,
		PCPKeyName:        sKey.Name,
		Public:            sKey.Public,
		CreateData:        sKey.CreateData,
		CreateAttestation: sKey.CreateAttestation,
		CreateSignature:   sKey.CreateSignature,
	}
	if k.hnd, err = t.pcp.LoadKeyByName(k.PCPKeyName); err != nil {
		return nil, fmt.Errorf("pcp failed to load key: %v", err)
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
