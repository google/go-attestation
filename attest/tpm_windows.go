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

//go:build windows
// +build windows

package attest

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/google/go-tpm/legacy/tpm2"
	tpm1 "github.com/google/go-tpm/tpm"
	tpmtbs "github.com/google/go-tpm/tpmutil/tbs"
	"golang.org/x/sys/windows"
)

var wellKnownAuth [20]byte

type windowsTPM struct {
	version TPMVersion
	pcp     *winPCP
}

func (*windowsTPM) isTPMBase() {}

func probeSystemTPMs() ([]probedTPM, error) {
	// Initialize Tbs.dll here so that it's linked only when TPM support is required.
	if tbs == nil {
		tbs = windows.MustLoadDLL("Tbs.dll")
		tbsGetDeviceInfo = tbs.MustFindProc("Tbsi_GetDeviceInfo")
	}

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

	return &TPM{tpm: &windowsTPM{
		pcp:     pcp,
		version: vers,
	}}, nil
}

func (t *windowsTPM) tpmVersion() TPMVersion {
	return t.version
}

func (t *windowsTPM) close() error {
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

func (t *windowsTPM) info() (*TPMInfo, error) {
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

func (t *windowsTPM) ekCertificates() ([]EK, error) {
	ekCerts, err := t.pcp.EKCerts()
	if err != nil {
		return nil, fmt.Errorf("could not read EKCerts: %v", err)
	}
	var eks []EK
	for _, cert := range ekCerts {
		eks = append(eks, EK{Certificate: cert, Public: cert.PublicKey})
	}
	return eks, nil
}

func (t *windowsTPM) eks() ([]EK, error) {
	ekCerts, err := t.pcp.EKCerts()
	if err != nil {
		return nil, fmt.Errorf("could not read EKCerts: %v", err)
	}
	if len(ekCerts) > 0 {
		var eks []EK
		for _, cert := range ekCerts {
			eks = append(eks, EK{Certificate: cert, Public: cert.PublicKey})
		}
		return eks, nil
	}

	pub, err := t.ekPub()
	if err != nil {
		return nil, fmt.Errorf("could not read ek public key from tpm: %v", err)
	}
	ek := EK{Public: pub}

	i, err := t.info()
	if err != nil {
		return nil, err
	}
	if i.Manufacturer.String() == manufacturerIntel {
		ek.CertificateURL = intelEKURL(pub)
	}
	return []EK{ek}, nil
}

func (t *windowsTPM) ekPub() (*rsa.PublicKey, error) {
	p, err := t.pcp.EKPub()
	if err != nil {
		return nil, fmt.Errorf("could not read ekpub: %v", err)
	}
	ekPub, err := decodeWindowsBcryptRSABlob(p)
	if err != nil {
		return nil, fmt.Errorf("could not decode ekpub: %v", err)
	}
	return ekPub, nil
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

func (t *windowsTPM) newAK(opts *AKConfig) (*AK, error) {
	nameHex := make([]byte, 5)
	if n, err := rand.Read(nameHex); err != nil || n != len(nameHex) {
		return nil, fmt.Errorf("rand.Read() failed with %d/%d bytes read and error: %v", n, len(nameHex), err)
	}
	name := fmt.Sprintf("ak-%x", nameHex)

	kh, err := t.pcp.NewAK(name)
	if err != nil {
		return nil, fmt.Errorf("pcp failed to mint attestation key: %v", err)
	}
	props, err := t.pcp.AKProperties(kh)
	if err != nil {
		closeNCryptObject(kh)
		return nil, fmt.Errorf("pcp failed to read attestation key properties: %v", err)
	}

	switch t.version {
	case TPMVersion12:
		return &AK{ak: newWindowsAK12(kh, name, props.RawPublic)}, nil
	case TPMVersion20:
		return &AK{ak: newWindowsAK20(kh, name, props.RawPublic, props.RawCreationData, props.RawAttest, props.RawSignature)}, nil
	default:
		return nil, fmt.Errorf("cannot handle TPM version: %v", t.version)
	}
}

func (t *windowsTPM) loadAK(opaqueBlob []byte) (*AK, error) {
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
		return &AK{ak: newWindowsAK12(hnd, sKey.Name, sKey.Public)}, nil
	case TPMVersion20:
		return &AK{ak: newWindowsAK20(hnd, sKey.Name, sKey.Public, sKey.CreateData, sKey.CreateAttestation, sKey.CreateSignature)}, nil
	default:
		return nil, fmt.Errorf("cannot handle TPM version: %v", t.version)
	}
}

func (t *windowsTPM) newKey(ak *AK, config *KeyConfig) (*Key, error) {
	if t.version != TPMVersion20 {
		return nil, fmt.Errorf("key generation on TPM version %v is unsupported", t.version)
	}
	k, ok := ak.ak.(*windowsAK20)
	if !ok {
		return nil, fmt.Errorf("expected *windowsAK20, got: %T", k)
	}

	nameHex := make([]byte, 5)
	if n, err := rand.Read(nameHex); err != nil || n != len(nameHex) {
		return nil, fmt.Errorf("rand.Read() failed with %d/%d bytes read and error: %v", n, len(nameHex), err)
	}
	name := fmt.Sprintf("app-%x", nameHex)

	hnd, pub, blob, err := t.pcp.NewKey(name, config)
	if err != nil {
		return nil, fmt.Errorf("pcp failed to mint application key: %v", err)
	}

	cp, err := k.certify(t, hnd)
	if err != nil {
		return nil, fmt.Errorf("ak.Certify() failed: %v", err)
	}

	if !bytes.Equal(pub, cp.Public) {
		return nil, fmt.Errorf("certified incorrect key, expected: %v, certified: %v", pub, cp.Public)
	}

	tpmPub, err := tpm2.DecodePublic(pub)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %v", err)
	}

	pubKey, err := tpmPub.Key()
	if err != nil {
		return nil, fmt.Errorf("access public key: %v", err)
	}

	// TODO(hslatman): do we need the blob?
	_ = blob

	// Return a new windowsAK20 certified by the ak, conforming to the key interface. This allows the
	// key to be verified to have been generated by the same TPM as the ak was generated with. The
	// resulting key can be used for signing purposes.
	return &Key{key: newWindowsKey20(hnd, name, pub, cp.CreateData, cp.CreateAttestation, cp.CreateSignature), pub: pubKey, tpm: t}, nil
}

func (t *windowsTPM) loadAKWithParent(opaqueBlob []byte, parent ParentKeyConfig) (*AK, error) {
	return nil, fmt.Errorf("not implemented")
}

func (t *windowsTPM) loadKey(opaqueBlob []byte) (*Key, error) {
	return nil, fmt.Errorf("not implemented")
}

func (t *windowsTPM) loadKeyWithParent(opaqueBlob []byte, parent ParentKeyConfig) (*Key, error) {
	return nil, fmt.Errorf("not implemented")
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

func (t *windowsTPM) pcrs(alg HashAlg) ([]PCR, error) {
	var PCRs map[uint32][]byte

	switch t.version {
	case TPMVersion12:
		if alg != HashSHA1 {
			return nil, fmt.Errorf("non-SHA1 algorithm %v is not supported on TPM 1.2", alg)
		}
		tpm, err := t.pcp.TPMCommandInterface()
		if err != nil {
			return nil, fmt.Errorf("TPMCommandInterface() failed: %v", err)
		}
		PCRs, err = allPCRs12(tpm)
		if err != nil {
			return nil, fmt.Errorf("failed to read PCRs: %v", err)
		}

	case TPMVersion20:
		tpm, err := t.pcp.TPMCommandInterface()
		if err != nil {
			return nil, fmt.Errorf("TPMCommandInterface() failed: %v", err)
		}
		PCRs, err = readAllPCRs20(tpm, alg.goTPMAlg())
		if err != nil {
			return nil, fmt.Errorf("failed to read PCRs: %v", err)
		}

	default:
		return nil, fmt.Errorf("unsupported TPM version: %x", t.version)
	}

	out := make([]PCR, len(PCRs))
	for index, digest := range PCRs {
		out[int(index)] = PCR{
			Index:     int(index),
			Digest:    digest,
			DigestAlg: alg.cryptoHash(),
		}
	}

	return out, nil
}

func (t *windowsTPM) measurementLog() ([]byte, error) {
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
