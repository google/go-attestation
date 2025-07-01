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
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	tpmtbs "github.com/google/go-tpm/tpmutil/tbs"
	"golang.org/x/sys/windows"
)

var wellKnownAuth [20]byte

type windowsTPM struct {
	pcp *winPCP
}

func probeSystemTPMs() ([]string, error) {
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

	if info.TBSInfo.TPMVersion != 2 {
		return nil, fmt.Errorf("TBSInfo.TPMVersion %d unsupported", info.TBSInfo.TPMVersion)
	}

	return []string{""}, nil
}

func openTPM(_ string) (*TPM, error) {
	pcp, err := openPCP()
	if err != nil {
		return nil, fmt.Errorf("openPCP() failed: %v", err)
	}

	info, err := pcp.TPMInfo()
	if err != nil {
		return nil, fmt.Errorf("TPMInfo() failed: %v", err)
	}
	if info.TBSInfo.TPMVersion != 2 {
		return nil, fmt.Errorf("TBSInfo.TPMVersion %d unsupported", info.TBSInfo.TPMVersion)
	}

	return &TPM{tpm: &windowsTPM{
		pcp: pcp,
	}}, nil
}

func (t *windowsTPM) close() error {
	return t.pcp.Close()
}

func (t *windowsTPM) info() (*TPMInfo, error) {
	tInfo := TPMInfo{
		Interface: TPMInterfaceKernelManaged,
	}
	tpm, err := t.pcp.TPMCommandInterface()
	if err != nil {
		return nil, err
	}

	t2Info, err := readVendorAttributes(tpm)
	if err != nil {
		return nil, err
	}
	tInfo.Manufacturer = t2Info.manufacturer
	tInfo.VendorInfo = t2Info.vendor
	tInfo.FirmwareVersionMajor = t2Info.fwMajor
	tInfo.FirmwareVersionMinor = t2Info.fwMinor

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
	ek.CertificateURL = ekCertURL(pub, i.Manufacturer.String())
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

func (t *windowsTPM) newAK(opts *AKConfig) (*AK, error) {
	var name string
	var alg Algorithm

	if opts != nil && opts.Name != "" {
		name = opts.Name
	} else {
		nameHex := make([]byte, 5)
		if n, err := rand.Read(nameHex); err != nil || n != len(nameHex) {
			return nil, fmt.Errorf("rand.Read() failed with %d/%d bytes read and error: %v", n, len(nameHex), err)
		}
		name = fmt.Sprintf("ak-%x", nameHex)
	}
	if opts != nil && opts.Algorithm != "" {
		alg = opts.Algorithm
	} else {
		// Default to RSA based AK.
		alg = RSA
	}

	kh, err := t.pcp.NewAK(name, alg)
	if err != nil {
		return nil, fmt.Errorf("pcp failed to mint attestation key: %v", err)
	}
	props, err := t.pcp.AKProperties(kh)
	if err != nil {
		closeNCryptObject(kh)
		return nil, fmt.Errorf("pcp failed to read attestation key properties: %v", err)
	}

	return &AK{ak: newWindowsKey20(kh, name, props.RawPublic, props.RawCreationData, props.RawAttest, props.RawSignature)}, nil
}

func (t *windowsTPM) loadAK(opaqueBlob []byte) (*AK, error) {
	sKey, err := deserializeKey(opaqueBlob)
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

	return &AK{ak: newWindowsKey20(hnd, sKey.Name, sKey.Public, sKey.CreateData, sKey.CreateAttestation, sKey.CreateSignature)}, nil
}

func (t *windowsTPM) loadAKWithParent(opaqueBlob []byte, parent ParentKeyConfig) (*AK, error) {
	return nil, fmt.Errorf("not implemented")
}

func (t *windowsTPM) newKey(*AK, *KeyConfig) (*Key, error) {
	return nil, fmt.Errorf("not implemented")
}

func (t *windowsTPM) newKeyCertifiedByKey(ck certifyingKey, opts *KeyConfig) (*Key, error) {
	return nil, fmt.Errorf("not implemented")
}

func (t *windowsTPM) loadKey(opaqueBlob []byte) (*Key, error) {
	return nil, fmt.Errorf("not implemented")
}

func (t *windowsTPM) loadKeyWithParent(opaqueBlob []byte, parent ParentKeyConfig) (*Key, error) {
	return nil, fmt.Errorf("not implemented")
}

func (t *windowsTPM) pcrbanks() ([]HashAlg, error) {
	tpm, err := t.pcp.TPMCommandInterface()
	if err != nil {
		return nil, fmt.Errorf("TPMCommandInterface() failed: %v", err)
	}
	return pcrbanks(tpm)
}

func (t *windowsTPM) pcrs(alg HashAlg) ([]PCR, error) {
	var PCRs map[uint32][]byte

	tpm, err := t.pcp.TPMCommandInterface()
	if err != nil {
		return nil, fmt.Errorf("TPMCommandInterface() failed: %v", err)
	}
	PCRs, err = readAllPCRs(tpm, alg.goTPMAlg())
	if err != nil {
		return nil, fmt.Errorf("failed to read PCRs: %v", err)
	}

	out := make([]PCR, len(PCRs))
	for index, digest := range PCRs {
		digestAlg, err := alg.cryptoHash()
		if err != nil {
			return nil, fmt.Errorf("unknown algorithm ID %x: %v", alg, err)
		}
		out[int(index)] = PCR{
			Index:     int(index),
			Digest:    digest,
			DigestAlg: digestAlg,
		}
	}

	return out, nil
}

func (t *windowsTPM) measurementLog() ([]byte, error) {
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
