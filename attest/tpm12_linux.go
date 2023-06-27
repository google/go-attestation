// Copyright 2020 Google Inc.
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

//go:build linux && !gofuzz && cgo && tspi
// +build linux,!gofuzz,cgo,tspi

package attest

import (
	"crypto"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"os"

	"github.com/google/go-tspi/attestation"
	"github.com/google/go-tspi/tspi"
	"github.com/google/go-tspi/tspiconst"
)

func init() {
	getTPM12Impl = getTPM12
}

func getTPM12() (*TPM, error) {
	ctx, err := tspi.NewContext()
	if err != nil {
		return nil, err
	}
	if err = ctx.Connect(); err != nil {
		return nil, err
	}
	return &TPM{tpm: &trousersTPM{ctx: ctx}}, nil
}

// trousersTPM interfaces with a TPM 1.2 device via tcsd.
type trousersTPM struct {
	ctx *tspi.Context
}

func (*trousersTPM) isTPMBase() {}

func (t *trousersTPM) tpmVersion() TPMVersion {
	return TPMVersion12
}

func (t *trousersTPM) close() error {
	return t.ctx.Close()
}

func readTPM12VendorAttributes(context *tspi.Context) (TCGVendorID, string, error) {
	// TPM 1.2 doesn't seem to store vendor data (other than unique ID)
	vendor, err := context.GetCapability(tspiconst.TSS_TPMCAP_PROPERTY, 4, tspiconst.TSS_TPMCAP_PROP_MANUFACTURER)
	if err != nil {
		return TCGVendorID(0), "", fmt.Errorf("tspi::Context::GetCapability failed: %v", err)
	}
	if len(vendor) > 4 {
		return TCGVendorID(0), "", fmt.Errorf("expecting at most 32-bit VendorID, got %d-bit ID instead", len(vendor)*8)
	}
	vendorID := TCGVendorID(binary.BigEndian.Uint32(vendor))
	return vendorID, vendorID.String(), nil
}

// Info returns information about the TPM.
func (t *trousersTPM) info() (*TPMInfo, error) {
	tInfo := TPMInfo{
		Version:   TPMVersion12,
		Interface: TPMInterfaceDaemonManaged,
	}
	var err error

	if tInfo.Manufacturer, tInfo.VendorInfo, err = readTPM12VendorAttributes(t.ctx); err != nil {
		return nil, err
	}
	return &tInfo, nil
}

func readEKCertFromNVRAM12(ctx *tspi.Context) (*x509.Certificate, error) {
	ekCert, err := attestation.GetEKCert(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading EK cert: %v", err)
	}
	return ParseEKCertificate(ekCert)
}

func (t *trousersTPM) ekCertificates() ([]EK, error) {
	cert, err := readEKCertFromNVRAM12(t.ctx)
	if err != nil {
		return nil, fmt.Errorf("readEKCertFromNVRAM failed: %v", err)
	}
	return []EK{
		{Public: crypto.PublicKey(cert.PublicKey), Certificate: cert},
	}, nil
}

func (t *trousersTPM) eks() ([]EK, error) {
	return t.ekCertificates()
}

func (t *trousersTPM) newKey(*AK, *KeyConfig) (*Key, error) {
	return nil, fmt.Errorf("not implemented")
}

func (t *trousersTPM) loadKey(opaqueBlob []byte) (*Key, error) {
	return nil, fmt.Errorf("not implemented")
}

func (t *trousersTPM) deleteKey(opaqueBlob []byte) error {
	return fmt.Errorf("not implemented")
}

func (t *trousersTPM) newAK(opts *AKConfig) (*AK, error) {
	pub, blob, err := attestation.CreateAIK(t.ctx)
	if err != nil {
		return nil, fmt.Errorf("CreateAIK failed: %v", err)
	}
	return &AK{ak: newTrousersKey12(blob, pub)}, nil
}

func (t *trousersTPM) loadAK(opaqueBlob []byte) (*AK, error) {
	sKey, err := deserializeKey(opaqueBlob, TPMVersion12)
	if err != nil {
		return nil, fmt.Errorf("deserializeKey() failed: %v", err)
	}
	if sKey.Encoding != keyEncodingEncrypted {
		return nil, fmt.Errorf("unsupported key encoding: %x", sKey.Encoding)
	}

	return &AK{ak: newTrousersKey12(sKey.Blob, sKey.Public)}, nil
}

func (t *trousersTPM) deleteAK(opaqueBlob []byte) error {
	return fmt.Errorf("not implemented")
}

// allPCRs12 returns a map of all the PCR values on the TPM
func allPCRs12(ctx *tspi.Context) (map[uint32][]byte, error) {
	tpm := ctx.GetTPM()
	PCRlist, err := tpm.GetPCRValues()
	if err != nil {
		return nil, fmt.Errorf("failed to read PCRs: %v", err)
	}

	PCRs := make(map[uint32][]byte)
	for i := 0; i < len(PCRlist); i++ {
		PCRs[(uint32)(i)] = PCRlist[i]
	}
	return PCRs, nil
}

func (t *trousersTPM) pcrs(alg HashAlg) ([]PCR, error) {
	if alg != HashSHA1 {
		return nil, fmt.Errorf("non-SHA1 algorithm %v is not supported on TPM 1.2", alg)
	}
	PCRs, err := allPCRs12(t.ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read PCRs: %v", err)
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

func (t *trousersTPM) measurementLog() ([]byte, error) {
	return os.ReadFile("/sys/kernel/security/tpm0/binary_bios_measurements")
}
