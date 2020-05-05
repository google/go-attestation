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

// +build linux,!gofuzz

package attest

import (
	"crypto"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"strings"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/go-tspi/attestation"
	"github.com/google/go-tspi/tspi" //for tpm12 support
	"github.com/google/go-tspi/tspiconst"

	"github.com/google/go-tpm/tpm2"
)

const (
	tpmRoot = "/sys/class/tpm"
)

func probeSystemTPMs() ([]probedTPM, error) {
	var tpms []probedTPM

	tpmDevs, err := ioutil.ReadDir(tpmRoot)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err == nil {
		for _, tpmDev := range tpmDevs {
			if strings.HasPrefix(tpmDev.Name(), "tpm") {
				tpm := probedTPM{
					Path: path.Join(tpmRoot, tpmDev.Name()),
				}

				if _, err := os.Stat(path.Join(tpm.Path, "caps")); err != nil {
					if !os.IsNotExist(err) {
						return nil, err
					}
					tpm.Version = TPMVersion20
				} else {
					tpm.Version = TPMVersion12
				}
				tpms = append(tpms, tpm)
			}
		}
	}

	return tpms, nil
}

type linuxCmdChannel struct {
	io.ReadWriteCloser
}

// MeasurementLog implements CommandChannelTPM20.
func (cc *linuxCmdChannel) MeasurementLog() ([]byte, error) {
	return ioutil.ReadFile("/sys/kernel/security/tpm0/binary_bios_measurements")
}

func openTPM(tpm probedTPM) (*TPM, error) {
	switch tpm.Version {
	case TPMVersion12:
		// TPM1.2 must be using Daemon (Connect will fail if not the case)
		ctx, err := tspi.NewContext()
		if err != nil {
			return nil, err
		}
		if err = ctx.Connect(); err != nil {
			return nil, err
		}
		return &TPM{tpm: &trousersTPM{ctx: ctx}}, nil

	case TPMVersion20:
		interf := TPMInterfaceDirect
		// If the TPM has a kernel-provided resource manager, we should
		// use that instead of communicating directly.
		devPath := path.Join("/dev", path.Base(tpm.Path))
		f, err := ioutil.ReadDir(path.Join(tpm.Path, "device", "tpmrm"))
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, err
			}
		} else if len(f) > 0 {
			devPath = path.Join("/dev", f[0].Name())
			interf = TPMInterfaceKernelManaged
		}

		rwc, err := tpm2.OpenTPM(devPath)
		if err != nil {
			return nil, err
		}

		return &TPM{tpm: &wrappedTPM20{
			interf: interf,
			rwc:    &linuxCmdChannel{rwc},
		}}, nil

	default:
		return nil, fmt.Errorf("unsuported TPM version: %v", tpm.Version)
	}
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

func (t *trousersTPM) eks() ([]EK, error) {
	cert, err := readEKCertFromNVRAM12(t.ctx)
	if err != nil {
		return nil, fmt.Errorf("readEKCertFromNVRAM failed: %v", err)
	}
	return []EK{
		{Public: crypto.PublicKey(cert.PublicKey), Certificate: cert},
	}, nil
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
	return ioutil.ReadFile("/sys/kernel/security/tpm0/binary_bios_measurements")
}
