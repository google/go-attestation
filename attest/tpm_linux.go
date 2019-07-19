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

// +build linux

package attest

import (
	"crypto"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"strings"

	"github.com/google/certificate-transparency-go/x509"

	"github.com/google/go-tspi/tspi" //for tpm12 support
	"github.com/google/go-tspi/tspiconst"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/google/go-tspi/attestation"
)

const (
	tpmRoot = "/sys/class/tpm"
)

// TPM interfaces with a TPM device on the system.
type TPM struct {
	version TPMVersion
	interf  TPMInterface

	sysPath string
	rwc     io.ReadWriteCloser
	ctx     *tspi.Context
}

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

func openTPM(tpm probedTPM) (*TPM, error) {
	interf := TPMInterfaceDirect
	var rwc io.ReadWriteCloser
	var ctx *tspi.Context
	var err error

	switch tpm.Version {
	case TPMVersion12:
		// TPM1.2 must be using Daemon (Connect will fail if not the case)
		interf = TPMInterfaceDaemonManaged
		ctx, err = tspi.NewContext()
		if err != nil {
			return nil, err
		}

		err = ctx.Connect()
		if err != nil {
			return nil, err
		}

	case TPMVersion20:
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

		rwc, err = tpm2.OpenTPM(devPath)
		if err != nil {
			return nil, err
		}
	}

	return &TPM{
		version: tpm.Version,
		interf:  interf,
		sysPath: tpm.Path,
		rwc:     rwc,
		ctx:     ctx,
	}, nil
}

// Close shuts down the connection to the TPM.
func (t *TPM) Close() error {
	switch t.version {
	case TPMVersion12:
		return t.ctx.Close()
	case TPMVersion20:
		return t.rwc.Close()
	default:
		return fmt.Errorf("unsupported TPM version: %x", t.version)
	}
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
func (t *TPM) Info() (*TPMInfo, error) {
	var manufacturer TCGVendorID
	var vendorInfo string
	var err error
	switch t.version {
	case TPMVersion12:
		manufacturer, vendorInfo, err = readTPM12VendorAttributes(t.ctx)
	case TPMVersion20:
		manufacturer, vendorInfo, err = readTPM2VendorAttributes(t.rwc)
	default:
		return nil, fmt.Errorf("unsupported TPM version: %x", t.version)
	}
	if err != nil {
		return nil, err
	}

	return &TPMInfo{
		Version:      t.version,
		Interface:    t.interf,
		VendorInfo:   vendorInfo,
		Manufacturer: manufacturer,
	}, nil
}

// Return value: handle, whether we generated a new one, error
func (t *TPM) getPrimaryKeyHandle(pHnd tpmutil.Handle) (tpmutil.Handle, bool, error) {
	_, _, _, err := tpm2.ReadPublic(t.rwc, pHnd)
	if err == nil {
		// Found the persistent handle, assume it's the key we want.
		return pHnd, false, nil
	}

	var keyHnd tpmutil.Handle
	switch pHnd {
	case commonSrkEquivalentHandle:
		keyHnd, _, err = tpm2.CreatePrimary(t.rwc, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", defaultSRKTemplate)
	case commonEkEquivalentHandle:
		keyHnd, _, err = tpm2.CreatePrimary(t.rwc, tpm2.HandleEndorsement, tpm2.PCRSelection{}, "", "", defaultEKTemplate)
	}
	if err != nil {
		return 0, false, fmt.Errorf("CreatePrimary failed: %v", err)
	}
	defer tpm2.FlushContext(t.rwc, keyHnd)

	err = tpm2.EvictControl(t.rwc, "", tpm2.HandleOwner, keyHnd, pHnd)
	if err != nil {
		return 0, false, fmt.Errorf("EvictControl failed: %v", err)
	}

	return pHnd, true, nil
}

func readEKCertFromNVRAM12(ctx *tspi.Context) (*x509.Certificate, error) {
	ekCert, err := attestation.GetEKCert(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading EK cert: %v", err)
	}
	return parseCert(ekCert)
}

// EKs returns the endorsement keys burned-in to the platform.
func (t *TPM) EKs() ([]PlatformEK, error) {
	var cert *x509.Certificate
	var err error
	switch t.version {
	case TPMVersion12:
		cert, err = readEKCertFromNVRAM12(t.ctx)

		if err != nil {
			return nil, fmt.Errorf("readEKCertFromNVRAM failed: %v", err)
		}

	case TPMVersion20:
		cert, err = readEKCertFromNVRAM20(t.rwc)

		if err != nil {
			ekHnd, _, err := tpm2.CreatePrimary(t.rwc, tpm2.HandleEndorsement, tpm2.PCRSelection{}, "", "", defaultEKTemplate)
			if err != nil {
				return nil, fmt.Errorf("EK CreatePrimary failed: %v", err)
			}
			defer tpm2.FlushContext(t.rwc, ekHnd)

			pub, _, _, err := tpm2.ReadPublic(t.rwc, ekHnd)
			if err != nil {
				return nil, fmt.Errorf("EK ReadPublic failed: %v", err)
			}
			if pub.RSAParameters == nil {
				return nil, errors.New("ECC EK not yet supported")
			}

			return []PlatformEK{
				{nil, &rsa.PublicKey{E: int(pub.RSAParameters.Exponent), N: pub.RSAParameters.Modulus}},
			}, nil
		}

	default:
		return nil, fmt.Errorf("unsupported TPM version: %x", t.version)
	}

	return []PlatformEK{
		{cert, cert.PublicKey},
	}, nil
}

// MintAIK creates an attestation key.
func (t *TPM) MintAIK(opts *MintOptions) (*AIK, error) {
	switch t.version {
	case TPMVersion12:
		pub, blob, err := attestation.CreateAIK(t.ctx)
		if err != nil {
			return nil, fmt.Errorf("CreateAIK failed: %v", err)
		}
		return &AIK{
			aik: &key12{
				blob:   blob,
				public: pub,
			},
		}, nil

	case TPMVersion20:
		// TODO(jsonp): Abstract choice of hierarchy & parent.
		srk, _, err := t.getPrimaryKeyHandle(commonSrkEquivalentHandle)
		if err != nil {
			return nil, fmt.Errorf("failed to get SRK handle: %v", err)
		}

		_, blob, pub, creationData, creationHash, tix, err := tpm2.CreateKey(t.rwc, srk, tpm2.PCRSelection{}, "", "", aikTemplate)
		if err != nil {
			return nil, fmt.Errorf("CreateKeyEx() failed: %v", err)
		}
		keyHandle, _, err := tpm2.Load(t.rwc, srk, "", pub, blob)
		if err != nil {
			return nil, fmt.Errorf("Load() failed: %v", err)
		}
		// If any errors occur, free the AIK's handle.
		defer func() {
			if err != nil {
				tpm2.FlushContext(t.rwc, keyHandle)
			}
		}()

		// We can only certify the creation immediately afterwards, so we cache the result.
		attestation, sig, err := tpm2.CertifyCreation(t.rwc, "", keyHandle, keyHandle, nil, creationHash, tpm2.SigScheme{tpm2.AlgRSASSA, tpm2.AlgSHA256, 0}, &tix)
		if err != nil {
			return nil, fmt.Errorf("CertifyCreation failed: %v", err)
		}
		// Pack the raw structure into a TPMU_SIGNATURE.
		signature, err := tpmutil.Pack(tpm2.AlgRSASSA, tpm2.AlgSHA256, tpmutil.U16Bytes(sig))
		if err != nil {
			return nil, fmt.Errorf("failed to pack TPMT_SIGNATURE: %v", err)
		}

		return &AIK{
			aik: &key20{
				hnd:               keyHandle,
				blob:              blob,
				public:            pub,
				createData:        creationData,
				createAttestation: attestation,
				createSignature:   signature,
			},
		}, nil

	default:
		return nil, fmt.Errorf("unsupported TPM version: %x", t.version)
	}
}

// LoadAIK loads a previously-created aik into the TPM for use.
// A key loaded via this function needs to be closed with .Close().
func (t *TPM) LoadAIK(opaqueBlob []byte) (*AIK, error) {
	sKey, err := deserializeKey(opaqueBlob, t.version)
	if err != nil {
		return nil, fmt.Errorf("deserializeKey() failed: %v", err)
	}
	if sKey.Encoding != KeyEncodingEncrypted {
		return nil, fmt.Errorf("unsupported key encoding: %x", sKey.Encoding)
	}

	switch sKey.TPMVersion {
	case TPMVersion12:
		return &AIK{
			aik: &key12{
				blob:   sKey.Blob,
				public: sKey.Public,
			},
		}, nil
	case TPMVersion20:
		srk, _, err := t.getPrimaryKeyHandle(commonSrkEquivalentHandle)
		if err != nil {
			return nil, fmt.Errorf("failed to get SRK handle: %v", err)
		}
		var hnd tpmutil.Handle
		if hnd, _, err = tpm2.Load(t.rwc, srk, "", sKey.Public, sKey.Blob); err != nil {
			return nil, fmt.Errorf("Load() failed: %v", err)
		}

		return &AIK{
			aik: &key20{
				hnd:               hnd,
				blob:              sKey.Blob,
				public:            sKey.Public,
				createData:        sKey.CreateData,
				createAttestation: sKey.CreateAttestation,
				createSignature:   sKey.CreateSignature,
			},
		}, nil
	default:
		return nil, fmt.Errorf("cannot load AIK with TPM version: %v", sKey.TPMVersion)
	}
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

// PCRs returns the present value of all Platform Configuration Registers.
func (t *TPM) PCRs() (map[int]PCR, tpm2.Algorithm, error) {
	var PCRs map[uint32][]byte
	var alg crypto.Hash
	var err error

	switch t.version {
	case TPMVersion12:
		PCRs, err = allPCRs12(t.ctx)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to read PCRs: %v", err)
		}
		alg = crypto.SHA1

	case TPMVersion20:
		PCRs, alg, err = allPCRs20(t.rwc)
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
	return ioutil.ReadFile("/sys/kernel/security/tpm0/binary_bios_measurements")
}
