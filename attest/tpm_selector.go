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

package attest

import (
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"io"
)

// selectorTPM interfaces with a platformTPM or a CommandChannel.
type selectorTPM struct {
	version TPMVersion
	interf  TPMInterface

	sysPath string
	rwc     io.ReadWriteCloser
	pTPM    *platformTPM
}

func openCommandChannel(v TPMVersion, rwc io.ReadWriteCloser) (*TPM, error) {
	if v == TPMVersion12 {
		return nil, errors.New("TPM1.2 is not supported when using CommandChannel")
	}
	return &TPM{tpm: &selectorTPM{
		version: TPMVersion20,
		interf:  TPMInterfaceCommandChannelManaged,
		rwc:     rwc,
	}}, nil
}

func (t *selectorTPM) tpmVersion() TPMVersion {
	if t.pTPM != nil {
		return t.pTPM.tpmVersion()
	}

	return t.version
}

func (t *selectorTPM) close() error {
	if t.pTPM != nil {
		return t.pTPM.close()
	}

	switch t.version {
	case TPMVersion20:
		return t.rwc.Close()
	default:
		return fmt.Errorf("unsupported TPM version: %x", t.version)
	}
}

// Info returns information about the TPM.
func (t *selectorTPM) info() (*TPMInfo, error) {
	if t.pTPM != nil {
		return t.pTPM.info()
	}

	tInfo := TPMInfo{
		Version:   t.version,
		Interface: t.interf,
	}

	var err error
	switch t.version {
	case TPMVersion20:
		var t2Info tpm20Info
		t2Info, err = readTPM2VendorAttributes(t.rwc)
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

// Return value: handle, whether we generated a new one, error
func (t *selectorTPM) getPrimaryKeyHandle(pHnd tpmutil.Handle) (tpmutil.Handle, bool, error) {
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

func (t *selectorTPM) eks() ([]EK, error) {
	if t.pTPM != nil {
		return t.pTPM.eks()
	}

	switch t.version {
	case TPMVersion20:
		if cert, err := readEKCertFromNVRAM20(t.rwc); err == nil {
			return []EK{
				{Public: crypto.PublicKey(cert.PublicKey), Certificate: cert},
			}, nil
		}

		// Attempt to create an EK.
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
		return []EK{
			{
				Public: &rsa.PublicKey{
					E: int(pub.RSAParameters.Exponent()),
					N: pub.RSAParameters.Modulus(),
				},
			},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported TPM version: %x", t.version)
	}
}

func (t *selectorTPM) newAK(opts *AKConfig) (*AK, error) {
	if t.pTPM != nil {
		return t.pTPM.newAK(opts)
	}

	switch t.version {
	case TPMVersion20:
		// TODO(jsonp): Abstract choice of hierarchy & parent.
		srk, _, err := t.getPrimaryKeyHandle(commonSrkEquivalentHandle)
		if err != nil {
			return nil, fmt.Errorf("failed to get SRK handle: %v", err)
		}

		blob, pub, creationData, creationHash, tix, err := tpm2.CreateKey(t.rwc, srk, tpm2.PCRSelection{}, "", "", akTemplate)
		if err != nil {
			return nil, fmt.Errorf("CreateKeyEx() failed: %v", err)
		}
		keyHandle, _, err := tpm2.Load(t.rwc, srk, "", pub, blob)
		if err != nil {
			return nil, fmt.Errorf("Load() failed: %v", err)
		}
		// If any errors occur, free the AK's handle.
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
		return &AK{ak: newKey20(keyHandle, blob, pub, creationData, attestation, signature)}, nil
	default:
		return nil, fmt.Errorf("unsupported TPM version: %x", t.version)
	}
}

func (t *selectorTPM) loadAK(opaqueBlob []byte) (*AK, error) {
	if t.pTPM != nil {
		return t.pTPM.loadAK(opaqueBlob)
	}

	sKey, err := deserializeKey(opaqueBlob, t.version)
	if err != nil {
		return nil, fmt.Errorf("deserializeKey() failed: %v", err)
	}
	if sKey.Encoding != keyEncodingEncrypted {
		return nil, fmt.Errorf("unsupported key encoding: %x", sKey.Encoding)
	}

	switch sKey.TPMVersion {
	case TPMVersion20:
		srk, _, err := t.getPrimaryKeyHandle(commonSrkEquivalentHandle)
		if err != nil {
			return nil, fmt.Errorf("failed to get SRK handle: %v", err)
		}
		var hnd tpmutil.Handle
		if hnd, _, err = tpm2.Load(t.rwc, srk, "", sKey.Public, sKey.Blob); err != nil {
			return nil, fmt.Errorf("Load() failed: %v", err)
		}
		return &AK{ak: newKey20(hnd, sKey.Blob, sKey.Public, sKey.CreateData, sKey.CreateAttestation, sKey.CreateSignature)}, nil
	default:
		return nil, fmt.Errorf("cannot load AK with TPM version: %v", sKey.TPMVersion)
	}
}

func (t *selectorTPM) pcrs(alg HashAlg) ([]PCR, error) {
	if t.pTPM != nil {
		return t.pTPM.pcrs(alg)
	}

	var PCRs map[uint32][]byte
	var err error

	switch t.version {
	case TPMVersion20:
		PCRs, err = readAllPCRs20(t.rwc, alg.goTPMAlg())
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

func (t *selectorTPM) measurementLog() ([]byte, error) {
	if t.interf == TPMInterfaceCommandChannelManaged {
		return nil, errors.New("MeasurementLog is not supported when using CommandChannel")
	}
	return platformMeasurementLog()
}
