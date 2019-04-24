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
	"encoding/json"
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

// Key represents a key bound to the TPM.
type Key struct {
	hnd         tpmutil.Handle
	KeyEncoding KeyEncoding
	TPMVersion  TPMVersion
	Purpose     KeyPurpose

	KeyBlob           []byte // exclusive to TPM1.2
	Public            []byte // used by both TPM1.2 and 2.0
	CreateData        []byte
	CreateAttestation []byte
	CreateSignature   []byte
}

// Marshal represents the key in a persistent format which may be
// loaded at a later time using tpm.LoadKey().
func (k *Key) Marshal() ([]byte, error) {
	return json.Marshal(k)
}

// Close frees any resources associated with the key.
func (k *Key) Close(tpm *TPM) error {
	switch tpm.version {
	case TPMVersion12:
		return nil
	case TPMVersion20:
		return tpm2.FlushContext(tpm.rwc, k.hnd)
	default:
		return fmt.Errorf("unsupported TPM version: %x", tpm.version)
	}
}

// ActivateCredential decrypts the specified credential using key.
// This operation is synonymous with TPM2_ActivateCredential.
func (k *Key) ActivateCredential(t *TPM, in EncryptedCredential) ([]byte, error) {
	switch t.version {
	case TPMVersion12:
		cred, err := attestation.AIKChallengeResponse(t.ctx, k.KeyBlob, in.Credential, in.Secret)
		if err != nil {
			return nil, fmt.Errorf("failed to refresh aik: %v", err)
		}
		return cred, nil

	case TPMVersion20:
		ekHnd, _, err := t.getPrimaryKeyHandle(commonEkEquivalentHandle)
		if err != nil {
			return nil, err
		}

		sessHandle, _, err := tpm2.StartAuthSession(
			t.rwc,
			tpm2.HandleNull,  /*tpmKey*/
			tpm2.HandleNull,  /*bindKey*/
			make([]byte, 16), /*nonceCaller*/
			nil,              /*secret*/
			tpm2.SessionPolicy,
			tpm2.AlgNull,
			tpm2.AlgSHA256)
		if err != nil {
			return nil, fmt.Errorf("creating session: %v", err)
		}
		defer tpm2.FlushContext(t.rwc, sessHandle)

		if _, err := tpm2.PolicySecret(t.rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, sessHandle, nil, nil, nil, 0); err != nil {
			return nil, fmt.Errorf("tpm2.PolicySecret() failed: %v", err)
		}

		return tpm2.ActivateCredentialUsingAuth(t.rwc, []tpm2.AuthCommand{
			{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession},
			{Session: sessHandle, Attributes: tpm2.AttrContinueSession},
		}, k.hnd, ekHnd, in.Credential[2:], in.Secret[2:])

	default:
		return nil, fmt.Errorf("unsupported TPM version: %x", t.version)

	}
}

func (k *Key) quote12(ctx *tspi.Context, nonce []byte) (*Quote, error) {
	quote, rawSig, err := attestation.GetQuote(ctx, k.KeyBlob, nonce)
	if err != nil {
		return nil, fmt.Errorf("GetQuote() failed: %v", err)
	}

	return &Quote{
		Version:   TPMVersion12,
		Quote:     quote,
		Signature: rawSig,
	}, nil
}

// Quote returns a quote over the platform state, signed by the key.
func (k *Key) Quote(t *TPM, nonce []byte, alg tpm2.Algorithm) (*Quote, error) {
	switch t.version {
	case TPMVersion12:
		return k.quote12(t.ctx, nonce)

	case TPMVersion20:
		return quote20(t.rwc, k.hnd, alg, nonce)

	default:
		return nil, fmt.Errorf("unsupported TPM version: %x", t.version)
	}
}

// MintAIK creates an attestation key.
func (t *TPM) MintAIK(opts *MintOptions) (*Key, error) {
	switch t.version {
	case TPMVersion12:
		pub, blob, err := attestation.CreateAIK(t.ctx)
		if err != nil {
			return nil, fmt.Errorf("CreateAIK failed: %v", err)
		}

		return &Key{
			KeyEncoding: KeyEncodingEncrypted,
			TPMVersion:  t.version,
			Purpose:     AttestationKey,
			KeyBlob:     blob,
			Public:      pub,
		}, nil

	case TPMVersion20:
		// TODO(jsonp): Abstract choice of hierarchy & parent.
		srk, _, err := t.getPrimaryKeyHandle(commonSrkEquivalentHandle)
		if err != nil {
			return nil, fmt.Errorf("failed to get SRK handle: %v", err)
		}

		_, blob, pub, creationData, creationHash, tix, err := tpm2.CreateKey(t.rwc, srk, tpm2.PCRSelection{}, "", "", aikTemplate)
		if err != nil {
			return nil, fmt.Errorf("CreateKeyEx failed: %v", err)
		}
		keyHandle, _, err := tpm2.Load(t.rwc, srk, "", pub, blob)
		if err != nil {
			return nil, fmt.Errorf("Load failed: %v", err)
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
		signature, err := tpmutil.Pack(tpm2.AlgRSASSA, tpm2.AlgSHA256, sig)
		if err != nil {
			return nil, fmt.Errorf("failed to pack TPMT_SIGNATURE: %v", err)
		}

		return &Key{
			hnd:               keyHandle,
			KeyEncoding:       KeyEncodingEncrypted,
			TPMVersion:        t.version,
			Purpose:           AttestationKey,
			KeyBlob:           blob,
			Public:            pub,
			CreateData:        creationData,
			CreateAttestation: attestation,
			CreateSignature:   signature,
		}, nil

	default:
		return nil, fmt.Errorf("unsupported TPM version: %x", t.version)
	}
}

// LoadKey loads a previously-created key into the TPM for use.
// A key loaded via this function needs to be closed with .Close().
func (t *TPM) LoadKey(opaqueBlob []byte) (*Key, error) {
	// TODO(b/124266168): Load under the key handle loaded by t.getPrimaryKeyHandle()

	var k Key
	var err error
	if err = json.Unmarshal(opaqueBlob, &k); err != nil {
		return nil, fmt.Errorf("Unmarshal failed: %v", err)
	}

	if k.TPMVersion != t.version {
		return nil, errors.New("key TPM version does not match opened TPM")
	}
	if k.Purpose != AttestationKey {
		return nil, fmt.Errorf("unsupported key kind: %x", k.Purpose)
	}

	switch t.version {
	case TPMVersion12:
		if k.KeyEncoding != KeyEncodingEncrypted {
			return nil, fmt.Errorf("unsupported key encoding: %x", k.KeyEncoding)
		}

	case TPMVersion20:
		if k.KeyEncoding != KeyEncodingEncrypted {
			return nil, fmt.Errorf("unsupported key encoding: %x", k.KeyEncoding)
		}

		srk, _, err := t.getPrimaryKeyHandle(commonSrkEquivalentHandle)
		if err != nil {
			return nil, fmt.Errorf("failed to get SRK handle: %v", err)
		}
		if k.hnd, _, err = tpm2.Load(t.rwc, srk, "", k.Public, k.KeyBlob); err != nil {
			return nil, fmt.Errorf("Load failed: %v", err)
		}
	}

	return &k, nil
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
