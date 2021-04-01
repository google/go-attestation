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

package attest

import (
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/google/certificate-transparency-go/asn1"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// wrappedTPM20 interfaces with a TPM 2.0 command channel.
type wrappedTPM20 struct {
	interf TPMInterface
	rwc    CommandChannelTPM20
}

func (*wrappedTPM20) isTPMBase() {}

func (t *wrappedTPM20) tpmVersion() TPMVersion {
	return TPMVersion20
}

func (t *wrappedTPM20) close() error {
	return t.rwc.Close()
}

// Info returns information about the TPM.
func (t *wrappedTPM20) info() (*TPMInfo, error) {
	var (
		tInfo = TPMInfo{
			Version:   TPMVersion20,
			Interface: t.interf,
		}
		t2Info tpm20Info
		err    error
	)

	if t2Info, err = readTPM2VendorAttributes(t.rwc); err != nil {
		return nil, err
	}
	tInfo.Manufacturer = t2Info.manufacturer
	tInfo.VendorInfo = t2Info.vendor
	tInfo.FirmwareVersionMajor = t2Info.fwMajor
	tInfo.FirmwareVersionMinor = t2Info.fwMinor
	return &tInfo, nil
}

// Return value: handle, whether we generated a new one, error
func (t *wrappedTPM20) getPrimaryKeyHandle(pHnd tpmutil.Handle) (tpmutil.Handle, bool, error) {
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

func (t *wrappedTPM20) eks() ([]EK, error) {
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
}

func (t *wrappedTPM20) newAK(opts *AKConfig) (*AK, error) {
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
	attestation, sig, err := tpm2.CertifyCreation(t.rwc, "", keyHandle, keyHandle, nil, creationHash, tpm2.SigScheme{tpm2.AlgRSASSA, tpm2.AlgSHA256, 0}, tix)
	if err != nil {
		return nil, fmt.Errorf("CertifyCreation failed: %v", err)
	}
	// Pack the raw structure into a TPMU_SIGNATURE.
	signature, err := tpmutil.Pack(tpm2.AlgRSASSA, tpm2.AlgSHA256, tpmutil.U16Bytes(sig))
	if err != nil {
		return nil, fmt.Errorf("failed to pack TPMT_SIGNATURE: %v", err)
	}
	return &AK{ak: newWrappedAK20(keyHandle, blob, pub, creationData, attestation, signature)}, nil
}

func (t *wrappedTPM20) newKey(ak *AK, opts *KeyConfig) (*Key, error) {
	// TODO(szp): TODO(jsonp): Abstract choice of hierarchy & parent.
	k, ok := ak.ak.(*wrappedKey20)
	if !ok {
		return nil, fmt.Errorf("expected *wrappedKey20, got: %T", k)
	}

	srk, _, err := t.getPrimaryKeyHandle(commonSrkEquivalentHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to get SRK handle: %v", err)
	}

	blob, pub, creationData, creationHash, tix, err := tpm2.CreateKey(t.rwc, srk, tpm2.PCRSelection{}, "", "", eccKeyTemplate)
	if err != nil {
		return nil, fmt.Errorf("CreateKey() failed: %v", err)
	}
	keyHandle, _, err := tpm2.Load(t.rwc, srk, "", pub, blob)
	if err != nil {
		return nil, fmt.Errorf("Load() failed: %v", err)
	}
	// If any errors occur, free the handle.
	defer func() {
		if err != nil {
			tpm2.FlushContext(t.rwc, keyHandle)
		}
	}()

	// Certify application key by AK
	attestation, sig, err := tpm2.CertifyCreation(t.rwc, "", keyHandle, k.hnd, nil, creationHash, tpm2.SigScheme{tpm2.AlgRSASSA, tpm2.AlgSHA256, 0}, tix)
	if err != nil {
		return nil, fmt.Errorf("CertifyCreation failed: %v", err)
	}
	// Pack the raw structure into a TPMU_SIGNATURE.
	signature, err := tpmutil.Pack(tpm2.AlgRSASSA, tpm2.AlgSHA256, tpmutil.U16Bytes(sig))
	if err != nil {
		return nil, fmt.Errorf("failed to pack TPMT_SIGNATURE: %v", err)
	}

	tpmPub, err := tpm2.DecodePublic(pub)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %v", err)
	}
	pubKey, err := tpmPub.Key()
	if err != nil {
		return nil, fmt.Errorf("access public key: %v", err)
	}
	return &Key{key: newWrappedKey20(keyHandle, blob, pub, creationData, attestation, signature), pub: pubKey, tpm: t}, nil
}

func (t *wrappedTPM20) deserializeAndLoad(opaqueBlob []byte) (tpmutil.Handle, *serializedKey, error) {
	sKey, err := deserializeKey(opaqueBlob, TPMVersion20)
	if err != nil {
		return 0, nil, fmt.Errorf("deserializeKey() failed: %v", err)
	}
	if sKey.Encoding != keyEncodingEncrypted {
		return 0, nil, fmt.Errorf("unsupported key encoding: %x", sKey.Encoding)
	}

	srk, _, err := t.getPrimaryKeyHandle(commonSrkEquivalentHandle)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to get SRK handle: %v", err)
	}
	var hnd tpmutil.Handle
	if hnd, _, err = tpm2.Load(t.rwc, srk, "", sKey.Public, sKey.Blob); err != nil {
		return 0, nil, fmt.Errorf("Load() failed: %v", err)
	}
	return hnd, sKey, nil
}

func (t *wrappedTPM20) loadAK(opaqueBlob []byte) (*AK, error) {
	hnd, sKey, err := t.deserializeAndLoad(opaqueBlob)
	if err != nil {
		return nil, fmt.Errorf("cannot load attestation key: %v", err)
	}
	return &AK{ak: newWrappedAK20(hnd, sKey.Blob, sKey.Public, sKey.CreateData, sKey.CreateAttestation, sKey.CreateSignature)}, nil
}

func (t *wrappedTPM20) loadKey(opaqueBlob []byte) (*Key, error) {
	hnd, sKey, err := t.deserializeAndLoad(opaqueBlob)
	if err != nil {
		return nil, fmt.Errorf("cannot load signing key: %v", err)
	}
	tpmPub, err := tpm2.DecodePublic(sKey.Public)
	if err != nil {
		return nil, fmt.Errorf("decode public blob: %v", err)
	}
	pub, err := tpmPub.Key()
	if err != nil {
		return nil, fmt.Errorf("access public key: %v", err)
	}
	return &Key{key: newWrappedKey20(hnd, sKey.Blob, sKey.Public, sKey.CreateData, sKey.CreateAttestation, sKey.CreateSignature), pub: pub, tpm: t}, nil
}

func (t *wrappedTPM20) pcrs(alg HashAlg) ([]PCR, error) {
	PCRs, err := readAllPCRs20(t.rwc, alg.goTPMAlg())
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

func (t *wrappedTPM20) measurementLog() ([]byte, error) {
	return t.rwc.MeasurementLog()
}

// wrappedKey20 represents a key manipulated through a *wrappedTPM20.
type wrappedKey20 struct {
	hnd tpmutil.Handle

	blob              []byte
	public            []byte // used by both TPM1.2 and 2.0
	createData        []byte
	createAttestation []byte
	createSignature   []byte
}

func newWrappedAK20(hnd tpmutil.Handle, blob, public, createData, createAttestation, createSig []byte) ak {
	return &wrappedKey20{
		hnd:               hnd,
		blob:              blob,
		public:            public,
		createData:        createData,
		createAttestation: createAttestation,
		createSignature:   createSig,
	}
}

func newWrappedKey20(hnd tpmutil.Handle, blob, public, createData, createAttestation, createSig []byte) key {
	return &wrappedKey20{
		hnd:               hnd,
		blob:              blob,
		public:            public,
		createData:        createData,
		createAttestation: createAttestation,
		createSignature:   createSig,
	}
}

func (k *wrappedKey20) marshal() ([]byte, error) {
	return (&serializedKey{
		Encoding:   keyEncodingEncrypted,
		TPMVersion: TPMVersion20,

		Blob:              k.blob,
		Public:            k.public,
		CreateData:        k.createData,
		CreateAttestation: k.createAttestation,
		CreateSignature:   k.createSignature,
	}).Serialize()
}

func (k *wrappedKey20) close(t tpmBase) error {
	tpm, ok := t.(*wrappedTPM20)
	if !ok {
		return fmt.Errorf("expected *wrappedTPM20, got %T", t)
	}
	return tpm2.FlushContext(tpm.rwc, k.hnd)
}

func (k *wrappedKey20) activateCredential(tb tpmBase, in EncryptedCredential) ([]byte, error) {
	t, ok := tb.(*wrappedTPM20)
	if !ok {
		return nil, fmt.Errorf("expected *wrappedTPM20, got %T", tb)
	}

	if len(in.Credential) < 2 {
		return nil, fmt.Errorf("malformed credential blob")
	}
	credential := in.Credential[2:]
	if len(in.Secret) < 2 {
		return nil, fmt.Errorf("malformed encrypted secret")
	}
	secret := in.Secret[2:]

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
	}, k.hnd, ekHnd, credential, secret)
}

func (k *wrappedKey20) quote(tb tpmBase, nonce []byte, alg HashAlg) (*Quote, error) {
	t, ok := tb.(*wrappedTPM20)
	if !ok {
		return nil, fmt.Errorf("expected *wrappedTPM20, got %T", tb)
	}
	return quote20(t.rwc, k.hnd, tpm2.Algorithm(alg), nonce)
}

func (k *wrappedKey20) attestationParameters() AttestationParameters {
	return AttestationParameters{
		Public:            k.public,
		CreateData:        k.createData,
		CreateAttestation: k.createAttestation,
		CreateSignature:   k.createSignature,
	}
}

func (k *wrappedKey20) certificationParameters() CertificationParameters {
	return CertificationParameters{
		Public:            k.public,
		CreateData:        k.createData,
		CreateAttestation: k.createAttestation,
		CreateSignature:   k.createSignature,
	}
}

func (k *wrappedKey20) sign(tb tpmBase, digest []byte) ([]byte, error) {
	t, ok := tb.(*wrappedTPM20)
	if !ok {
		return nil, fmt.Errorf("expected *wrappedTPM20, got %T", tb)
	}
	sig, err := tpm2.Sign(t.rwc, k.hnd, "", digest, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("signing data: %v", err)
	}
	if sig.RSA != nil {
		return sig.RSA.Signature, nil
	}
	if sig.ECC != nil {
		return asn1.Marshal(struct {
			R *big.Int
			S *big.Int
		}{sig.ECC.R, sig.ECC.S})
	}
	return nil, fmt.Errorf("unsupported signature type: %v", sig.Alg)
}

func (k *wrappedKey20) decrypt(tb tpmBase, ctxt []byte) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

func (k *wrappedKey20) blobs() ([]byte, []byte, error) {
	return k.public, k.blob, nil
}
