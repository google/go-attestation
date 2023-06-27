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
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const (
	tpmPtManufacturer = 0x00000100 + 5  // PT_FIXED + offset of 5
	tpmPtVendorString = 0x00000100 + 6  // PT_FIXED + offset of 6
	tpmPtFwVersion1   = 0x00000100 + 11 // PT_FIXED + offset of 11

	// Defined in "Registry of reserved TPM 2.0 handles and localities".
	nvramRSACertIndex    = 0x1c00002
	nvramRSAEkNonceIndex = 0x1c00003
	nvramECCCertIndex    = 0x1c0000a

	// Defined in "Registry of reserved TPM 2.0 handles and localities", and checked on a glinux machine.
	commonSrkEquivalentHandle   = 0x81000001
	commonRSAEkEquivalentHandle = 0x81010001
	commonECCEkEquivalentHandle = 0x81010002
)

var (
	akTemplate = tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagSignerDefault | tpm2.FlagNoDA,
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits: 2048,
		},
	}
	defaultSRKTemplate = tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagStorageDefault | tpm2.FlagNoDA,
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			ModulusRaw: make([]byte, 256),
			KeyBits:    2048,
		},
	}
	// Default RSA EK template defined in:
	// https://trustedcomputinggroup.org/wp-content/uploads/Credential_Profile_EK_V2.0_R14_published.pdf
	defaultRSAEKTemplate = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagAdminWithPolicy | tpm2.FlagRestricted | tpm2.FlagDecrypt,
		AuthPolicy: []byte{
			0x83, 0x71, 0x97, 0x67, 0x44, 0x84,
			0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D,
			0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52,
			0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
			0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14,
			0x69, 0xAA,
		},
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits:    2048,
			ModulusRaw: make([]byte, 256),
		},
	}
	// Basic template for an ECDSA key signing outside-TPM objects. Other
	// fields are populated depending on the key creation options.
	ecdsaKeyTemplate = tpm2.Public{
		Type:       tpm2.AlgECC,
		Attributes: tpm2.FlagSignerDefault ^ tpm2.FlagRestricted,
		ECCParameters: &tpm2.ECCParams{
			Sign: &tpm2.SigScheme{
				Alg: tpm2.AlgECDSA,
			},
		},
	}
	// Basic template for an RSA key signing outside-TPM objects. Other
	// fields are populated depending on the key creation options.
	rsaKeyTemplate = tpm2.Public{
		Type:          tpm2.AlgRSA,
		NameAlg:       tpm2.AlgSHA256,
		Attributes:    tpm2.FlagSignerDefault ^ tpm2.FlagRestricted,
		RSAParameters: &tpm2.RSAParams{},
	}
)

type tpm20Info struct {
	vendor       string
	manufacturer TCGVendorID
	fwMajor      int
	fwMinor      int
}

func readTPM2VendorAttributes(tpm io.ReadWriter) (tpm20Info, error) {
	var vendorInfo string
	// The Vendor String is split up into 4 sections of 4 bytes,
	// for a maximum length of 16 octets of ASCII text. We iterate
	// through the 4 indexes to get all 16 bytes & construct vendorInfo.
	// See: TPM_PT_VENDOR_STRING_1 in TPM 2.0 Structures reference.
	for i := 0; i < 4; i++ {
		caps, _, err := tpm2.GetCapability(tpm, tpm2.CapabilityTPMProperties, 1, tpmPtVendorString+uint32(i))
		if err != nil {
			return tpm20Info{}, fmt.Errorf("tpm2.GetCapability(PT_VENDOR_STRING_%d) failed: %v", i+1, err)
		}
		subset, ok := caps[0].(tpm2.TaggedProperty)
		if !ok {
			return tpm20Info{}, fmt.Errorf("got capability of type %T, want tpm2.TaggedProperty", caps[0])
		}
		// Reconstruct the 4 ASCII octets from the uint32 value.
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, subset.Value)
		vendorInfo += string(b)
	}

	caps, _, err := tpm2.GetCapability(tpm, tpm2.CapabilityTPMProperties, 1, tpmPtManufacturer)
	if err != nil {
		return tpm20Info{}, fmt.Errorf("tpm2.GetCapability(PT_MANUFACTURER) failed: %v", err)
	}
	manu, ok := caps[0].(tpm2.TaggedProperty)
	if !ok {
		return tpm20Info{}, fmt.Errorf("got capability of type %T, want tpm2.TaggedProperty", caps[0])
	}

	caps, _, err = tpm2.GetCapability(tpm, tpm2.CapabilityTPMProperties, 1, tpmPtFwVersion1)
	if err != nil {
		return tpm20Info{}, fmt.Errorf("tpm2.GetCapability(PT_FIRMWARE_VERSION_1) failed: %v", err)
	}
	fw, ok := caps[0].(tpm2.TaggedProperty)
	if !ok {
		return tpm20Info{}, fmt.Errorf("got capability of type %T, want tpm2.TaggedProperty", caps[0])
	}

	return tpm20Info{
		vendor:       strings.Trim(vendorInfo, "\x00"),
		manufacturer: TCGVendorID(manu.Value),
		fwMajor:      int((fw.Value & 0xffff0000) >> 16),
		fwMinor:      int(fw.Value & 0x0000ffff),
	}, nil
}

// ParseEKCertificate parses a raw DER encoded EK certificate blob.
func ParseEKCertificate(ekCert []byte) (*x509.Certificate, error) {
	var wasWrapped bool

	// TCG PC Specific Implementation section 7.3.2 specifies
	// a prefix when storing a certificate in NVRAM. We look
	// for and unwrap the certificate if its present.
	if len(ekCert) > 5 && bytes.Equal(ekCert[:3], []byte{0x10, 0x01, 0x00}) {
		certLen := int(binary.BigEndian.Uint16(ekCert[3:5]))
		if len(ekCert) < certLen+5 {
			return nil, fmt.Errorf("parsing nvram header: ekCert size %d smaller than specified cert length %d", len(ekCert), certLen)
		}
		ekCert = ekCert[5 : 5+certLen]
		wasWrapped = true
	}

	// If the cert parses fine without any changes, we are G2G.
	if c, err := x509.ParseCertificate(ekCert); err == nil {
		return c, nil
	}
	// There might be trailing nonsense in the cert, which Go
	// does not parse correctly. As ASN1 data is TLV encoded, we should
	// be able to just get the certificate, and then send that to Go's
	// certificate parser.
	var cert struct {
		Raw asn1.RawContent
	}
	if _, err := asn1.UnmarshalWithParams(ekCert, &cert, "lax"); err != nil {
		return nil, fmt.Errorf("asn1.Unmarshal() failed: %v, wasWrapped=%v", err, wasWrapped)
	}

	c, err := x509.ParseCertificate(cert.Raw)
	if err != nil {
		return nil, fmt.Errorf("x509.ParseCertificate() failed: %v", err)
	}
	return c, nil
}

const (
	manufacturerIntel     = "Intel"
	intelEKCertServiceURL = "https://ekop.intel.com/ekcertservice/"
)

func intelEKURL(ekPub *rsa.PublicKey) string {
	pubHash := sha256.New()
	pubHash.Write(ekPub.N.Bytes())
	pubHash.Write([]byte{0x1, 0x00, 0x01})

	return intelEKCertServiceURL + url.QueryEscape(base64.URLEncoding.EncodeToString(pubHash.Sum(nil)))
}

func readEKCertFromNVRAM20(tpm io.ReadWriter, nvramCertIndex tpmutil.Handle) (*x509.Certificate, error) {
	// By passing nvramCertIndex as our auth handle we're using the NV index
	// itself as the auth hierarchy, which is the same approach
	// tpm2_getekcertificate takes.
	ekCert, err := tpm2.NVReadEx(tpm, nvramCertIndex, nvramCertIndex, "", 0)
	if err != nil {
		return nil, fmt.Errorf("reading EK cert: %v", err)
	}
	return ParseEKCertificate(ekCert)
}

func quote20(tpm io.ReadWriter, akHandle tpmutil.Handle, hashAlg tpm2.Algorithm, nonce []byte, selectedPCRs []int) (*Quote, error) {
	sel := tpm2.PCRSelection{Hash: hashAlg,
		PCRs: selectedPCRs}

	quote, sig, err := tpm2.Quote(tpm, akHandle, "", "", nonce, sel, tpm2.AlgNull)
	if err != nil {
		return nil, err
	}

	rawSig, err := tpmutil.Pack(sig.Alg, sig.RSA.HashAlg, sig.RSA.Signature)
	return &Quote{
		Version:   TPMVersion20,
		Quote:     quote,
		Signature: rawSig,
	}, err
}

func readAllPCRs20(tpm io.ReadWriter, alg tpm2.Algorithm) (map[uint32][]byte, error) {
	numPCRs := 24
	out := map[uint32][]byte{}

	// The TPM 2.0 spec says that the TPM can partially fulfill the
	// request. As such, we repeat the command up to 24 times to get all
	// 24 PCRs.
	for i := 0; i < numPCRs; i++ {
		// Build a selection structure, specifying all PCRs we do
		// not have the value for.
		sel := tpm2.PCRSelection{Hash: alg}
		for pcr := 0; pcr < numPCRs; pcr++ {
			if _, present := out[uint32(pcr)]; !present {
				sel.PCRs = append(sel.PCRs, pcr)
			}
		}

		// Ask the TPM for those PCR values.
		ret, err := tpm2.ReadPCRs(tpm, sel)
		if err != nil {
			return nil, fmt.Errorf("tpm2.ReadPCRs(%+v) failed with err: %v", sel, err)
		}
		// Keep track of the PCRs we were actually given.
		for pcr, digest := range ret {
			out[uint32(pcr)] = digest
		}
		if len(out) == numPCRs {
			break
		}
	}

	if len(out) != numPCRs {
		return nil, fmt.Errorf("failed to read all PCRs, only read %d", len(out))
	}

	return out, nil
}

// tpmBase defines the implementation of a TPM invariant.
type tpmBase interface {
	close() error
	tpmVersion() TPMVersion
	eks() ([]EK, error)
	ekCertificates() ([]EK, error)
	info() (*TPMInfo, error)

	loadAK(opaqueBlob []byte) (*AK, error)
	newAK(opts *AKConfig) (*AK, error)
	deleteAK(opaqueBlob []byte) error
	loadKey(opaqueBlob []byte) (*Key, error)
	newKey(ak *AK, opts *KeyConfig) (*Key, error)
	deleteKey(opaqueBlob []byte) error
	pcrs(alg HashAlg) ([]PCR, error)
	measurementLog() ([]byte, error)
}

// TPM interfaces with a TPM device on the system.
type TPM struct {
	// tpm refers to a concrete implementation of TPM logic, based on the current
	// platform and TPM version.
	tpm tpmBase
}

// Close shuts down the connection to the TPM.
func (t *TPM) Close() error {
	return t.tpm.close()
}

// EKs returns the endorsement keys burned-in to the platform.
func (t *TPM) EKs() ([]EK, error) {
	return t.tpm.eks()
}

// EKCertificates returns the endorsement key certificates burned-in to the platform.
// It is guaranteed that each EK.Certificate field will be populated.
func (t *TPM) EKCertificates() ([]EK, error) {
	return t.tpm.ekCertificates()
}

// Info returns information about the TPM.
func (t *TPM) Info() (*TPMInfo, error) {
	return t.tpm.info()
}

// LoadAK loads a previously-created ak into the TPM for use.
// A key loaded via this function needs to be closed with .Close().
// Only blobs generated by calling AK.Marshal() are valid parameters
// to this function.
func (t *TPM) LoadAK(opaqueBlob []byte) (*AK, error) {
	return t.tpm.loadAK(opaqueBlob)
}

// MeasurementLog returns the present value of the System Measurement Log.
//
// This is a low-level API. Consumers seeking to attest the state of the
// platform should use tpm.AttestPlatform() instead.
func (t *TPM) MeasurementLog() ([]byte, error) {
	el, err := t.tpm.measurementLog()
	if err != nil {
		return nil, err
	}

	// A valid event log contains at least one SpecID event header (28 bytes).
	// For TPM 1.2, we would expect at least an event header (32 bytes).
	if minValidSize := 28; len(el) < minValidSize {
		return nil, fmt.Errorf("event log too short: %d < %d", len(el), minValidSize)
	}
	return el, nil
}

// NewAK creates an attestation key.
func (t *TPM) NewAK(opts *AKConfig) (*AK, error) {
	return t.tpm.newAK(opts)
}

func (t *TPM) DeleteAK(opaqueBlob []byte) error {
	return t.tpm.deleteAK(opaqueBlob)
}

// NewKey creates an application key certified by the attestation key. If opts is nil
// then DefaultConfig is used.
func (t *TPM) NewKey(ak *AK, opts *KeyConfig) (*Key, error) {
	if opts == nil {
		opts = defaultConfig
	}
	if opts.Algorithm == "" && opts.Size == 0 {
		opts.Algorithm = defaultConfig.Algorithm
		opts.Size = defaultConfig.Size
	}
	return t.tpm.newKey(ak, opts)
}

// LoadKey loads a previously-created application key into the TPM for use.
// A key loaded via this function needs to be closed with .Close().
// Only blobs generated by calling Key.Marshal() are valid parameters
// to this function.
func (t *TPM) LoadKey(opaqueBlob []byte) (*Key, error) {
	return t.tpm.loadKey(opaqueBlob)
}

func (t *TPM) DeleteKey(opaqueBlob []byte) error {
	return t.tpm.deleteKey(opaqueBlob)
}

// PCRs returns the present value of Platform Configuration Registers with
// the given digest algorithm.
//
// This is a low-level API. Consumers seeking to attest the state of the
// platform should use tpm.AttestPlatform() instead.
func (t *TPM) PCRs(alg HashAlg) ([]PCR, error) {
	return t.tpm.pcrs(alg)
}

func (t *TPM) attestPCRs(ak *AK, nonce []byte, alg HashAlg) (*Quote, []PCR, error) {
	pcrs, err := t.PCRs(alg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read %v PCRs: %v", alg, err)
	}

	quote, err := ak.Quote(t, nonce, alg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to quote using %v: %v", alg, err)
	}

	// Make sure that the pcrs and quote values are consistent. See details in Section 17.6.2 of
	// https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part1_Architecture_pub.pdf
	pub, err := ParseAKPublic(t.Version(), ak.AttestationParameters().Public)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse AK public: %v", err)
	}
	if err := pub.Verify(*quote, pcrs, nonce); err != nil {
		return nil, nil, fmt.Errorf("local quote verification failed: %v", err)
	}

	return quote, pcrs, nil
}

func (t *TPM) attestPlatform(ak *AK, nonce []byte, eventLog []byte) (*PlatformParameters, error) {
	out := PlatformParameters{
		TPMVersion: t.Version(),
		Public:     ak.AttestationParameters().Public,
		EventLog:   eventLog,
	}

	algs := []HashAlg{HashSHA1}
	if t.Version() == TPMVersion20 {
		algs = []HashAlg{HashSHA1, HashSHA256}
	}

	var lastErr error
	for _, alg := range algs {
		quote, pcrs, err := t.attestPCRs(ak, nonce, alg)
		if err != nil {
			lastErr = err
			continue
		}
		out.Quotes = append(out.Quotes, *quote)
		out.PCRs = append(out.PCRs, pcrs...)
	}

	if len(out.Quotes) == 0 {
		return nil, lastErr
	}
	return &out, nil
}

// PlatformAttestConfig configures how attestations are generated through
// tpm.AttestPlatform().
type PlatformAttestConfig struct {
	// If non-nil, the raw event log will be read from EventLog
	// instead of being obtained from the running system.
	EventLog []byte
}

// AttestPlatform computes the set of information necessary to attest the
// state of the platform. For TPM 2.0 devices, AttestPlatform will attempt
// to read both SHA1 & SHA256 PCR banks and quote both of them, so bugs in
// platform firmware which break replay for one PCR bank can be mitigated
// using the other.
// The provided config, if not nil, can be used to configure aspects of the
// platform attestation.
func (t *TPM) AttestPlatform(ak *AK, nonce []byte, config *PlatformAttestConfig) (*PlatformParameters, error) {
	if config == nil {
		config = &PlatformAttestConfig{}
	}

	var el []byte
	if config.EventLog != nil {
		el = config.EventLog
	} else {
		var err error
		if el, err = t.MeasurementLog(); err != nil {
			return nil, fmt.Errorf("failed to read event log: %v", err)
		}
	}

	return t.attestPlatform(ak, nonce, el)
}

// Version returns the version of the TPM.
func (t *TPM) Version() TPMVersion {
	return t.tpm.tpmVersion()
}
