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

// Package attest abstracts TPM attestation operations.
package attest

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// TPMInterface indicates how the client communicates
// with the TPM.
type TPMInterface uint8

// TPM interfaces
const (
	TPMInterfaceDirect TPMInterface = iota
	TPMInterfaceKernelManaged
	TPMInterfaceDaemonManaged
	TPMInterfaceCommandChannel
)

// CommandChannelTPM20 represents a pipe along which TPM 2.0 commands
// can be issued, and measurement logs read.
type CommandChannelTPM20 interface {
	io.ReadWriteCloser
	MeasurementLog() ([]byte, error)
}

// OpenConfig encapsulates settings passed to OpenTPM().
type OpenConfig struct {
	// CommandChannel provides a TPM 2.0 command channel, which can be
	// used in-lieu of any TPM present on the platform.
	CommandChannel CommandChannelTPM20
}

// keyEncoding indicates how an exported TPM key is represented.
type keyEncoding uint8

func (e keyEncoding) String() string {
	switch e {
	case keyEncodingInvalid:
		return "invalid"
	case keyEncodingOSManaged:
		return "os-managed"
	case keyEncodingEncrypted:
		return "encrypted"
	case keyEncodingParameterized:
		return "parameterized"
	default:
		return fmt.Sprintf("keyEncoding<%d>", int(e))
	}
}

// Key encodings
const (
	keyEncodingInvalid keyEncoding = iota
	// Managed by the OS but loadable by name.
	keyEncodingOSManaged
	// Key fully represented but in encrypted form.
	keyEncodingEncrypted
	// Parameters stored, but key must be regenerated before use.
	keyEncodingParameterized
)

// ParentKeyConfig describes the Storage Root Key that is used
// as a parent for new keys.
type ParentKeyConfig struct {
	Algorithm Algorithm
	Handle    tpmutil.Handle
}

var defaultParentConfig = ParentKeyConfig{
	Algorithm: RSA,
	Handle:    0x81000001,
}

type ak interface {
	close(tpmBase) error
	marshal() ([]byte, error)
	activateCredential(tpm tpmBase, in EncryptedCredential, ek *EK) ([]byte, error)
	quote(t tpmBase, nonce []byte, alg HashAlg, selectedPCRs []int) (*Quote, error)
	attestationParameters() AttestationParameters
	certify(tb tpmBase, handle any, opts CertifyOpts) (*CertificationParameters, error)
	signMsg(tb tpmBase, msg []byte, pub crypto.PublicKey, opts crypto.SignerOpts) ([]byte, error)
}

// AK represents a key which can be used for attestation.
type AK struct {
	ak  ak
	pub crypto.PublicKey
}

// Public returns the public key for the AK. This is only supported for TPM 2.0
// on Linux currently.
func (k *AK) Public() crypto.PublicKey {
	return k.pub
}

// Close unloads the AK from the system.
func (k *AK) Close(t *TPM) error {
	return k.ak.close(t.tpm)
}

// Marshal encodes the AK in a format that can be reloaded with tpm.LoadAK().
// This method exists to allow consumers to store the key persistently and load
// it as a later time. Users SHOULD NOT attempt to interpret or extract values
// from this blob.
func (k *AK) Marshal() ([]byte, error) {
	return k.ak.marshal()
}

// ActivateCredential decrypts the secret using the key to prove that the AK
// was generated on the same TPM as the EK. This method can be used with TPMs
// that have the default EK, i.e. RSA EK with handle 0x81010001.
//
// This operation is synonymous with TPM2_ActivateCredential.
func (k *AK) ActivateCredential(tpm *TPM, in EncryptedCredential) (secret []byte, err error) {
	return k.ak.activateCredential(tpm.tpm, in, nil)
}

// ActivateCredentialWithEK decrypts the secret using the key to prove that the AK
// was generated on the same TPM as the EK. This method can be used with TPMs
// that have an ECC EK. The 'ek' argument must be one of EKs returned from
// TPM.EKs() or TPM.EKCertificates().
//
// This operation is synonymous with TPM2_ActivateCredential.
func (k *AK) ActivateCredentialWithEK(tpm *TPM, in EncryptedCredential, ek EK) (secret []byte, err error) {
	return k.ak.activateCredential(tpm.tpm, in, &ek)
}

// Quote returns a quote over the platform state, signed by the AK.
//
// This is a low-level API. Consumers seeking to attest the state of the
// platform should use tpm.AttestPlatform() instead.
func (k *AK) Quote(tpm *TPM, nonce []byte, alg HashAlg) (*Quote, error) {
	pcrs := make([]int, 24)
	for pcr := range pcrs {
		pcrs[pcr] = pcr
	}
	return k.ak.quote(tpm.tpm, nonce, alg, pcrs)
}

// QuotePCRs is like Quote() but allows the caller to select a subset of the PCRs.
func (k *AK) QuotePCRs(tpm *TPM, nonce []byte, alg HashAlg, pcrs []int) (*Quote, error) {
	return k.ak.quote(tpm.tpm, nonce, alg, pcrs)
}

// AttestationParameters returns information about the AK, typically used to
// generate a credential activation challenge.
func (k *AK) AttestationParameters() AttestationParameters {
	return k.ak.attestationParameters()
}

// Certify uses the attestation key to certify the key with `handle`. It returns
// certification parameters which allow to verify the properties of the attested
// key. Depending on the actual instantiation it can accept different handle
// types (e.g., tpmutil.Handle on Linux or uintptr on Windows).
func (k *AK) Certify(tpm *TPM, handle any) (*CertificationParameters, error) {
	return k.ak.certify(tpm.tpm, handle, CertifyOpts{})
}

// SignMsg signs the message (not the digest) with the AK. Note that AK is a
// restricted signing key, it cannot sign a digest directly.
func (k *AK) SignMsg(tpm *TPM, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	return k.ak.signMsg(tpm.tpm, msg, k.pub, opts)
}

// AKConfig encapsulates parameters for minting keys.
type AKConfig struct {
	// Optionally set unique name for AK on Windows.
	Name string
	// Parent describes the Storage Root Key that will be used as a parent.
	// If nil, the default SRK (i.e. RSA with handle 0x81000001) is assumed.
	// Supported only by TPM 2.0 on Linux.
	Parent *ParentKeyConfig

	// If not specified, the default algorithm (RSA) is assumed.
	Algorithm Algorithm
}

// EncryptedCredential represents encrypted parameters which must be activated
// against a key.
type EncryptedCredential struct {
	Credential []byte
	Secret     []byte
}

// Quote encapsulates the results of a Quote operation against the TPM,
// using an attestation key.
type Quote struct {
	Quote     []byte
	Signature []byte
}

// PCR encapsulates the value of a PCR at a point in time.
type PCR struct {
	Index     int
	Digest    []byte
	DigestAlg crypto.Hash

	// quoteVerified is true if the PCR was verified against a quote
	// in a call to AKPublic.Verify or AKPublic.VerifyAll.
	quoteVerified bool
}

// QuoteVerified returns true if the value of this PCR was previously
// verified against a Quote, in a call to AKPublic.Verify or AKPublic.VerifyAll.
func (p *PCR) QuoteVerified() bool {
	return p.quoteVerified
}

// EK is a burned-in endorcement key bound to a TPM. This optionally contains
// a certificate that can chain to the TPM manufacturer.
type EK struct {
	// Public key of the EK.
	Public crypto.PublicKey

	// Certificate is the EK certificate for TPMs that provide it.
	Certificate *x509.Certificate

	// For Intel TPMs, Intel hosts certificates at a public URL derived from the
	// Public key. Clients or servers can perform an HTTP GET to this URL, and
	// use ParseEKCertificate on the response body.
	CertificateURL string

	// The EK persistent handle.
	handle tpmutil.Handle
}

// AttestationParameters describes information about a key which is necessary
// for verifying its properties remotely.
type AttestationParameters struct {
	// Public represents the AK's canonical encoding. This blob includes the
	// public key, as well as signing parameters such as the hash algorithm
	// used to generate quotes.
	//
	// Use ParseAKPublic to access the key's data.
	Public []byte
	// For TPM 2.0 devices, Public is encoded as a TPMT_PUBLIC structure.
	// For TPM 1.2 devices, Public is a TPM_PUBKEY structure, as defined in
	// the TPM Part 2 Structures specification, available at
	// https://trustedcomputinggroup.org/wp-content/uploads/TPM-Main-Part-2-TPM-Structures_v1.2_rev116_01032011.pdf

	// UseTCSDActivationFormat is set when tcsd (trousers daemon) is operating
	// as an intermediary between this library and the TPM. A value of true
	// indicates that activation challenges should use the TCSD-specific format.
	UseTCSDActivationFormat bool

	// Subsequent fields are only populated for AKs generated on a TPM
	// implementing version 2.0 of the specification. The specific structures
	// referenced for each field are defined in the TPM Revision 2, Part 2 -
	// Structures specification, available here:
	// https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf

	// CreateData represents the properties of a TPM 2.0 key. It is encoded
	// as a TPMS_CREATION_DATA structure.
	CreateData []byte
	// CreateAttestation represents an assertion as to the details of the key.
	// It is encoded as a TPMS_ATTEST structure.
	CreateAttestation []byte
	// CreateSignature represents a signature of the CreateAttestation structure.
	// It is encoded as a TPMT_SIGNATURE structure.
	CreateSignature []byte
}

// AKPublic holds structured information about an AK's public key.
type AKPublic struct {
	// Public is the public part of the AK. This can either be an *rsa.PublicKey or
	// and *ecdsa.PublicKey.
	Public crypto.PublicKey
	// Hash is the hashing algorithm the AK will use when signing quotes.
	Hash crypto.Hash
}

// ParseAKPublic parses the Public blob from the AttestationParameters,
// returning the public key and signing parameters for the key.
func ParseAKPublic(public []byte) (*AKPublic, error) {
	pub, err := tpm2.DecodePublic(public)
	if err != nil {
		return nil, fmt.Errorf("parsing TPM public key structure: %v", err)
	}
	switch {
	case pub.RSAParameters == nil && pub.ECCParameters == nil:
		return nil, errors.New("parsing public key: missing asymmetric parameters")
	case pub.RSAParameters != nil && pub.RSAParameters.Sign == nil:
		return nil, errors.New("parsing public key: missing rsa signature scheme")
	case pub.ECCParameters != nil && pub.ECCParameters.Sign == nil:
		return nil, errors.New("parsing public key: missing ecc signature scheme")
	}

	pubKey, err := pub.Key()
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %v", err)
	}

	var h crypto.Hash
	switch pub.Type {
	case tpm2.AlgRSA:
		h, err = pub.RSAParameters.Sign.Hash.Hash()
	case tpm2.AlgECC:
		h, err = pub.ECCParameters.Sign.Hash.Hash()
	default:
		return nil, fmt.Errorf("unsupported public key type 0x%x", pub.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("invalid public key hash: %v", err)
	}
	return &AKPublic{Public: pubKey, Hash: h}, nil
}

// Verify is used to prove authenticity of the PCR measurements. It ensures that
// the quote was signed by the AK, and that its contents matches the PCR and
// nonce combination. An error is returned if a provided PCR index was not part
// of the quote. QuoteVerified() will return true on PCRs which were verified
// by a quote.
//
// Do NOT use this method if you have multiple quotes to verify: Use VerifyAll
// instead.
//
// The nonce is used to prevent replays of Quote and PCRs and is signed by the
// quote. Some TPMs don't support nonces longer than 20 bytes, and if the
// nonce is used to tie additional data to the quote, the additional data should be
// hashed to construct the nonce.
func (a *AKPublic) Verify(quote Quote, pcrs []PCR, nonce []byte) error {
	return a.validateQuote(quote, pcrs, nonce)
}

// VerifyAll uses multiple quotes to verify the authenticity of all PCR
// measurements. See documentation on Verify() for semantics.
//
// An error is returned if any PCRs provided were not covered by a quote,
// or if no quote/nonce was provided.
func (a *AKPublic) VerifyAll(quotes []Quote, pcrs []PCR, nonce []byte) error {
	if len(quotes) == 0 {
		return errors.New("no quotes were provided")
	}
	if len(nonce) == 0 {
		return errors.New("no nonce was provided")
	}

	for i, quote := range quotes {
		if err := a.Verify(quote, pcrs, nonce); err != nil {
			return fmt.Errorf("quote %d: %v", i, err)
		}
	}

	var errPCRs []string
	for _, p := range pcrs {
		if !p.QuoteVerified() {
			errPCRs = append(errPCRs, fmt.Sprintf("%d (%s)", p.Index, p.DigestAlg))
		}
	}
	if len(errPCRs) > 0 {
		return fmt.Errorf("some PCRs were not covered by a quote: %s", strings.Join(errPCRs, ", "))
	}
	return nil
}

// HashAlg identifies a hashing Algorithm.
type HashAlg uint8

// Known valid hash algorithms.
var (
	HashSHA1   = HashAlg(tpm2.AlgSHA1)
	HashSHA256 = HashAlg(tpm2.AlgSHA256)
	HashSHA384 = HashAlg(tpm2.AlgSHA384)
	HashSHA512 = HashAlg(tpm2.AlgSHA512)
)

func (a HashAlg) cryptoHash() (crypto.Hash, error) {
	g := a.goTPMAlg()
	h, err := g.Hash()
	if err != nil {
		return 0, fmt.Errorf("HashAlg %v (corresponding to TPM2.Algorithm %v) has no corresponding crypto.Hash", a, g)
	}
	return h, nil
}
func (a HashAlg) goTPMAlg() tpm2.Algorithm {
	return tpm2.Algorithm(a)
}

// String returns a human-friendly representation of the hash algorithm.
func (a HashAlg) String() string {
	return a.goTPMAlg().String()
}

// PlatformParameters encapsulates the set of information necessary to attest
// the booted state of the machine the TPM is attached to.
//
// The digests contained in the event log can be considered authentic if:
//   - The AK public corresponds to the known AK for that platform.
//   - All quotes are verified with AKPublic.Verify(), and return no errors.
//   - The event log parsed successfully using ParseEventLog(), and a call
//     to EventLog.Verify() with the full set of PCRs returned no error.
type PlatformParameters struct {
	// The public blob of the AK which endorsed the platform state. This can
	// be decoded to verify the adjacent quotes using ParseAKPublic().
	Public []byte
	// The set of quotes which endorse the state of the PCRs.
	Quotes []Quote
	// The set of expected PCR values, which are used in replaying the event log
	// to verify digests were not tampered with.
	PCRs []PCR
	// The raw event log provided by the platform. This can be processed with
	// ParseEventLog().
	EventLog []byte
}

var (
	defaultOpenConfig = &OpenConfig{}

	// ErrTPMNotAvailable is returned in response to OpenTPM() when
	// either no TPM is available, or a TPM of the requested version
	// is not available (if TPMVersion was set in the provided config).
	ErrTPMNotAvailable = errors.New("TPM device not available")
)

// TPMInfo contains information about the version & interface
// of an open TPM.
type TPMInfo struct {
	Interface    TPMInterface
	VendorInfo   string
	Manufacturer TCGVendorID

	// FirmwareVersionMajor and FirmwareVersionMinor describe
	// the firmware version of the TPM, but are only available
	// for TPM 2.0 devices.
	FirmwareVersionMajor int
	FirmwareVersionMinor int
}

// OpenTPM initializes access to the TPM based on the
// config provided.
func OpenTPM(config *OpenConfig) (*TPM, error) {
	if config == nil {
		config = defaultOpenConfig
	}
	// As a special case, if the user provided us with a command channel,
	// we should use that.
	if config.CommandChannel != nil {
		return &TPM{&wrappedTPM20{
			interf: TPMInterfaceCommandChannel,
			rwc:    config.CommandChannel,
		}}, nil
	}

	candidateTPMs, err := probeSystemTPMs()
	if err != nil {
		return nil, err
	}

	for _, tpm := range candidateTPMs {
		return openTPM(tpm)
	}

	return nil, ErrTPMNotAvailable
}

// AvailableTPMs returns information about available TPMs matching
// the given config, without opening the devices.
func AvailableTPMs(config *OpenConfig) ([]TPMInfo, error) {
	candidateTPMs, err := probeSystemTPMs()
	if err != nil {
		return nil, err
	}

	var out []TPMInfo

	for _, tpm := range candidateTPMs {
		t, err := openTPM(tpm)
		if err != nil {
			return nil, err
		}
		defer t.Close()
		i, err := t.Info()
		if err != nil {
			return nil, err
		}
		out = append(out, *i)

	}

	return out, nil
}
