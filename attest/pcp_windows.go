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
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"syscall"
	"unsafe"

	"github.com/google/go-tpm/tpmutil"
	tpmtbs "github.com/google/go-tpm/tpmutil/tbs"
	"golang.org/x/sys/windows"
)

const (
	pcpProviderName = "Microsoft Platform Crypto Provider"
	cryptENotFound  = 0x80092004 // From winerror.h.

	// The below is documented in this Microsoft whitepaper:
	// https://github.com/Microsoft/TSS.MSR/blob/master/PCPTool.v11/Using%20the%20Windows%208%20Platform%20Crypto%20Provider%20and%20Associated%20TPM%20Functionality.pdf
	ncryptOverwriteKeyFlag = 0x80
	// Key usage value for AKs.
	nCryptPropertyPCPKeyUsagePolicyIdentity = 0x8
)

// DLL references.
var (
	nCrypt                    = windows.MustLoadDLL("ncrypt.dll")
	nCryptOpenStorageProvider = nCrypt.MustFindProc("NCryptOpenStorageProvider")
	nCryptFreeObject          = nCrypt.MustFindProc("NCryptFreeObject")
	nCryptGetProperty         = nCrypt.MustFindProc("NCryptGetProperty")
	nCryptSetProperty         = nCrypt.MustFindProc("NCryptSetProperty")
	nCryptOpenKey             = nCrypt.MustFindProc("NCryptOpenKey")
	nCryptCreatePersistedKey  = nCrypt.MustFindProc("NCryptCreatePersistedKey")
	nCryptFinalizeKey         = nCrypt.MustFindProc("NCryptFinalizeKey")
	nCryptDeleteKey           = nCrypt.MustFindProc("NCryptDeleteKey")

	crypt32                            = windows.MustLoadDLL("crypt32.dll")
	crypt32CertEnumCertificatesInStore = crypt32.MustFindProc("CertEnumCertificatesInStore")
	crypt32CertCloseStore              = crypt32.MustFindProc("CertCloseStore")

	tbs              *windows.DLL
	tbsGetDeviceInfo *windows.Proc
)

func maybeWinErr(errNo uintptr) error {
	if errData, known := tpmErrNums[uint32(errNo)]; known {
		return fmt.Errorf("tpm or subsystem failure: %s: %s", errData.name, errData.description)
	}
	return nil
}

func utf16ToString(buf []byte) (string, error) {
	b := make([]uint16, len(buf)/2)
	// LPCSTR (Windows' representation of utf16) is always little endian.
	if err := binary.Read(bytes.NewReader(buf), binary.LittleEndian, &b); err != nil {
		return "", err
	}
	return windows.UTF16ToString(b), nil
}

// closeNCryptoObject is a helper to call NCryptFreeObject on a given handle.
func closeNCryptObject(hnd uintptr) error {
	r, _, msg := nCryptFreeObject.Call(hnd)
	if r != 0 {
		if tpmErr := maybeWinErr(r); tpmErr != nil {
			return tpmErr
		}
		return fmt.Errorf("NCryptFreeObject returned %X: %v", r, msg)
	}
	return nil
}

// getNCryptBufferProperty is a helper to read a byte slice from a NCrypt handle property
// using NCryptGetProperty.
func getNCryptBufferProperty(hnd uintptr, field string) ([]byte, error) {
	var size uint32
	wideField, err := windows.UTF16FromString(field)
	if err != nil {
		return nil, err
	}

	r, _, msg := nCryptGetProperty.Call(hnd, uintptr(unsafe.Pointer(&wideField[0])), 0, 0, uintptr(unsafe.Pointer(&size)), 0)
	if r != 0 {
		if tpmErr := maybeWinErr(r); tpmErr != nil {
			msg = tpmErr
		}
		return nil, fmt.Errorf("NCryptGetProperty returned %d,%X (%v) for key %q on size read", size, r, msg, field)
	}
	buff := make([]byte, size)
	r, _, msg = nCryptGetProperty.Call(hnd, uintptr(unsafe.Pointer(&wideField[0])), uintptr(unsafe.Pointer(&buff[0])), uintptr(size), uintptr(unsafe.Pointer(&size)), 0)
	if r != 0 {
		if tpmErr := maybeWinErr(r); tpmErr != nil {
			msg = tpmErr
		}
		return nil, fmt.Errorf("NCryptGetProperty returned %X (%v) for key %q on data read", r, msg, field)
	}
	return buff, nil
}

// winPCP represents a reference to the Platform Crypto Provider.
type winPCP struct {
	hProv uintptr
}

// tbsDeviceInfo represents TPM device information from the TBS
// API. This structure is identical to _TBS_DEVICE_INFO in tbs.h.
type tbsDeviceInfo struct {
	TBSVersion                uint32
	TPMVersion                uint32
	TPMInterfaceType          uint32
	TPMImplementationRevision uint32
}

// windowsTPMInfo describes the versions of the TPM and OS interface code.
type windowsTPMInfo struct {
	Manufacturer string
	PCPVersion   string
	TBSInfo      tbsDeviceInfo
}

// TPMInfo returns version information about the TPM & OS interface code.
func (h *winPCP) TPMInfo() (*windowsTPMInfo, error) {
	var err error
	out := &windowsTPMInfo{}

	buf, err := getNCryptBufferProperty(h.hProv, "PCP_PLATFORM_TYPE")
	if err != nil {
		return nil, fmt.Errorf("Failed to read PCP_PLATFORM_TYPE: %v", err)
	}
	out.Manufacturer, err = utf16ToString(buf)
	if err != nil {
		return nil, err
	}

	buf, err = getNCryptBufferProperty(h.hProv, "PCP_PROVIDER_VERSION")
	if err != nil {
		return nil, fmt.Errorf("Failed to read PCP_PROVIDER_VERSION: %v", err)
	}
	out.PCPVersion, err = utf16ToString(buf)
	if err != nil {
		return nil, err
	}

	r, _, msg := tbsGetDeviceInfo.Call(unsafe.Sizeof(out.TBSInfo), uintptr(unsafe.Pointer(&out.TBSInfo)))
	if r != 0 {
		return nil, fmt.Errorf("Failed to call Tbsi_GetDeviceInfo: %v", msg)
	}

	return out, nil
}

// TPMCommandInterface returns an interface where TPM commands can issued directly.
func (h *winPCP) TPMCommandInterface() (io.ReadWriteCloser, error) {
	var provTBS tpmtbs.Context
	var sz uint32
	platformHndField, err := windows.UTF16FromString("PCP_PLATFORMHANDLE")
	if err != nil {
		return nil, err
	}

	r, _, err := nCryptGetProperty.Call(h.hProv, uintptr(unsafe.Pointer(&platformHndField[0])), uintptr(unsafe.Pointer(&provTBS)), unsafe.Sizeof(provTBS), uintptr(unsafe.Pointer(&sz)), 0)
	if r != 0 {
		if tpmErr := maybeWinErr(r); tpmErr != nil {
			err = tpmErr
		}
		return nil, fmt.Errorf("NCryptGetProperty for platform handle returned %X (%v)", r, err)
	}

	return tpmutil.FromContext(provTBS), nil
}

// TPMKeyHandle returns a transient handle to the given key on the TPM.
func (h *winPCP) TPMKeyHandle(hnd uintptr) (tpmutil.Handle, error) {
	var keyHndTBS tpmutil.Handle
	var sz uint32
	platformHndField, err := windows.UTF16FromString("PCP_PLATFORMHANDLE")
	if err != nil {
		return 0, err
	}

	if r, _, err := nCryptGetProperty.Call(hnd, uintptr(unsafe.Pointer(&platformHndField[0])), uintptr(unsafe.Pointer(&keyHndTBS)), unsafe.Sizeof(keyHndTBS), uintptr(unsafe.Pointer(&sz)), 0); r != 0 {
		if tpmErr := maybeWinErr(r); tpmErr != nil {
			err = tpmErr
		}
		return 0, fmt.Errorf("NCryptGetProperty for hKey platform handle returned %X (%v)", r, err)
	}

	return keyHndTBS, nil
}

// Close releases all resources managed by the Handle.
func (h *winPCP) Close() error {
	return closeNCryptObject(h.hProv)
}

// DeleteKey permanently removes the key with the given handle from the system,
// and frees its handle.
func (h *winPCP) DeleteKey(kh uintptr) error {
	r, _, msg := nCryptDeleteKey.Call(kh, 0)
	if r != 0 {
		return fmt.Errorf("nCryptDeleteKey returned %X: %v", r, msg)
	}
	return nil
}

// EKCerts returns the Endorsement Certificates.
// Failure to fetch an ECC certificate is not considered
// an error as they do not exist on all platforms.
func (h *winPCP) EKCerts() ([]*x509.Certificate, error) {
	c, err := getPCPCerts(h.hProv, "PCP_RSA_EKNVCERT")
	if err != nil {
		return nil, err
	}
	eccCerts, err := getPCPCerts(h.hProv, "PCP_ECC_EKNVCERT")
	if err == nil { // ECC certs are not present on all platforms
		c = append(c, eccCerts...)
	}

	// Reading the certificate from the system store has failed.
	// Lets try reading the raw bytes directly from NVRAM instead.
	if len(c) == 0 {
		certs, err := getPCPCerts(h.hProv, "PCP_EKNVCERT")
		if err != nil {
			return nil, fmt.Errorf("Failed to read PCP_EKNVCERT: %v", err)
		}
		c = append(c, certs...)
	}

	var out []*x509.Certificate
	for _, der := range c {
		cert, err := ParseEKCertificate(der)
		if err != nil {
			return nil, err
		}
		out = append(out, cert)
	}

	return out, nil
}

// getPCPCerts is a helper to iterate over a certificates in a cert store,
// whose handle was obtained by reading a specific property on a PCP handle.
func getPCPCerts(hProv uintptr, propertyName string) ([][]byte, error) {
	var size, cryptCertHnd uintptr
	utf16PropName, err := windows.UTF16FromString(propertyName)
	if err != nil {
		return nil, err
	}

	r, _, msg := nCryptGetProperty.Call(hProv, uintptr(unsafe.Pointer(&utf16PropName[0])), uintptr(unsafe.Pointer(&cryptCertHnd)), 8, uintptr(unsafe.Pointer(&size)), 0)
	if r != 0 {
		return nil, fmt.Errorf("NCryptGetProperty returned %X, %v", r, msg)
	}
	defer crypt32CertCloseStore.Call(uintptr(unsafe.Pointer(cryptCertHnd)), 0)

	var out [][]byte
	var certContext uintptr
	for {
		certContext, _, msg = crypt32CertEnumCertificatesInStore.Call(uintptr(unsafe.Pointer(cryptCertHnd)), certContext)
		if certContext == 0 && msg != nil {
			if errno, ok := msg.(syscall.Errno); ok {
				// cryptENotFound is returned when there are no more certificates to iterate through.
				if errno == cryptENotFound {
					break
				}
			}
			return nil, msg
		}
		cert := (*syscall.CertContext)(unsafe.Pointer(certContext))
		// Copy the buffer. This was taken straight from the Go source: src/crypto/x509/root_windows.go#L70
		buf := (*[1 << 20]byte)(unsafe.Pointer(cert.EncodedCert))[:]
		buf2 := make([]byte, cert.Length)
		copy(buf2, buf)
		out = append(out, buf2)
	}
	return out, nil
}

// NewAK creates a persistent attestation key of the specified name.
func (h *winPCP) NewAK(name string, alg Algorithm) (uintptr, error) {
	var kh uintptr
	utf16Name, err := windows.UTF16FromString(name)
	if err != nil {
		return 0, err
	}
	utf16Alg, err := windows.UTF16FromString(string(alg))
	if err != nil {
		return 0, err
	}

	// Create a persistent RSA key of the specified name.
	r, _, msg := nCryptCreatePersistedKey.Call(h.hProv, uintptr(unsafe.Pointer(&kh)), uintptr(unsafe.Pointer(&utf16Alg[0])), uintptr(unsafe.Pointer(&utf16Name[0])), 0, 0)
	if r != 0 {
		if tpmErr := maybeWinErr(r); tpmErr != nil {
			msg = tpmErr
		}
		return 0, fmt.Errorf("NCryptCreatePersistedKey returned %X: %v", r, msg)
	}
	// Specify generated key length to be 2048 bits.
	utf16Length, err := windows.UTF16FromString("Length")
	if err != nil {
		return 0, err
	}
	var length uint32 = uint32(alg.Size())
	r, _, msg = nCryptSetProperty.Call(kh, uintptr(unsafe.Pointer(&utf16Length[0])), uintptr(unsafe.Pointer(&length)), unsafe.Sizeof(length), 0)
	if r != 0 {
		if tpmErr := maybeWinErr(r); tpmErr != nil {
			msg = tpmErr
		}
		return 0, fmt.Errorf("NCryptSetProperty (Length) returned %X: %v", r, msg)
	}
	// Specify the generated key can only be used for identity attestation.
	utf16KeyPolicy, err := windows.UTF16FromString("PCP_KEY_USAGE_POLICY")
	if err != nil {
		return 0, err
	}
	var policy uint32 = nCryptPropertyPCPKeyUsagePolicyIdentity
	r, _, msg = nCryptSetProperty.Call(kh, uintptr(unsafe.Pointer(&utf16KeyPolicy[0])), uintptr(unsafe.Pointer(&policy)), unsafe.Sizeof(policy), 0)
	if r != 0 {
		if tpmErr := maybeWinErr(r); tpmErr != nil {
			msg = tpmErr
		}
		return 0, fmt.Errorf("NCryptSetProperty (PCP KeyUsage Policy) returned %X: %v", r, msg)
	}

	// Finalize (create) the key.
	r, _, msg = nCryptFinalizeKey.Call(kh, 0)
	if r != 0 {
		if tpmErr := maybeWinErr(r); tpmErr != nil {
			msg = tpmErr
		}
		return 0, fmt.Errorf("NCryptFinalizeKey returned %X: %v", r, msg)
	}

	return kh, nil
}

// EKPub returns a BCRYPT_RSA_BLOB structure representing the EK.
func (h *winPCP) EKPub() ([]byte, error) {
	return getNCryptBufferProperty(h.hProv, "PCP_EKPUB")
}

type akProps struct {
	RawPublic       []byte
	RawCreationData []byte
	RawAttest       []byte
	RawSignature    []byte
}

// AKProperties returns the binding properties of the given attestation
// key. Note that it is only valid to call this function with the same
// winPCP handle within which the AK was created.
func (h *winPCP) AKProperties(kh uintptr) (*akProps, error) {
	idBlob, err := getNCryptBufferProperty(kh, "PCP_TPM12_IDBINDING")
	if err != nil {
		return nil, err
	}
	r := bytes.NewReader(idBlob)
	// Because the TPM 1.2 blob leads with a version tag,
	// we can switch decoding logic based on it.
	if bytes.Equal(idBlob[0:4], []byte{1, 1, 0, 0}) {
		return decodeAKProps12(r)
	}
	return decodeAKProps20(r)
}

// decodeAKProps12 separates the single TPM 1.2 blob from the PCP property
// into its constituents, returning information about the public key
// of the AK.
func decodeAKProps12(r *bytes.Reader) (*akProps, error) {
	var out akProps
	// Skip over fixed-size fields in TPM_IDENTITY_CONTENTS which
	// we don't need to read.
	// Specifically: ver, ordinal, & labelPrivCADigest.
	r.Seek(4+4+20, io.SeekCurrent)
	pubKeyStartIdx := int(r.Size()) - r.Len()

	// Skip over fixed-size key parameters in TPM_PUBKEY, so
	// we can read the length of the exponent &
	// determine where the pubkey structure ends.
	// Specifically: algID, encScheme, sigScheme, paramSize, keyLength,
	// and numPrimes.
	r.Seek(4+2+2+4+4+4, io.SeekCurrent)

	// Read the size of the exponent section.
	var exponentSize uint32
	if err := binary.Read(r, binary.BigEndian, &exponentSize); err != nil {
		return nil, fmt.Errorf("failed to decode exponentSize: %v", err)
	}
	// Consume the bytes representing the exponent.
	exp := make([]byte, int(exponentSize))
	if err := binary.Read(r, binary.BigEndian, &exp); err != nil {
		return nil, fmt.Errorf("failed to decode exp: %v", err)
	}
	// Read the size of the key data.
	var keyDataSize uint32
	if err := binary.Read(r, binary.BigEndian, &keyDataSize); err != nil {
		return nil, fmt.Errorf("failed to decode keyDataSize: %v", err)
	}
	// Seek to the end of the key data.
	r.Seek(int64(keyDataSize), io.SeekCurrent)

	// Read the trailing signature.
	out.RawSignature = make([]byte, r.Len())
	if err := binary.Read(r, binary.BigEndian, &out.RawSignature); err != nil {
		return nil, fmt.Errorf("failed to decode signature: %v", err)
	}

	// Seek back to the location of the public key, and consume it.
	r.Seek(int64(pubKeyStartIdx), io.SeekStart)
	out.RawPublic = make([]byte, 24+int(exponentSize)+4+int(keyDataSize))
	if err := binary.Read(r, binary.BigEndian, &out.RawPublic); err != nil {
		return nil, fmt.Errorf("failed to decode public: %v", err)
	}

	return &out, nil
}

// decodeAKProps20 separates the single TPM 2.0 blob from the PCP property
// into its constituents. For TPM 2.0 devices, these are bytes representing
// the following structures: TPM2B_PUBLIC, TPM2B_CREATION_DATA, TPM2B_ATTEST,
// and TPMT_SIGNATURE.
func decodeAKProps20(r *bytes.Reader) (*akProps, error) {
	var out akProps

	var publicSize uint16
	if err := binary.Read(r, binary.BigEndian, &publicSize); err != nil {
		return nil, fmt.Errorf("failed to decode TPM2B_PUBLIC.size: %v", err)
	}
	out.RawPublic = make([]byte, publicSize)
	if err := binary.Read(r, binary.BigEndian, &out.RawPublic); err != nil {
		return nil, fmt.Errorf("failed to decode TPM2B_PUBLIC.data: %v", err)
	}

	var creationDataSize uint16
	if err := binary.Read(r, binary.BigEndian, &creationDataSize); err != nil {
		return nil, fmt.Errorf("failed to decode TPM2B_CREATION_DATA.size: %v", err)
	}
	out.RawCreationData = make([]byte, creationDataSize)
	if err := binary.Read(r, binary.BigEndian, &out.RawCreationData); err != nil {
		return nil, fmt.Errorf("failed to decode TPM2B_CREATION_DATA.data: %v", err)
	}

	var attestSize uint16
	if err := binary.Read(r, binary.BigEndian, &attestSize); err != nil {
		return nil, fmt.Errorf("failed to decode TPM2B_ATTEST.size: %v", err)
	}
	out.RawAttest = make([]byte, attestSize)
	if err := binary.Read(r, binary.BigEndian, &out.RawAttest); err != nil {
		return nil, fmt.Errorf("failed to decode TPM2B_ATTEST.data: %v", err)
	}

	// The encoded TPMT_SIGNATURE structure represents the remaining bytes in
	// the ID binding blob.
	out.RawSignature = make([]byte, r.Len())
	if err := binary.Read(r, binary.BigEndian, &out.RawSignature); err != nil {
		return nil, fmt.Errorf("failed to decode TPMT_SIGNATURE.data: %v", err)
	}
	return &out, nil
}

// LoadKeyByName returns a handle to the persistent PCP key with the specified
// name.
func (h *winPCP) LoadKeyByName(name string) (uintptr, error) {
	utf16Name, err := windows.UTF16FromString(name)
	if err != nil {
		return 0, err
	}

	var hKey uintptr
	r, _, msg := nCryptOpenKey.Call(h.hProv, uintptr(unsafe.Pointer(&hKey)), uintptr(unsafe.Pointer(&utf16Name[0])), 0, 0)
	if r != 0 {
		if tpmErr := maybeWinErr(r); tpmErr != nil {
			msg = tpmErr
		}
		return 0, fmt.Errorf("NCryptOpenKey returned %X (%v) for key %q", r, msg, name)
	}
	return hKey, nil
}

// ActivateCredential performs TPM2_ActivateCredential or TPM_ActivateIdentity.
func (h *winPCP) ActivateCredential(hKey uintptr, activationBlob []byte) ([]byte, error) {
	utf16ActivationStr, err := windows.UTF16FromString("PCP_TPM12_IDACTIVATION")
	if err != nil {
		return nil, err
	}

	r, _, msg := nCryptSetProperty.Call(hKey, uintptr(unsafe.Pointer(&utf16ActivationStr[0])), uintptr(unsafe.Pointer(&activationBlob[0])), uintptr(len(activationBlob)), 0)
	if r != 0 {
		if tpmErr := maybeWinErr(r); tpmErr != nil {
			msg = tpmErr
		}
		return nil, fmt.Errorf("NCryptSetProperty returned %X (%v) for key activation", r, msg)
	}

	return getNCryptBufferProperty(hKey, "PCP_TPM12_IDACTIVATION")
}

// openPCP initializes a reference to the Microsoft PCP provider.
// The Caller is expected to call Close() when they are done.
func openPCP() (*winPCP, error) {
	var err error
	var h winPCP
	pname, err := windows.UTF16FromString(pcpProviderName)
	if err != nil {
		return nil, err
	}

	r, _, err := nCryptOpenStorageProvider.Call(uintptr(unsafe.Pointer(&h.hProv)), uintptr(unsafe.Pointer(&pname[0])), 0)
	if r != 0 { // r is non-zero on error, err is always populated in this case.
		if tpmErr := maybeWinErr(r); tpmErr != nil {
			return nil, tpmErr
		}
		return nil, err
	}
	return &h, nil
}
