// Copyright 2026 Google Inc.
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

// Package tcg defines TCG (Trusted Computing Group) reserved TPM 2.0 handles
// and default key templates for Endorsement Keys, Storage Root Keys, and
// their certificates.
//
// These constants and templates come from:
//   - TCG EK Credential Profile v2.3 rev 2
//   - TCG TPM v2.0 Provisioning Guidance v1r1
//   - Registry of Reserved TPM 2.0 Handles and Localities
package tcg

import (
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"

	"github.com/google/go-attestation/oid"
	"github.com/google/go-attestation/x509"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var emptyHash = sha256.Sum256(nil)

// EKProfile describes a TCG-defined Endorsement Key profile, linking a key
// algorithm/size to its standard persistent key handle, NVRAM certificate
// index, optional NVRAM template/nonce indices, and normative default template.
type EKProfile struct {
	// Name is a human-readable label (e.g. "L-1 RSA 2048").
	Name string
	// KeyHandle is the TCG-reserved persistent handle for this EK.
	KeyHandle tpmutil.Handle
	// CertHandle is the TCG-reserved NVRAM index for this EK's certificate.
	CertHandle tpmutil.Handle
	// TemplateHandle is the TCG-reserved NVRAM index for this EK's template.
	// 0 means no template index is defined for this profile.
	TemplateHandle tpmutil.Handle
	// NonceHandle is the TCG-reserved NVRAM index for this EK's nonce
	// (used to populate the unique field of the template).
	// 0 means no nonce index is defined for this profile.
	NonceHandle tpmutil.Handle
	// DefaultTemplate is the TCG-specified default TPMT_PUBLIC template.
	DefaultTemplate tpm2.Public
}

// Persistent SRK Key Handles (0x81000000 – 0x8100FFFF)
//
// From "TCG TPM v2.0 Provisioning Guidance" v1r1.
const (
	SRKKeyRSA2048Handle = tpmutil.Handle(0x81000001)
	SRKKeyECCP256Handle = tpmutil.Handle(0x81000002)
)

// Persistent EK Key Handles (0x81010001 – 0x810100FF)
//
// From "TCG TPM v2.0 Provisioning Guidance" v1r1, Table 2, and
// "TCG EK Credential Profile" v2.3r2, Section 2.2.1.
const (
	// L-template key handles (original TCG profiles)
	EKKeyRSA2048Handle = tpmutil.Handle(0x81010001)
	EKKeyECCP256Handle = tpmutil.Handle(0x81010002)

	// H-template key handles (added in EK Credential Profile v2.3)
	EKKeyAltRSA2048Handle = tpmutil.Handle(0x81010003)
	EKKeyAltECCP256Handle = tpmutil.Handle(0x81010004)
	EKKeyECCP384Handle    = tpmutil.Handle(0x81010005)
	EKKeyECCP521Handle    = tpmutil.Handle(0x81010006)
	EKKeySM2P256Handle    = tpmutil.Handle(0x81010007)
	EKKeyRSA3072Handle    = tpmutil.Handle(0x81010008)
	EKKeyRSA4096Handle    = tpmutil.Handle(0x81010009)
)

// NVRAM EK Certificate Indices (0x01C00000 – 0x01C0FFFF)
//
// From "TCG EK Credential Profile" v2.3r2, Section 2.2.1.4.
const (
	// L-template certificate NVRAM indices
	EKCertRSA2048Index = tpmutil.Handle(0x01C00002)
	EKCertECCP256Index = tpmutil.Handle(0x01C0000A)

	// H-template certificate NVRAM indices
	EKCertAltRSA2048Index = tpmutil.Handle(0x01C00012)
	EKCertAltECCP256Index = tpmutil.Handle(0x01C00014)
	EKCertECCP384Index    = tpmutil.Handle(0x01C00016)
	EKCertECCP521Index    = tpmutil.Handle(0x01C00018)
	EKCertSM2P256Index    = tpmutil.Handle(0x01C0001A)
	EKCertRSA3072Index    = tpmutil.Handle(0x01C0001C)
	EKCertRSA4096Index    = tpmutil.Handle(0x01C0001E)
)

// EK Nonce NVRAM Indices
//
// Nonces are used to populate the unique field of L-template EKs.
// From "TCG EK Credential Profile" v2.3r2.
const (
	EKNonceRSA2048Index = tpmutil.Handle(0x01C00003)
	EKNonceECCP256Index = tpmutil.Handle(0x01C0000B)
)

// EK Template NVRAM Indices
//
// Templates are stored in NVRAM only when the TPM manufacturer uses
// non-default EK templates. If absent, the TCG default template for that
// algorithm/key size should be used.
const (
	// L-template NVRAM indices
	EKTemplateRSA2048Index = tpmutil.Handle(0x01C00004)
	EKTemplateECCP256Index = tpmutil.Handle(0x01C0000C)

	// H-template NVRAM indices
	EKTemplateAltRSA2048Index = tpmutil.Handle(0x01C00013)
	EKTemplateAltECCP256Index = tpmutil.Handle(0x01C00015)
	EKTemplateECCP384Index    = tpmutil.Handle(0x01C00017)
	EKTemplateECCP521Index    = tpmutil.Handle(0x01C00019)
	EKTemplateSM2P256Index    = tpmutil.Handle(0x01C0001B)
	EKTemplateRSA3072Index    = tpmutil.Handle(0x01C0001D)
	EKTemplateRSA4096Index    = tpmutil.Handle(0x01C0001F)
)

// Default TCG SRK and EK Templates
var (
	// Default RSASRKTemplate contains the TCG reference RSA-2048 SRK template.
	// Defined in TCG TPM v2.0 Provisioning Guidance v1r1.
	DefaultRSASRKTemplate = tpm2.Public{
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
	// Default ECCSRKTemplate contains the TCG reference ECC P-256 SRK template.
	// Defined in TCG TPM v2.0 Provisioning Guidance v1r1.
	DefaultECCSRKTemplate = tpm2.Public{
		Type:       tpm2.AlgECC,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagStorageDefault | tpm2.FlagNoDA,
		ECCParameters: &tpm2.ECCParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			CurveID: tpm2.CurveNISTP256,
			Point: tpm2.ECPoint{
				XRaw: make([]byte, 32),
				YRaw: make([]byte, 32),
			},
		},
	}

	// Default RSA-2048 EK template (Template L-1 / H-1).
	// Defined in TCG EK Credential Profile v2.0/v2.3.
	DefaultRSA2048EKTemplate = tpm2.Public{
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
	// Default ECC P-256 EK template (Template L-2 / H-2).
	// Defined in TCG EK Credential Profile v2.0/v2.3.
	DefaultECCP256EKTemplate = tpm2.Public{
		Type:    tpm2.AlgECC,
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
		ECCParameters: &tpm2.ECCParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			CurveID: tpm2.CurveNISTP256,
		},
	}
	// Default ECC P-384 EK template (Template H-3).
	// Defined in TCG EK Credential Profile v2.3r2.
	DefaultECCP384EKTemplate = tpm2.Public{
		Type:    tpm2.AlgECC,
		NameAlg: tpm2.AlgSHA384,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagAdminWithPolicy | tpm2.FlagRestricted | tpm2.FlagDecrypt,
		AuthPolicy: []byte{
			0xB2, 0x6E, 0x7D, 0x28, 0xD1, 0x1A, 0x50, 0xBC,
			0x53, 0xD8, 0x82, 0xBC, 0xF5, 0xFD, 0x3A, 0x1A,
			0x07, 0x41, 0x48, 0xBB, 0x35, 0xD3, 0xB4, 0xE4,
			0xCB, 0x1C, 0x0A, 0xD9, 0xBD, 0xE4, 0x19, 0xCA,
			0xCB, 0x47, 0xBA, 0x09, 0x69, 0x96, 0x46, 0x15,
			0x0F, 0x9F, 0xC0, 0x00, 0xF3, 0xF8, 0x0E, 0x12,
		},
		ECCParameters: &tpm2.ECCParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 256,
				Mode:    tpm2.AlgCFB,
			},
			CurveID: tpm2.CurveNISTP384,
		},
	}
	// Default ECC P-521 EK template (Template H-4).
	// Defined in TCG EK Credential Profile v2.3r2.
	DefaultECCP521EKTemplate = tpm2.Public{
		Type:    tpm2.AlgECC,
		NameAlg: tpm2.AlgSHA512,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagAdminWithPolicy | tpm2.FlagRestricted | tpm2.FlagDecrypt,
		AuthPolicy: []byte{
			0xB8, 0x22, 0x1C, 0xA6, 0x9E, 0x85, 0x50, 0xA4,
			0x91, 0x4D, 0xE3, 0xFA, 0xA6, 0xA1, 0x8C, 0x07,
			0x2C, 0xC0, 0x12, 0x08, 0x07, 0x3A, 0x92, 0x8D,
			0x5D, 0x66, 0xD5, 0x9E, 0xF7, 0x9E, 0x49, 0xA4,
			0x29, 0xC4, 0x1A, 0x6B, 0x26, 0x95, 0x71, 0xD5,
			0x7E, 0xDB, 0x25, 0xFB, 0xDB, 0x18, 0x38, 0x42,
			0x56, 0x08, 0xB4, 0x13, 0xCD, 0x61, 0x6A, 0x5F,
			0x6D, 0xB5, 0xB6, 0x07, 0x1A, 0xF9, 0x9B, 0xEA,
		},
		ECCParameters: &tpm2.ECCParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 256,
				Mode:    tpm2.AlgCFB,
			},
			CurveID: tpm2.CurveNISTP521,
		},
	}
	// Default RSA 3072 EK template (Template H-6).
	// Defined in TCG EK Credential Profile v2.3r2.
	DefaultRSA3072EKTemplate = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA384,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagAdminWithPolicy | tpm2.FlagRestricted | tpm2.FlagDecrypt,
		AuthPolicy: []byte{
			0xB2, 0x6E, 0x7D, 0x28, 0xD1, 0x1A, 0x50, 0xBC,
			0x53, 0xD8, 0x82, 0xBC, 0xF5, 0xFD, 0x3A, 0x1A,
			0x07, 0x41, 0x48, 0xBB, 0x35, 0xD3, 0xB4, 0xE4,
			0xCB, 0x1C, 0x0A, 0xD9, 0xBD, 0xE4, 0x19, 0xCA,
			0xCB, 0x47, 0xBA, 0x09, 0x69, 0x96, 0x46, 0x15,
			0x0F, 0x9F, 0xC0, 0x00, 0xF3, 0xF8, 0x0E, 0x12,
		},
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 256,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits:    3072,
			ModulusRaw: make([]byte, 384),
		},
	}
	// Default RSA 4096 EK template (Template H-7).
	// Defined in TCG EK Credential Profile v2.3r2.
	DefaultRSA4096EKTemplate = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA384,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagAdminWithPolicy | tpm2.FlagRestricted | tpm2.FlagDecrypt,
		AuthPolicy: []byte{
			0xB2, 0x6E, 0x7D, 0x28, 0xD1, 0x1A, 0x50, 0xBC,
			0x53, 0xD8, 0x82, 0xBC, 0xF5, 0xFD, 0x3A, 0x1A,
			0x07, 0x41, 0x48, 0xBB, 0x35, 0xD3, 0xB4, 0xE4,
			0xCB, 0x1C, 0x0A, 0xD9, 0xBD, 0xE4, 0x19, 0xCA,
			0xCB, 0x47, 0xBA, 0x09, 0x69, 0x96, 0x46, 0x15,
			0x0F, 0x9F, 0xC0, 0x00, 0xF3, 0xF8, 0x0E, 0x12,
		},
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 256,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits:    4096,
			ModulusRaw: make([]byte, 512),
		},
	}
)

// Profiles lists all TCG-defined EK profiles with their paired key,
// certificate, template, and nonce handles, and default template.
var Profiles = []EKProfile{
	// L-templates (original TCG profiles)
	{
		Name:            "L-1 RSA 2048",
		KeyHandle:       EKKeyRSA2048Handle,
		CertHandle:      EKCertRSA2048Index,
		TemplateHandle:  EKTemplateRSA2048Index,
		NonceHandle:     EKNonceRSA2048Index,
		DefaultTemplate: DefaultRSA2048EKTemplate,
	},
	{
		Name:            "L-2 ECC P-256",
		KeyHandle:       EKKeyECCP256Handle,
		CertHandle:      EKCertECCP256Index,
		TemplateHandle:  EKTemplateECCP256Index,
		NonceHandle:     EKNonceECCP256Index,
		DefaultTemplate: DefaultECCP256EKTemplate,
	},

	// H-templates (EK Credential Profile v2.3)
	{
		Name:            "H-1 RSA 2048",
		KeyHandle:       EKKeyAltRSA2048Handle,
		CertHandle:      EKCertAltRSA2048Index,
		TemplateHandle:  EKTemplateAltRSA2048Index,
		DefaultTemplate: DefaultRSA2048EKTemplate,
	},
	{
		Name:            "H-2 ECC P-256",
		KeyHandle:       EKKeyAltECCP256Handle,
		CertHandle:      EKCertAltECCP256Index,
		TemplateHandle:  EKTemplateAltECCP256Index,
		DefaultTemplate: DefaultECCP256EKTemplate,
	},
	{
		Name:            "H-3 ECC P-384",
		KeyHandle:       EKKeyECCP384Handle,
		CertHandle:      EKCertECCP384Index,
		TemplateHandle:  EKTemplateECCP384Index,
		DefaultTemplate: DefaultECCP384EKTemplate,
	},
	{
		Name:            "H-4 ECC P-521",
		KeyHandle:       EKKeyECCP521Handle,
		CertHandle:      EKCertECCP521Index,
		TemplateHandle:  EKTemplateECCP521Index,
		DefaultTemplate: DefaultECCP521EKTemplate,
	},
	{
		Name:            "H-5 SM2 P-256",
		KeyHandle:       EKKeySM2P256Handle,
		CertHandle:      EKCertSM2P256Index,
		TemplateHandle:  EKTemplateSM2P256Index,
		DefaultTemplate: DefaultECCP256EKTemplate,
	},
	{
		Name:            "H-6 RSA 3072",
		KeyHandle:       EKKeyRSA3072Handle,
		CertHandle:      EKCertRSA3072Index,
		TemplateHandle:  EKTemplateRSA3072Index,
		DefaultTemplate: DefaultRSA3072EKTemplate,
	},
	{
		Name:            "H-7 RSA 4096",
		KeyHandle:       EKKeyRSA4096Handle,
		CertHandle:      EKCertRSA4096Index,
		TemplateHandle:  EKTemplateRSA4096Index,
		DefaultTemplate: DefaultRSA4096EKTemplate,
	},
}

// ProfileByCertHandle returns the EKProfile for the given NVRAM cert index,
// or nil if no profile is found.
func ProfileByCertHandle(certHandle tpmutil.Handle) *EKProfile {
	for i := range Profiles {
		if Profiles[i].CertHandle == certHandle {
			return &Profiles[i]
		}
	}
	return nil
}

// TemplateForCertHandle returns the TCG-specified default EK template
// for the given NVRAM certificate index, or nil if not defined.
func TemplateForCertHandle(certHandle tpmutil.Handle) *tpm2.Public {
	if p := ProfileByCertHandle(certHandle); p != nil {
		t := p.DefaultTemplate
		return &t
	}
	return nil
}

// KeyHandles returns all TCG-reserved persistent EK key handles.
func KeyHandles() []tpmutil.Handle {
	handles := make([]tpmutil.Handle, len(Profiles))
	for i, p := range Profiles {
		handles[i] = p.KeyHandle
	}
	return handles
}

// CertHandles returns all TCG-reserved NVRAM EK certificate indices.
func CertHandles() []tpmutil.Handle {
	handles := make([]tpmutil.Handle, len(Profiles))
	for i, p := range Profiles {
		handles[i] = p.CertHandle
	}
	return handles
}

// DefaultSubjectAltName returns a TCG-compliant SubjectAltName extension
// containing TPM Manufacturer, Model, and Version attributes per the
// TCG EK Credential Profile.
func DefaultSubjectAltName(manufacturer, model, version string) (pkix.Extension, error) {
	san := &x509ext.SubjectAltName{
		DirectoryNames: []pkix.Name{
			{
				ExtraNames: []pkix.AttributeTypeAndValue{
					{
						Type:  oid.TPMManufacturer,
						Value: manufacturer,
					},
					{
						Type:  oid.TPMModel,
						Value: model,
					},
					{
						Type:  oid.TPMVersion,
						Value: version,
					},
				},
			},
		},
		PermanentIdentifiers: []x509ext.PermanentIdentifier{
			{
				IdentifierValue: hex.EncodeToString(emptyHash[:]),
				Assigner:        oid.EKPermIDSHA256,
			},
		},
	}
	return x509ext.MarshalSubjectAltName(san, false)
}

// EncodeSubjectDirectoryAttributes serializes TPM specification attributes
// (family, level, revision) into a SubjectDirectoryAttributes extension per the
// TCG EK Credential Profile.
func EncodeSubjectDirectoryAttributes(family string, level, revision int) (pkix.Extension, error) {
	var b cryptobyte.Builder
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oid.TPMSpecification)
			b.AddASN1(cryptobyte_asn1.SET, func(b *cryptobyte.Builder) {
				b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1(cryptobyte_asn1.UTF8String, func(b *cryptobyte.Builder) {
						b.AddBytes([]byte(family))
					})
					b.AddASN1Int64(int64(level))
					b.AddASN1Int64(int64(revision))
				})
			})
		})
	})
	val, err := b.Bytes()
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("encoding subject directory attributes: %w", err)
	}
	return pkix.Extension{
		Id:    oid.SubjectDirectoryAttributes,
		Value: val,
	}, nil
}
