// Copyright 2009 The Go Authors. All rights reserved.
// Copyright 2019 Google, LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package attributecert parses X.509-encoded attribute certificates.
package attributecert

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"
)

var (
	oidExtensionSubjectDirectoryAttributes = []int{2, 5, 29, 9}
	oidExtensionSubjectAltName             = []int{2, 5, 29, 17}
	oidExtensionCertificatePolicies        = []int{2, 5, 29, 32}
	oidExtensionAuthorityKeyIdentifier     = []int{2, 5, 29, 35}
	oidAuthorityInfoAccess                 = []int{1, 3, 6, 1, 5, 5, 7, 1, 1}
	oidCpsCertificatePolicy                = []int{1, 3, 6, 1, 5, 5, 7, 2, 1}
	oidAttributeUserNotice                 = []int{1, 3, 6, 1, 5, 5, 7, 2, 2}
	oidAuthorityInfoAccessOcsp             = []int{1, 3, 6, 1, 5, 5, 7, 48, 1}
	oidAuthorityInfoAccessIssuers          = []int{1, 3, 6, 1, 5, 5, 7, 48, 2}
	oidTcgCertificatePolicy                = []int{1, 2, 840, 113741, 1, 5, 2, 4}
	oidTcgAttribute                        = []int{2, 23, 133, 2}
	oidTpmManufacturer                     = []int{2, 23, 133, 2, 1}
	oidTpmModel                            = []int{2, 23, 133, 2, 2}
	oidTpmVersion                          = []int{2, 23, 133, 2, 3}
	oidTcgPlatformManufacturerStrV1        = []int{2, 23, 133, 2, 4}
	oidTcgPlatformModelV1                  = []int{2, 23, 133, 2, 5}
	oidTcgPlatformVersionV1                = []int{2, 23, 133, 2, 6}
	oidSecurityQualities                   = []int{2, 23, 133, 2, 10}
	oidTpmProtectionProfile                = []int{2, 23, 133, 2, 11}
	oidTpmSecurityTarget                   = []int{2, 23, 133, 2, 12}
	oidTbbProtectionProfile                = []int{2, 23, 133, 2, 13}
	oidTbbSecurityTarget                   = []int{2, 23, 133, 2, 14}
	oidTpmIDLabel                          = []int{2, 23, 133, 2, 15}
	oidTpmSpecification                    = []int{2, 23, 133, 2, 16}
	oidTcgPlatformSpecification            = []int{2, 23, 133, 2, 17}
	oidTpmSecurityAssertions               = []int{2, 23, 133, 2, 18}
	oidTbbSecurityAssertions               = []int{2, 23, 133, 2, 19}
	oidTcgCredentialSpecification          = []int{2, 23, 133, 2, 23}
	oidTcgCredentialType                   = []int{2, 23, 133, 2, 25}
	oidTcgPlatformClass                    = []int{2, 23, 133, 5}
	oidTcgCommon                           = []int{2, 23, 133, 5, 1}
	oidTcgPlatformManufacturerStrV2        = []int{2, 23, 133, 5, 1, 1}
	oidTcgPlatformManufacturerIDV2         = []int{2, 23, 133, 5, 1, 2}
	oidTcgPlatformConfigURI                = []int{2, 23, 133, 5, 1, 3}
	oidTcgPlatformModelV2                  = []int{2, 23, 133, 5, 1, 4}
	oidTcgPlatformVersionV2                = []int{2, 23, 133, 5, 1, 5}
	oidTcgPlatformSerialV2                 = []int{2, 23, 133, 5, 1, 6}
	oidTcgPlatformConfiguration            = []int{2, 23, 133, 5, 1, 7}
	oidTcgPlatformConfigurationV1          = []int{2, 23, 133, 5, 1, 7, 1}
	oidTcgPlatformConfigurationV2          = []int{2, 23, 133, 5, 1, 7, 2}
)

var (
	oidSignatureRSAPSS  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidSignatureEd25519 = asn1.ObjectIdentifier{1, 3, 101, 112}

	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	oidMGF1 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
)

var signatureAlgorithmDetails = []struct {
	algo       x509.SignatureAlgorithm
	name       string
	oid        asn1.ObjectIdentifier
	pubKeyAlgo x509.PublicKeyAlgorithm
	hash       crypto.Hash
}{
	{x509.SHA256WithRSAPSS, "SHA256-RSAPSS", oidSignatureRSAPSS, x509.RSA, crypto.SHA256},
	{x509.SHA384WithRSAPSS, "SHA384-RSAPSS", oidSignatureRSAPSS, x509.RSA, crypto.SHA384},
	{x509.SHA512WithRSAPSS, "SHA512-RSAPSS", oidSignatureRSAPSS, x509.RSA, crypto.SHA512},
	{x509.PureEd25519, "Ed25519", oidSignatureEd25519, x509.Ed25519, crypto.Hash(0) /* no pre-hashing */},
}

// pssParameters reflects the parameters in an AlgorithmIdentifier that
// specifies RSA PSS. See RFC 3447, Appendix A.2.3.
type pssParameters struct {
	// The following three fields are not marked as
	// optional because the default values specify SHA-1,
	// which is no longer suitable for use in signatures.
	Hash         pkix.AlgorithmIdentifier `asn1:"explicit,tag:0"`
	MGF          pkix.AlgorithmIdentifier `asn1:"explicit,tag:1"`
	SaltLength   int                      `asn1:"explicit,tag:2"`
	TrailerField int                      `asn1:"optional,explicit,tag:3,default:1"`
}

func getSignatureAlgorithmFromAI(ai pkix.AlgorithmIdentifier) x509.SignatureAlgorithm {
	if ai.Algorithm.Equal(oidSignatureEd25519) {
		// RFC 8410, Section 3
		// > For all of the OIDs, the parameters MUST be absent.
		if len(ai.Parameters.FullBytes) != 0 {
			return x509.UnknownSignatureAlgorithm
		}
	}

	if !ai.Algorithm.Equal(oidSignatureRSAPSS) {
		for _, details := range signatureAlgorithmDetails {
			if ai.Algorithm.Equal(details.oid) {
				return details.algo
			}
		}
		return x509.UnknownSignatureAlgorithm
	}

	// RSA PSS is special because it encodes important parameters
	// in the Parameters.

	var params pssParameters
	if _, err := asn1.Unmarshal(ai.Parameters.FullBytes, &params); err != nil {
		return x509.UnknownSignatureAlgorithm
	}

	var mgf1HashFunc pkix.AlgorithmIdentifier
	if _, err := asn1.Unmarshal(params.MGF.Parameters.FullBytes, &mgf1HashFunc); err != nil {
		return x509.UnknownSignatureAlgorithm
	}

	// PSS is greatly overburdened with options. This code forces them into
	// three buckets by requiring that the MGF1 hash function always match the
	// message hash function (as recommended in RFC 3447, Section 8.1), that the
	// salt length matches the hash length, and that the trailer field has the
	// default value.
	if (len(params.Hash.Parameters.FullBytes) != 0 && !bytes.Equal(params.Hash.Parameters.FullBytes, asn1.NullBytes)) ||
		!params.MGF.Algorithm.Equal(oidMGF1) ||
		!mgf1HashFunc.Algorithm.Equal(params.Hash.Algorithm) ||
		(len(mgf1HashFunc.Parameters.FullBytes) != 0 && !bytes.Equal(mgf1HashFunc.Parameters.FullBytes, asn1.NullBytes)) ||
		params.TrailerField != 1 {
		return x509.UnknownSignatureAlgorithm
	}

	switch {
	case params.Hash.Algorithm.Equal(oidSHA256) && params.SaltLength == 32:
		return x509.SHA256WithRSAPSS
	case params.Hash.Algorithm.Equal(oidSHA384) && params.SaltLength == 48:
		return x509.SHA384WithRSAPSS
	case params.Hash.Algorithm.Equal(oidSHA512) && params.SaltLength == 64:
		return x509.SHA512WithRSAPSS
	}

	return x509.UnknownSignatureAlgorithm
}

//RFC 5280 4.2.2.1
type authorityInfoAccess struct {
	Method   asn1.ObjectIdentifier
	Location asn1.RawValue
}

//RFC 5280 4.2.1.1
type authKeyID struct {
	ID           []byte        `asn1:"optional,tag:0"`
	IssuerName   asn1.RawValue `asn1:"set,optional,tag:1"`
	SerialNumber *big.Int      `asn1:"optional,tag:2"`
}

//RFC 5280 4.2.1.4
type cpsPolicy struct {
	ID    asn1.ObjectIdentifier
	Value string
}

//RFC 5280 4.2.1.4
type policyInformation struct {
	Raw    asn1.RawContent
	ID     asn1.ObjectIdentifier
	Policy asn1.RawValue
}

//RFC 5280 4.1.2.5
type validity struct {
	NotBefore, NotAfter time.Time
}

//RFC 5280 4.2.1.4
type NoticeReference struct {
	Organization  string
	NoticeNumbers []int
}

//RFC 5280 4.2.1.4
type userNotice struct {
	NoticeRef    NoticeReference `asn1:"optional"`
	ExplicitText string          `asn1:"optional"`
}

//RFC 5755 4.1
type objectDigestInfo struct {
	DigestedObjectType asn1.Enumerated
	OtherObjectTypeID  asn1.ObjectIdentifier
	DigestAlgorithm    pkix.AlgorithmIdentifier
	ObjectDigest       asn1.BitString
}

//RFC 5755 4.1
type attCertIssuer struct {
	IssuerName        asn1.RawValue    `asn1:"set,optional"`
	BaseCertificateID issuerSerial     `asn1:"optional,tag:0"`
	ObjectDigestInfo  objectDigestInfo `asn1:"optional,tag:1"`
}

//RFC 5755 4.1
type issuerSerial struct {
	Raw       asn1.RawContent
	Issuer    asn1.RawValue
	Serial    *big.Int
	IssuerUID asn1.BitString `asn1:"optional"`
}

//RFC 5755 4.1
type holder struct {
	Raw               asn1.RawContent
	BaseCertificateID issuerSerial     `asn1:"optional,tag:0"`
	EntityName        pkix.Extension   `asn1:"optional,tag:1"`
	ObjectDigestInfo  objectDigestInfo `asn1:"optional,tag:2"`
}

//RFC 5755 4.1
type attribute struct {
	ID        asn1.ObjectIdentifier
	RawValues []asn1.RawValue `asn1:"set"`
}

//RFC 5755 4.1
type tbsAttributeCertificate struct {
	Raw                asn1.RawContent
	Version            int
	Holder             holder
	Issuer             attCertIssuer `asn1:"tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SerialNumber       *big.Int
	Validity           validity
	Attributes         []attribute
	IssuerUniqueID     asn1.BitString   `asn1:"optional"`
	Extensions         []pkix.Extension `asn1:"optional"`
}

type attributeCertificate struct {
	Raw                     asn1.RawContent
	TBSAttributeCertificate tbsAttributeCertificate
	SignatureAlgorithm      pkix.AlgorithmIdentifier
	SignatureValue          asn1.BitString
}

type Certholder struct {
	Issuer pkix.Name
	Serial *big.Int
}

type AttributeCertificate struct {
	Raw                        []byte // Complete ASN.1 DER content (certificate, signature algorithm and signature).
	RawTBSAttributeCertificate []byte // Certificate part of raw ASN.1 DER content.

	Signature          []byte
	SignatureAlgorithm x509.SignatureAlgorithm

	Version                  int
	SerialNumber             *big.Int
	Holder                   Certholder
	Issuer                   pkix.Name
	Subject                  pkix.Name
	NotBefore, NotAfter      time.Time // Validity bounds.
	TCGPlatformSpecification TCGPlatformSpecification
	TBBSecurityAssertions    TBBSecurityAssertions
	PlatformManufacturer     string
	PlatformModel            string
	PlatformVersion          string
	PlatformSerial           string
	CredentialSpecification  string
	UserNotice               userNotice
}

// ParseAttributeCertificate parses a single attribute certificate from the
// given ASN.1 DER data.
func ParseAttributeCertificate(asn1Data []byte) (*AttributeCertificate, error) {
	var cert attributeCertificate

	rest, err := asn1.Unmarshal(asn1Data, &cert)
	if err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, asn1.SyntaxError{Msg: "attributecert: trailing data"}
	}

	return parseAttributeCertificate(&cert)
}

type PlatformDataSequence []PlatformDataSET
type PlatformDataSET []pkix.AttributeTypeAndValue

type TCGData struct {
	ID   asn1.ObjectIdentifier
	Data string
}

type TCGDirectoryEntry struct {
	ID   asn1.ObjectIdentifier
	Data asn1.RawValue
}

type TCGSpecificationVersion struct {
	MajorVersion int
	MinorVersion int
	Revision     int
}

type TCGPlatformSpecification struct {
	Version TCGSpecificationVersion
}

type TCGCredentialSpecification struct {
	Version TCGSpecificationVersion
}

type TCGCredentialType struct {
	CertificateType asn1.ObjectIdentifier
}

type FipsLevel struct {
	Version string
	Level   asn1.Enumerated
	Plus    bool
}

type CommonCriteriaMeasures struct {
	Version            string
	AssuranceLevel     asn1.Enumerated
	EvaluationStatus   asn1.Enumerated
	Plus               bool
	StrengthOfFunction asn1.Enumerated       `asn1:"optional,tag=0"`
	ProfileOid         asn1.ObjectIdentifier `asn1:"optional,tag=1"`
	ProfileURI         string                `asn1:"optional,tag=2"`
	TargetOid          asn1.ObjectIdentifier `asn1:"optional,tag=3"`
	TargetURI          asn1.ObjectIdentifier `asn1:"optional,tag=4"`
}

type TBBSecurityAssertions struct {
	Version          int
	CcInfo           CommonCriteriaMeasures `asn1:"optional,tag=0"`
	FipsLevel        FipsLevel              `asn1:"optional,tag=1"`
	RtmType          asn1.Enumerated        `asn1:"optional,tag=2"`
	Iso9000Certified bool                   `asn1:"optional"`
	Iso9000URI       string                 `asn1:"optional"`
}

type Property struct {
	PropertyName  string
	PropertyValue string
	Status        asn1.Enumerated `asn1:"optional,tag=0"`
}

type AttributeCertificateIdentifier struct {
	HashAlgorithm          pkix.AlgorithmIdentifier
	HashOverSignatureValue string
}

type CertificateIdentifier struct {
	AttributeCertIdentifier AttributeCertificateIdentifier `asn1:"optional,tag=0"`
	GenericCertIdientifier  issuerSerial                   `asn1:"optional,tag=1"`
}

type ComponentAddress struct {
	AddressType  asn1.ObjectIdentifier
	AddressValue string
}

type ComponentClass struct {
	ComponentClassRegistry asn1.ObjectIdentifier
	ComponentClassValue    string
}

type ComponentIdentifierV2 struct {
	ComponentClass           ComponentClass
	ComponentManufacturer    string
	ComponentModel           string
	ComponentSerial          string                `asn1:"optional,tag=0"`
	ComponentRevision        string                `asn1:"optional,tag=1"`
	ComponentManufacturerID  int                   `asn1:"optional,tag=2"`
	FieldReplaceable         bool                  `asn1:"optional,tag=3"`
	ComponentAddresses       []ComponentAddress    `asn1:"optional,tag=4"`
	ComponentPlatformCert    CertificateIdentifier `asn1:"optional,tag=5"`
	ComponentPlatformCertURI string                `asn1:"optional,tag=6"`
	Status                   asn1.Enumerated       `asn1:"optional,tag=7"`
}

type URIReference struct {
	UniformResourceIdentifier string
	HashAlgorithm             pkix.AlgorithmIdentifier `asn1:"optional"`
	HashValue                 string                   `asn1:"optional"`
}

type PlatformConfigurationV2 struct {
	ComponentIdentifiers    []ComponentIdentifierV2 `asn1:"optional,tag=0"`
	ComponentIdentifiersURI URIReference            `asn1:"optional,tag=1"`
	PlatformProperties      []Property              `asn1:"optional,tag=2"`
	PlatformPropertiesURI   URIReference            `asn1:"optional,tag=3"`
}

type ComponentIdentifierV1 struct {
	ComponentManufacturer   string
	ComponentModel          string
	ComponentSerial         string             `asn1:"optional,tag=0"`
	ComponentRevision       string             `asn1:"optional,tag=1"`
	ComponentManufacturerId int                `asn1:"optional,tag=2"`
	FieldReplaceable        bool               `asn1:"optional,tag=3"`
	ComponentAddresses      []ComponentAddress `asn1:"optional,tag=4"`
}

type PlatformConfigurationV1 struct {
	ComponentIdentifiers  []ComponentIdentifierV1 `asn1:"optional,tag=0"`
	PlatformProperties    []Property              `asn1:"optional,tag=1"`
	PlatformPropertiesURI []URIReference          `asn1:"optional,tag=2"`
}

func unmarshalSAN(v asn1.RawValue) ([]pkix.AttributeTypeAndValue, error) {
	if v.Tag == asn1.TagSet {
		var e pkix.AttributeTypeAndValue
		if _, err := asn1.Unmarshal(v.Bytes, &e); err != nil {
			return nil, err
		}
		return []pkix.AttributeTypeAndValue{e}, nil
	} else if v.Tag == asn1.TagOctetString {
		var attributes []pkix.AttributeTypeAndValue
		var platformData PlatformDataSequence
		rest, err := asn1.Unmarshal(v.Bytes, &platformData)
		if err != nil {
			return nil, err
		} else if len(rest) != 0 {
			return nil, errors.New("attributecert: trailing data after X.509 subject")
		}
		for _, e := range platformData {
			for _, e2 := range e {
				attributes = append(attributes, e2)
			}
		}
		return attributes, nil
	}
	return nil, fmt.Errorf("attributecert: unexpected SAN type %v", v.Tag)
}

func parseAttributeCertificate(in *attributeCertificate) (*AttributeCertificate, error) {
	out := &AttributeCertificate{
		Raw:                        in.Raw,
		RawTBSAttributeCertificate: in.TBSAttributeCertificate.Raw,
		Signature:                  in.SignatureValue.RightAlign(),
		SignatureAlgorithm:         getSignatureAlgorithmFromAI(in.TBSAttributeCertificate.SignatureAlgorithm),
		Version:                    in.TBSAttributeCertificate.Version + 1,
		SerialNumber:               in.TBSAttributeCertificate.SerialNumber,
	}

	var v asn1.RawValue
	if _, err := asn1.Unmarshal(in.TBSAttributeCertificate.Issuer.IssuerName.Bytes, &v); err != nil {
		return nil, err
	}

	var issuer pkix.RDNSequence
	if rest, err := asn1.Unmarshal(v.Bytes, &issuer); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("attributecert: trailing data after X.509 subject")
	}

	out.Issuer.FillFromRDNSequence(&issuer)
	if _, err := asn1.Unmarshal(in.TBSAttributeCertificate.Holder.BaseCertificateID.Issuer.Bytes, &v); err != nil {
		return nil, err
	}

	var holder pkix.RDNSequence
	if rest, err := asn1.Unmarshal(v.Bytes, &holder); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("attributecert: trailing data after X.509 subject")
	}

	out.Holder.Issuer.FillFromRDNSequence(&holder)
	out.Holder.Serial = in.TBSAttributeCertificate.Holder.BaseCertificateID.Serial

	out.NotBefore = in.TBSAttributeCertificate.Validity.NotBefore
	out.NotAfter = in.TBSAttributeCertificate.Validity.NotAfter

	for _, attribute := range in.TBSAttributeCertificate.Attributes {
		switch {
		case attribute.ID.Equal(oidAttributeUserNotice):
			if _, err := asn1.Unmarshal(attribute.RawValues[0].FullBytes, &out.UserNotice); err != nil {
				return nil, err
			}
		case attribute.ID.Equal(oidTcgPlatformSpecification):
			if _, err := asn1.Unmarshal(attribute.RawValues[0].FullBytes, &out.TCGPlatformSpecification); err != nil {
				return nil, err
			}
		case attribute.ID.Equal(oidTbbSecurityAssertions):
			if _, err := asn1.Unmarshal(attribute.RawValues[0].FullBytes, &out.TBBSecurityAssertions); err != nil {
				return nil, err
			}
		case attribute.ID.Equal(oidTcgCredentialSpecification):
			var credentialSpecification TCGCredentialSpecification
			if _, err := asn1.Unmarshal(attribute.RawValues[0].FullBytes, &credentialSpecification); err != nil {
				var credentialSpecification TCGSpecificationVersion
				if _, err := asn1.Unmarshal(attribute.RawValues[0].FullBytes, &credentialSpecification); err != nil {
					return nil, err
				}
			}
		case attribute.ID.Equal(oidTcgCredentialType):
			var credentialType TCGCredentialType
			if _, err := asn1.Unmarshal(attribute.RawValues[0].FullBytes, &credentialType); err != nil {
				return nil, err
			}
		case attribute.ID.Equal(oidTcgPlatformConfigurationV1):
			var platformConfiguration PlatformConfigurationV1
			if _, err := asn1.Unmarshal(attribute.RawValues[0].FullBytes, &platformConfiguration); err != nil {
				return nil, err
			}
		case attribute.ID.Equal(oidTcgPlatformConfigurationV2):
			var platformConfiguration PlatformConfigurationV2
			if _, err := asn1.Unmarshal(attribute.RawValues[0].FullBytes, &platformConfiguration); err != nil {
				return nil, err
			}
		case attribute.ID.Equal(oidTcgPlatformConfigURI):
			var platformConfigurationURI URIReference
			if _, err := asn1.Unmarshal(attribute.RawValues[0].FullBytes, &platformConfigurationURI); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("attributecert: unknown attribute %v", attribute.ID)
		}
	}

	for _, extension := range in.TBSAttributeCertificate.Extensions {
		switch {
		case extension.Id.Equal(oidExtensionSubjectAltName):
			var seq asn1.RawValue
			rest, err := asn1.Unmarshal(extension.Value, &seq)
			if err != nil {
				return nil, err
			} else if len(rest) != 0 {
				return nil, errors.New("attributecert: trailing data after X.509 extension")
			}
			rest = seq.Bytes
			for len(rest) > 0 {
				var v asn1.RawValue
				rest, err = asn1.Unmarshal(rest, &v)
				if err != nil {
					return nil, err
				}
				tcgdata, err := unmarshalSAN(v)
				if err != nil {
					return nil, fmt.Errorf("attributecert: failed to unmarshal SAN: %v", err)
				}
				for _, e := range tcgdata {
					switch {
					case e.Type.Equal(oidTcgPlatformManufacturerStrV1):
						out.PlatformManufacturer = e.Value.(string)
					case e.Type.Equal(oidTcgPlatformModelV1):
						out.PlatformModel = e.Value.(string)
					case e.Type.Equal(oidTcgPlatformVersionV1):
						out.PlatformVersion = e.Value.(string)
					case e.Type.Equal(oidTcgCredentialSpecification):
						// This OID appears to be misused in this context
						out.PlatformSerial = e.Value.(string)
					case e.Type.Equal(oidTcgPlatformManufacturerStrV2):
						out.PlatformManufacturer = e.Value.(string)
					case e.Type.Equal(oidTcgPlatformManufacturerIDV2):
						// We can't parse these out at present
						break
					case e.Type.Equal(oidTcgPlatformModelV2):
						out.PlatformModel = e.Value.(string)
					case e.Type.Equal(oidTcgPlatformVersionV2):
						out.PlatformVersion = e.Value.(string)
					case e.Type.Equal(oidTcgPlatformSerialV2):
						out.PlatformSerial = e.Value.(string)
					default:
						return nil, fmt.Errorf("attributecert: unhandled attribute: %v", e.Type)
					}
				}
			}

		case extension.Id.Equal(oidExtensionSubjectDirectoryAttributes):
			var seq asn1.RawValue
			rest, err := asn1.Unmarshal(extension.Value, &seq)
			if err != nil {
				return nil, err
			} else if len(rest) != 0 {
				return nil, errors.New("attributecert: trailing data after X.509 extension")
			}
			rest = seq.Bytes
			for len(rest) > 0 {
				var e TCGDirectoryEntry
				rest, err = asn1.Unmarshal(rest, &e)
				if err != nil {
					return nil, err
				}
				switch {
				case e.ID.Equal(oidTcgPlatformSpecification):
					var platformSpecification TCGPlatformSpecification
					_, err := asn1.Unmarshal(e.Data.Bytes, &platformSpecification)
					if err != nil {
						return nil, err
					}
					out.TCGPlatformSpecification = platformSpecification
				case e.ID.Equal(oidTbbSecurityAssertions):
					var securityAssertions TBBSecurityAssertions
					_, err := asn1.Unmarshal(e.Data.Bytes, &securityAssertions)
					if err != nil {
						return nil, err
					}
					out.TBBSecurityAssertions = securityAssertions
				default:
					return nil, fmt.Errorf("attributecert: unhandled TCG directory attribute: %v", e.ID)
				}
			}

		case extension.Id.Equal(oidExtensionCertificatePolicies):
			var policies []policyInformation
			_, err := asn1.Unmarshal(extension.Value, &policies)
			if err != nil {
				return nil, err
			}
			for _, policy := range policies {
				if policy.ID.Equal(oidTcgCertificatePolicy) {
					var subpolicies []policyInformation
					_, err := asn1.Unmarshal(policy.Policy.FullBytes, &subpolicies)
					if err != nil {
						return nil, err
					}
					for _, subpolicy := range subpolicies {
						switch {
						case subpolicy.ID.Equal(oidCpsCertificatePolicy):
							var cpsPolicy cpsPolicy
							_, err := asn1.Unmarshal(subpolicy.Raw, &cpsPolicy)
							if err != nil {
								return nil, err
							}
						case subpolicy.ID.Equal(oidAttributeUserNotice):
							var userNotice string
							_, err := asn1.Unmarshal(subpolicy.Policy.Bytes, &userNotice)
							if err != nil {
								return nil, err
							}
						default:
							return nil, fmt.Errorf("attributecert: unhandled certificate policy: %v", subpolicy.ID)
						}
					}
				}
			}

		case extension.Id.Equal(oidExtensionAuthorityKeyIdentifier):
			var a authKeyID
			_, err := asn1.Unmarshal(extension.Value, &a)
			if err != nil {
				return nil, err
			}

		case extension.Id.Equal(oidAuthorityInfoAccess):
			var aia []authorityInfoAccess
			_, err := asn1.Unmarshal(extension.Value, &aia)
			if err != nil {
				return nil, err
			}
			for _, v := range aia {
				if v.Method.Equal(oidAuthorityInfoAccessOcsp) {
					//TODO
				} else if v.Method.Equal(oidAuthorityInfoAccessIssuers) {
					//TODO
				} else {
					return nil, fmt.Errorf("attributecert: unhandled Authority Info Access type %v", v.Method)
				}
			}

		default:
			return nil, fmt.Errorf("attributecert: unknown extension ID %v", extension.Id)
		}
	}

	return out, nil
}

// CheckSignatureFrom verifies that the signature on c is a valid signature
// from parent.
func (c *AttributeCertificate) CheckSignatureFrom(parent *x509.Certificate) error {
	// RFC 5280, 4.2.1.9:
	// "If the basic constraints extension is not present in a version 3
	// certificate, or the extension is present but the cA boolean is not
	// asserted, then the certified public key MUST NOT be used to verify
	// certificate signatures."
	if parent.Version == 3 && !parent.BasicConstraintsValid ||
		parent.BasicConstraintsValid && !parent.IsCA {
		return x509.ConstraintViolationError{}
	}

	if parent.KeyUsage != 0 && parent.KeyUsage&x509.KeyUsageCertSign == 0 {
		return x509.ConstraintViolationError{}
	}

	if parent.PublicKeyAlgorithm == x509.UnknownPublicKeyAlgorithm {
		return x509.ErrUnsupportedAlgorithm
	}

	// TODO(agl): don't ignore the path length constraint.

	return parent.CheckSignature(c.SignatureAlgorithm, c.RawTBSAttributeCertificate, c.Signature)
}
