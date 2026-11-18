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

package attributecert

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"math/big"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/go-attestation/oid"
)

func TestVerifyAttributeCert(t *testing.T) {
	testfiles := [...]string{"testdata/Intel_nuc_pc2.cer",
		"testdata/Intel_nuc_pc.cer",
		"testdata/Intel_pc2.cer",
		"testdata/Intel_pc3.cer",
	}
	data, err := os.ReadFile("testdata/IntelSigningKey_20April2017.cer")
	if err != nil {
		t.Fatalf("failed to read Intel intermediate certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		t.Fatalf("failed to parse Intel intermediate certificate: %v", err)
	}

	for _, filename := range testfiles {
		t.Run(filename, func(t *testing.T) {
			data, err = os.ReadFile(filename)
			if err != nil {
				t.Fatalf("failed to read %s: %v", filename, err)
			}

			attributecert, err := ParseAttributeCertificate(data)
			if err != nil {
				t.Fatalf("failed to parse %s: %v", filename, err)
			}

			err = attributecert.CheckSignatureFrom(cert)
			if err != nil {
				t.Fatalf("failed to verify signature on %s: %v", filename, err)
			}
		})
	}
}

func TestVerifyAttributeCertRejectsNonCAIssuer(t *testing.T) {
	signerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Non-CA Attribute Cert Signer",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  false,
		BasicConstraintsValid: true,
	}
	signerKey, signerCert := createKeyAndCert(t, signerTemplate, signerTemplate)

	_, holderCert := signCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "Test EK",
			Organization: []string{"Test Org"},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
	}, signerTemplate, signerKey)

	data, err := CreateAttributeCertificateFor(holderCert, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), signerCert, signerKey)
	if err != nil {
		t.Fatalf("CreateAttributeCertificateFor() failed: %v", err)
	}
	attributecert, err := ParseAttributeCertificate(data)
	if err != nil {
		t.Fatalf("ParseAttributeCertificate() failed: %v", err)
	}

	err = attributecert.CheckSignatureFrom(signerCert)
	if _, ok := err.(x509.ConstraintViolationError); !ok {
		t.Errorf("CheckSignatureFrom() = %v, want x509.ConstraintViolationError", err)
	}
}

func TestParseAttributeCerts(t *testing.T) {
	files, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatalf("failed to read test dir: %v", err)
	}
	for _, file := range files {
		filename := file.Name()
		if strings.Contains(filename, "Signing") {
			continue
		}
		if strings.HasSuffix(filename, ".json") {
			continue
		}
		t.Run(filename, func(t *testing.T) {
			filename := "testdata/" + filename
			jsonfile := filename + ".json"
			data, err := os.ReadFile(filename)
			if err != nil {
				t.Fatalf("failed to read test data %s: %v", filename, err)
			}
			got, err := ParseAttributeCertificate(data)
			if err != nil {
				t.Fatalf("failed to parse test data %s: %v", filename, err)
			}
			jsondata, err := os.ReadFile(jsonfile)
			if err != nil {
				t.Fatalf("failed to read json test data %s: %v", jsonfile, err)
			}
			var want AttributeCertificate
			if err := json.Unmarshal(jsondata, &want); err != nil {
				t.Fatalf("failed to unmarshal file %s: %v", filename, err)
			}
			if !reflect.DeepEqual(&want, got) {
				t.Fatalf("%s fails to match test data", filename)
			}
		})
	}
}

func createBaseAttributeCertDER(t *testing.T) []byte {
	t.Helper()
	signerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Attribute Cert Signer",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	signerKey, signerCert := createKeyAndCert(t, signerTemplate, signerTemplate)

	_, holderCert := signCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "Test EK",
			Organization: []string{"Test Org"},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
	}, signerTemplate, signerKey)

	der, err := CreateAttributeCertificateFor(holderCert, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), signerCert, signerKey)
	if err != nil {
		t.Fatalf("CreateAttributeCertificateFor() failed: %v", err)
	}
	return der
}

func mutateAttributeCertDER(t *testing.T, baseDER []byte, mutate func(*attributeCertificate)) []byte {
	t.Helper()
	var cert attributeCertificate
	if rest, err := asn1.Unmarshal(baseDER, &cert); err != nil || len(rest) != 0 {
		t.Fatalf("asn1.Unmarshal(baseDER) failed: err=%v, rest=%d", err, len(rest))
	}
	cert.Raw = nil
	cert.TBSAttributeCertificate.Raw = nil
	mutate(&cert)
	der, err := asn1.Marshal(cert)
	if err != nil {
		t.Fatalf("asn1.Marshal(attributeCertificate) failed: %v", err)
	}
	return der
}

type rawAttributeTypeAndValue struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue
}

type rawPlatformDataSET []rawAttributeTypeAndValue

func encodeSANExtensionValue(t *testing.T, directoryNameEncoding bool, attrOID asn1.ObjectIdentifier, rawVal asn1.RawValue) []byte {
	t.Helper()
	atv := rawAttributeTypeAndValue{Type: attrOID, Value: rawVal}

	var generalName asn1.RawValue
	if directoryNameEncoding {
		seqBytes, err := asn1.Marshal([]rawPlatformDataSET{{atv}})
		if err != nil {
			t.Fatalf("asn1.Marshal(PlatformDataSequence) failed: %v", err)
		}
		// X.509 GeneralName directoryName [4] EXPLICIT Name (tag 4 == asn1.TagOctetString).
		generalName = asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        4,
			IsCompound: true,
			Bytes:      seqBytes,
		}
	} else {
		atvBytes, err := asn1.Marshal(atv)
		if err != nil {
			t.Fatalf("asn1.Marshal(AttributeTypeAndValue) failed: %v", err)
		}
		generalName = asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagSet,
			IsCompound: true,
			Bytes:      atvBytes,
		}
	}

	gnBytes, err := asn1.Marshal(generalName)
	if err != nil {
		t.Fatalf("asn1.Marshal(GeneralName) failed: %v", err)
	}
	extVal, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      gnBytes,
	})
	if err != nil {
		t.Fatalf("asn1.Marshal(GeneralNames) failed: %v", err)
	}
	return extVal
}

func TestParseAttributeCertRejectsEmptyAttributeValues(t *testing.T) {
	baseDER := createBaseAttributeCertDER(t)

	// ASN.1 DER empty SET {} TLV (tag 0x31, length 0x00):
	// RFC 5755 Section 4.1 requires Attribute.values SET OF AttributeValue to contain
	// at least one element.
	emptyASN1SetDER := []byte{0x31, 0x00}

	attributeOIDs := []struct {
		name string
		id   asn1.ObjectIdentifier
	}{
		{"UserNotice", oidAttributeUserNotice},
		{"TCGPlatformSpecification", oid.TCGPlatformSpecification},
		{"TBBSecurityAssertions", oid.TBBSecurityAssertions},
		{"TCGCredentialSpecification", oid.TCGCredentialSpecification},
		{"TCGCredentialType", oid.TCGCredentialType},
		{"PlatformConfigurationV1", oid.PlatformConfigurationV1},
		{"PlatformConfigurationV2", oid.PlatformConfigurationV2},
		{"PlatformConfigURI", oid.PlatformConfigURI},
	}

	for _, tc := range attributeOIDs {
		t.Run(tc.name, func(t *testing.T) {
			der := mutateAttributeCertDER(t, baseDER, func(cert *attributeCertificate) {
				cert.TBSAttributeCertificate.Attributes = []attribute{
					{
						ID:        tc.id,
						RawValues: []asn1.RawValue{},
					},
				}
			})
			if !bytes.Contains(der, emptyASN1SetDER) {
				t.Fatalf("marshaled DER does not contain empty ASN.1 SET (0x31 0x00)")
			}

			defer func() {
				if r := recover(); r != nil {
					t.Errorf("ParseAttributeCertificate() panicked on empty attribute SET for %s: %v", tc.name, r)
				}
			}()
			if _, err := ParseAttributeCertificate(der); err == nil {
				t.Errorf("ParseAttributeCertificate() = nil error for empty attribute SET on %s, want error", tc.name)
			}
		})
	}
}

func TestParseAttributeCertRejectsNonStringSANValues(t *testing.T) {
	baseDER := createBaseAttributeCertDER(t)

	stringSANOIDs := []struct {
		name string
		id   asn1.ObjectIdentifier
	}{
		{"TcgPlatformManufacturerStrV1", oidTcgPlatformManufacturerStrV1},
		{"TcgPlatformModelV1", oidTcgPlatformModelV1},
		{"TcgPlatformVersionV1", oidTcgPlatformVersionV1},
		{"TCGCredentialSpecification", oid.TCGCredentialSpecification},
		{"PlatformManufacturerStr", oid.PlatformManufacturerStr},
		{"PlatformModel", oid.PlatformModel},
		{"PlatformVersion", oid.PlatformVersion},
		{"PlatformSerial", oid.PlatformSerial},
	}

	// Raw ASN.1 DER non-string AttributeValue payloads: encoding/asn1 decodes these
	// universal tags into non-string Go values (int64, []byte, asn1.BitString,
	// asn1.ObjectIdentifier, bool, asn1.RawValue).
	nonStringValues := []struct {
		name string
		val  asn1.RawValue
	}{
		{
			name: "INTEGER",
			// ASN.1 DER INTEGER 42 (tag 0x02, len 0x01, value 0x2a).
			val: asn1.RawValue{FullBytes: []byte{0x02, 0x01, 0x2a}},
		},
		{
			name: "OCTET_STRING",
			// ASN.1 DER OCTET STRING "abc" (tag 0x04, len 0x03, "abc").
			val: asn1.RawValue{FullBytes: []byte{0x04, 0x03, 'a', 'b', 'c'}},
		},
		{
			name: "BIT_STRING",
			// ASN.1 DER BIT STRING 0xff with 0 unused bits (tag 0x03, len 0x02, 0x00, 0xff).
			val: asn1.RawValue{FullBytes: []byte{0x03, 0x02, 0x00, 0xff}},
		},
		{
			name: "OBJECT_IDENTIFIER",
			// ASN.1 DER OBJECT IDENTIFIER 2.5.4.3 / commonName (tag 0x06, len 0x03, 0x55, 0x04, 0x03).
			val: asn1.RawValue{FullBytes: []byte{0x06, 0x03, 0x55, 0x04, 0x03}},
		},
		{
			name: "BOOLEAN",
			// ASN.1 DER BOOLEAN TRUE (tag 0x01, len 0x01, 0xff).
			val: asn1.RawValue{FullBytes: []byte{0x01, 0x01, 0xff}},
		},
		{
			name: "NULL",
			// ASN.1 DER NULL (tag 0x05, len 0x00).
			val: asn1.RawValue{FullBytes: []byte{0x05, 0x00}},
		},
	}

	encodings := []struct {
		name          string
		directoryName bool
	}{
		{"Set", false},
		{"DirectoryName", true},
	}

	for _, enc := range encodings {
		for _, oidTC := range stringSANOIDs {
			for _, valTC := range nonStringValues {
				t.Run(enc.name+"/"+oidTC.name+"/"+valTC.name, func(t *testing.T) {
					extVal := encodeSANExtensionValue(t, enc.directoryName, oidTC.id, valTC.val)
					der := mutateAttributeCertDER(t, baseDER, func(cert *attributeCertificate) {
						cert.TBSAttributeCertificate.Extensions = []pkix.Extension{
							{
								Id:    oid.SubjectAltName,
								Value: extVal,
							},
						}
					})

					defer func() {
						if r := recover(); r != nil {
							t.Errorf("ParseAttributeCertificate() panicked on non-string SAN (%s/%s/%s): %v", enc.name, oidTC.name, valTC.name, r)
						}
					}()
					if _, err := ParseAttributeCertificate(der); err == nil {
						t.Errorf("ParseAttributeCertificate() = nil error on non-string SAN (%s/%s/%s), want error", enc.name, oidTC.name, valTC.name)
					}
				})
			}
		}
	}
}

func TestParseAttributeCertRejectsMismatchedSignatureAlgorithm(t *testing.T) {
	baseDER := createBaseAttributeCertDER(t)

	testCases := []struct {
		name  string
		build func(t *testing.T) []byte
	}{
		{
			name: "DifferentOID_SHA256WithRSA_vs_SHA384WithRSA",
			build: func(t *testing.T) []byte {
				return mutateAttributeCertDER(t, baseDER, func(cert *attributeCertificate) {
					cert.SignatureAlgorithm.Algorithm = oidSignatureSHA384WithRSA
					cert.SignatureAlgorithm.Parameters = asn1.NullRawValue
				})
			},
		},
		{
			name: "DifferentOID_SHA256WithRSA_vs_ECDSAWithSHA256",
			build: func(t *testing.T) []byte {
				return mutateAttributeCertDER(t, baseDER, func(cert *attributeCertificate) {
					cert.SignatureAlgorithm.Algorithm = oidSignatureECDSAWithSHA256
					cert.SignatureAlgorithm.Parameters = emptyRawValue
				})
			},
		},
		{
			name: "Parameters_InnerNull_vs_OuterAbsent",
			build: func(t *testing.T) []byte {
				return mutateAttributeCertDER(t, baseDER, func(cert *attributeCertificate) {
					// Inner TBS SignatureAlgorithm is SHA256WithRSA with explicit ASN.1 NULL (0x05 0x00);
					// outer SignatureAlgorithm omits Parameters.
					cert.SignatureAlgorithm.Algorithm = oidSignatureSHA256WithRSA
					cert.SignatureAlgorithm.Parameters = emptyRawValue
				})
			},
		},
		{
			name: "Parameters_InnerAbsent_vs_OuterNull",
			build: func(t *testing.T) []byte {
				return mutateAttributeCertDER(t, baseDER, func(cert *attributeCertificate) {
					cert.TBSAttributeCertificate.SignatureAlgorithm.Algorithm = oidSignatureECDSAWithSHA256
					cert.TBSAttributeCertificate.SignatureAlgorithm.Parameters = emptyRawValue
					cert.SignatureAlgorithm.Algorithm = oidSignatureECDSAWithSHA256
					cert.SignatureAlgorithm.Parameters = asn1.NullRawValue
				})
			},
		},
		{
			name: "Parameters_RSAPSS_SHA256_vs_SHA384",
			build: func(t *testing.T) []byte {
				return mutateAttributeCertDER(t, baseDER, func(cert *attributeCertificate) {
					cert.TBSAttributeCertificate.SignatureAlgorithm.Algorithm = oidSignatureRSAPSS
					cert.TBSAttributeCertificate.SignatureAlgorithm.Parameters = pssParametersSHA256
					cert.SignatureAlgorithm.Algorithm = oidSignatureRSAPSS
					cert.SignatureAlgorithm.Parameters = pssParametersSHA384
				})
			},
		},
		{
			name: "TrailingElementInOuterAlgorithmIdentifierSequence",
			build: func(t *testing.T) []byte {
				var cert attributeCertificate
				if rest, err := asn1.Unmarshal(baseDER, &cert); err != nil || len(rest) != 0 {
					t.Fatalf("asn1.Unmarshal(baseDER) failed: err=%v, rest=%d", err, len(rest))
				}
				innerSigAlgDER, err := asn1.Marshal(cert.TBSAttributeCertificate.SignatureAlgorithm)
				if err != nil {
					t.Fatalf("asn1.Marshal(TBS SignatureAlgorithm) failed: %v", err)
				}
				var outerAI asn1.RawValue
				if _, err := asn1.Unmarshal(innerSigAlgDER, &outerAI); err != nil {
					t.Fatalf("asn1.Unmarshal(innerSigAlgDER) failed: %v", err)
				}
				// Append an extra ASN.1 DER INTEGER 0 (tag 0x02, len 0x01, val 0x00) inside the
				// outer AlgorithmIdentifier SEQUENCE; encoding/asn1 ignores trailing elements
				// when unmarshaling a 2-field struct, so raw SEQUENCE bytes must match.
				trailingASN1IntZero := []byte{0x02, 0x01, 0x00}
				outerAI.FullBytes = nil
				outerAI.Bytes = append(append([]byte(nil), outerAI.Bytes...), trailingASN1IntZero...)

				rawCert := struct {
					TBS            asn1.RawValue
					SignatureAlg   asn1.RawValue
					SignatureValue asn1.BitString
				}{
					TBS:            asn1.RawValue{FullBytes: cert.TBSAttributeCertificate.Raw},
					SignatureAlg:   outerAI,
					SignatureValue: cert.SignatureValue,
				}
				der, err := asn1.Marshal(rawCert)
				if err != nil {
					t.Fatalf("asn1.Marshal(rawCert) failed: %v", err)
				}
				return der
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			der := tc.build(t)
			if _, err := ParseAttributeCertificate(der); err == nil {
				t.Errorf("ParseAttributeCertificate() = nil error for mismatched signature algorithm (%s), want error", tc.name)
			}
		})
	}
}

func TestParseAttributeCertSANValidAndIgnoredAttributes(t *testing.T) {
	baseDER := createBaseAttributeCertDER(t)

	t.Run("PlatformManufacturerIDNonStringAllowed", func(t *testing.T) {
		// PlatformManufacturerID (2.23.133.5.1.3) is ignored during SAN parsing and may carry
		// a non-string ASN.1 value (such as an enterprise OID) in TCG platform certificates.
		penBytes, err := asn1.Marshal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129})
		if err != nil {
			t.Fatalf("asn1.Marshal(PEN OID) failed: %v", err)
		}
		googlePEN := asn1.RawValue{FullBytes: penBytes}

		extVal := encodeSANExtensionValue(t, true, oid.PlatformManufacturerID, googlePEN)
		der := mutateAttributeCertDER(t, baseDER, func(cert *attributeCertificate) {
			cert.TBSAttributeCertificate.Extensions = []pkix.Extension{
				{
					Id:    oid.SubjectAltName,
					Value: extVal,
				},
			}
		})
		if _, err := ParseAttributeCertificate(der); err != nil {
			t.Fatalf("ParseAttributeCertificate() unexpected error for non-string PlatformManufacturerID: %v", err)
		}
	})

	t.Run("UnknownSANOIDReturnsUnhandledError", func(t *testing.T) {
		// ASN.1 DER INTEGER 1 (tag 0x02, len 0x01, val 0x01) on unknown OID 1.2.3.4.
		intOne := asn1.RawValue{FullBytes: []byte{0x02, 0x01, 0x01}}
		extVal := encodeSANExtensionValue(t, false, asn1.ObjectIdentifier{1, 2, 3, 4}, intOne)
		der := mutateAttributeCertDER(t, baseDER, func(cert *attributeCertificate) {
			cert.TBSAttributeCertificate.Extensions = []pkix.Extension{
				{
					Id:    oid.SubjectAltName,
					Value: extVal,
				},
			}
		})
		_, err := ParseAttributeCertificate(der)
		if err == nil || !strings.Contains(err.Error(), "unhandled attribute") {
			t.Errorf("ParseAttributeCertificate() error = %v, want substring %q", err, "unhandled attribute")
		}
	})

	t.Run("ValidUTF8StringSANPopulatesFields", func(t *testing.T) {
		utf8Bytes, err := asn1.MarshalWithParams("AcmeModel-v2", "utf8")
		if err != nil {
			t.Fatalf("asn1.MarshalWithParams() failed: %v", err)
		}
		extVal := encodeSANExtensionValue(t, true, oid.PlatformModel, asn1.RawValue{FullBytes: utf8Bytes})
		der := mutateAttributeCertDER(t, baseDER, func(cert *attributeCertificate) {
			cert.TBSAttributeCertificate.Extensions = []pkix.Extension{
				{
					Id:    oid.SubjectAltName,
					Value: extVal,
				},
			}
		})
		got, err := ParseAttributeCertificate(der)
		if err != nil {
			t.Fatalf("ParseAttributeCertificate() unexpected error: %v", err)
		}
		if got.PlatformModel != "AcmeModel-v2" {
			t.Errorf("PlatformModel = %q, want %q", got.PlatformModel, "AcmeModel-v2")
		}
	})
}
