// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package oid contains X.509 and TCG ASN.1 object identifiers.
package oid

import "encoding/asn1"

// Trusted Computing Group (2.23.133)
var (
	TPMManufacturer            = asn1.ObjectIdentifier{2, 23, 133, 2, 1}
	TPMModel                   = asn1.ObjectIdentifier{2, 23, 133, 2, 2}
	TPMVersion                 = asn1.ObjectIdentifier{2, 23, 133, 2, 3}
	TCGPlatformSpecification   = asn1.ObjectIdentifier{2, 23, 133, 2, 17}
	TBBSecurityAssertions      = asn1.ObjectIdentifier{2, 23, 133, 2, 19}
	TPMSpecification           = asn1.ObjectIdentifier{2, 23, 133, 2, 16}
	TCGCredentialSpecification = asn1.ObjectIdentifier{2, 23, 133, 2, 23}
	TCGCredentialType          = asn1.ObjectIdentifier{2, 23, 133, 2, 25}
	PlatformManufacturerStr    = asn1.ObjectIdentifier{2, 23, 133, 5, 1, 1}
	PlatformManufacturerID     = asn1.ObjectIdentifier{2, 23, 133, 5, 1, 2}
	PlatformConfigURI          = asn1.ObjectIdentifier{2, 23, 133, 5, 1, 3}
	PlatformModel              = asn1.ObjectIdentifier{2, 23, 133, 5, 1, 4}
	PlatformVersion            = asn1.ObjectIdentifier{2, 23, 133, 5, 1, 5}
	PlatformSerial             = asn1.ObjectIdentifier{2, 23, 133, 5, 1, 6}
	PlatformConfigurationV1    = asn1.ObjectIdentifier{2, 23, 133, 5, 1, 7, 1}
	PlatformConfigurationV2    = asn1.ObjectIdentifier{2, 23, 133, 5, 1, 7, 2}
)

// X.509 (2.23.23)
//
// https://www.itu.int/ITU-T/recommendations/rec.aspx?rec=14033
// https://tools.ietf.org/html/rfc5280
var (
	SubjectDirectoryAttributes = asn1.ObjectIdentifier{2, 5, 29, 9}
	SubjectAltName             = asn1.ObjectIdentifier{2, 5, 29, 17}
	CertificatePolicies        = asn1.ObjectIdentifier{2, 5, 29, 32}
)
