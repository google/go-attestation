// Package x509ext provides functions for (un)marshalling X.509 extensions not
// supported by the crypto/x509 package.
package x509ext

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/google/go-attestation/oid"
)

// RFC 4043
//
// https://tools.ietf.org/html/rfc4043
var (
	oidPermanentIdentifier = []int{1, 3, 6, 1, 5, 5, 7, 8, 3}
)

//	OtherName ::= SEQUENCE {
//	  type-id    OBJECT IDENTIFIER,
//	  value      [0] EXPLICIT ANY DEFINED BY type-id }
type otherName struct {
	TypeID asn1.ObjectIdentifier
	Value  asn1.RawValue
}

func marshalOtherName(typeID asn1.ObjectIdentifier, value interface{}) (asn1.RawValue, error) {
	valueBytes, err := asn1.MarshalWithParams(value, "explicit,tag:0")
	if err != nil {
		return asn1.RawValue{}, err
	}
	otherName := otherName{
		TypeID: typeID,
		Value:  asn1.RawValue{FullBytes: valueBytes},
	}
	bytes, err := asn1.MarshalWithParams(otherName, "tag:0")
	if err != nil {
		return asn1.RawValue{}, err
	}
	return asn1.RawValue{FullBytes: bytes}, nil
}

// PermanentIdentifier represents an ASN.1 encoded "permanent identifier" as
// defined by RFC4043.
//
//	PermanentIdentifier ::= SEQUENCE {
//	    identifierValue    UTF8String OPTIONAL,
//	    assigner           OBJECT IDENTIFIER OPTIONAL
//	   }
//
// https://datatracker.ietf.org/doc/html/rfc4043
type PermanentIdentifier struct {
	IdentifierValue string                `asn1:"utf8,optional"`
	Assigner        asn1.ObjectIdentifier `asn1:"optional"`
}

func parsePermanentIdentifier(der []byte) (PermanentIdentifier, error) {
	var permID PermanentIdentifier
	if _, err := asn1.UnmarshalWithParams(der, &permID, "explicit,tag:0"); err != nil {
		return PermanentIdentifier{}, err
	}
	return permID, nil
}

// SubjectAltName contains GeneralName variations not supported by the
// crypto/x509 package.
//
// https://datatracker.ietf.org/doc/html/rfc5280
type SubjectAltName struct {
	DirectoryNames       []pkix.Name
	PermanentIdentifiers []PermanentIdentifier
}

// ParseSubjectAltName parses a pkix.Extension into a SubjectAltName struct.
func ParseSubjectAltName(ext pkix.Extension) (*SubjectAltName, error) {
	var out SubjectAltName
	dirNames, otherNames, err := parseSubjectAltName(ext)
	if err != nil {
		return nil, fmt.Errorf("parseSubjectAltName: %v", err)
	}
	out.DirectoryNames = dirNames

	for _, otherName := range otherNames {
		if otherName.TypeID.Equal(oidPermanentIdentifier) {
			permID, err := parsePermanentIdentifier(otherName.Value.FullBytes)
			if err != nil {
				return nil, fmt.Errorf("parsePermanentIdentifier: %v", err)
			}
			out.PermanentIdentifiers = append(out.PermanentIdentifiers, permID)
		}
	}
	return &out, nil
}

// https://datatracker.ietf.org/doc/html/rfc5280#page-35
func parseSubjectAltName(ext pkix.Extension) (dirNames []pkix.Name, otherNames []otherName, err error) {
	err = forEachSAN(ext.Value, func(generalName asn1.RawValue) error {
		switch generalName.Tag {
		case 0: // otherName
			var otherName otherName
			if _, err := asn1.UnmarshalWithParams(generalName.FullBytes, &otherName, "tag:0"); err != nil {
				return fmt.Errorf("OtherName: asn1.UnmarshalWithParams: %v", err)
			}
			otherNames = append(otherNames, otherName)
		case 4: // directoryName
			var rdns pkix.RDNSequence
			if _, err := asn1.Unmarshal(generalName.Bytes, &rdns); err != nil {
				return fmt.Errorf("DirectoryName: asn1.Unmarshal: %v", err)
			}
			var dirName pkix.Name
			dirName.FillFromRDNSequence(&rdns)
			dirNames = append(dirNames, dirName)
		default:
			return fmt.Errorf("expected tag %d", generalName.Tag)
		}
		return nil
	})
	return
}

// Borrowed from the x509 package.
func forEachSAN(extension []byte, callback func(ext asn1.RawValue) error) error {
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(extension, &seq)
	if err != nil {
		return err
	} else if len(rest) != 0 {
		return errors.New("x509: trailing data after X.509 extension")
	}
	if !seq.IsCompound || seq.Tag != 16 || seq.Class != 0 {
		return asn1.StructuralError{Msg: "bad SAN sequence"}
	}

	rest = seq.Bytes
	for len(rest) > 0 {
		var v asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &v)
		if err != nil {
			return err
		}

		if err := callback(v); err != nil {
			return err
		}
	}

	return nil
}

// MarshalSubjectAltName converts a SubjectAltName struct into a pkix.Extension,
// allowing callers to specify if the extension is critical.
func MarshalSubjectAltName(san *SubjectAltName, critical bool) (pkix.Extension, error) {
	var generalNames []asn1.RawValue
	for _, permID := range san.PermanentIdentifiers {
		val, err := marshalOtherName(oidPermanentIdentifier, permID)
		if err != nil {
			return pkix.Extension{}, err
		}
		generalNames = append(generalNames, val)
	}
	for _, dirName := range san.DirectoryNames {
		bytes, err := asn1.MarshalWithParams(dirName.ToRDNSequence(), "explicit,tag:4")
		if err != nil {
			return pkix.Extension{}, err
		}
		generalNames = append(generalNames, asn1.RawValue{FullBytes: bytes})
	}
	val, err := asn1.Marshal(generalNames)
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{
		Id:       oid.SubjectAltName,
		Critical: critical,
		Value:    val,
	}, nil
}
