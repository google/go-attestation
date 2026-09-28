package tpmsim

import (
	"crypto/x509/pkix"
	"math/big"

	"github.com/google/go-attestation/oid"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// GCEInstanceID contains metadata about a Google Compute Engine VM instance.
type GCEInstanceID struct {
	Zone               string
	ProjectNumber      *big.Int
	ProjectID          string
	InstanceID         *big.Int
	InstanceName       string
	SecurityProperties GCESecurityProperties
}

// GCESecurityProperties holds security configuration for a GCE instance.
type GCESecurityProperties struct {
	SecurityVersion *big.Int
}

// EncodeGCEInstanceID serializes a GCEInstanceID into an X.509 pkix.Extension
// using the standard CloudComputeInstanceIdentifier OID (1.3.6.1.4.1.11129.2.1.21).
func EncodeGCEInstanceID(gce *GCEInstanceID) (pkix.Extension, error) {
	var b cryptobyte.Builder
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cryptobyte_asn1.UTF8String, func(b *cryptobyte.Builder) {
			b.AddBytes([]byte(gce.Zone))
		})
		b.AddASN1BigInt(gce.ProjectNumber)
		b.AddASN1(cryptobyte_asn1.UTF8String, func(b *cryptobyte.Builder) {
			b.AddBytes([]byte(gce.ProjectID))
		})
		b.AddASN1BigInt(gce.InstanceID)
		b.AddASN1(cryptobyte_asn1.UTF8String, func(b *cryptobyte.Builder) {
			b.AddBytes([]byte(gce.InstanceName))
		})
	})
	val, err := b.Bytes()
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{
		Id:    oid.CloudComputeInstanceIdentifier,
		Value: val,
	}, nil
}
