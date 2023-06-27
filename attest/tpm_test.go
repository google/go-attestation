package attest

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"
)

// Created by downloading the base64-url encoded PEM data from
// https://ekop.intel.com/ekcertservice/WVEG2rRwkQ7m3RpXlUphgo6Y2HLxl18h6ZZkkOAdnBE%3D,
// extracting its public key, and formatting it to PEM using
//
//	openssl x509 -in ekcert.pem  -pubkey
//
// This is the public key from the EK cert that's used for testing tpm2-tools:
// https://github.com/tpm2-software/tpm2-tools/blob/master/test/integration/tests/getekcertificate.sh
var testRSAKey = mustParseRSAKey(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwyDi8kSoYBqs8+AdJsZl
JJk1Vi3h2hl+nn8HbEaWE8+2U+mOwsOG/B0TPyyMbMM4tzLwsgi9g4qHej5bvD4d
QIToNcfIkGocBbTS0w/b68HbrZUPprFlvUtqhkYDFGFkwMT1nUiQEe8fko3upukA
YfPTdeVkYnMVHvYiJSCYvhpKsB3AoSInxgn9rOsRWvQI1Gk6b0mRl3RpWwwSvBih
/3EgpzN7L7XxlR2Lt/CU1bVUwRyVI7MHKf5keH0KE7nmMEiNq039hmNKUnDscvzF
pE3GeajzKTjdgZfina6Dn1tMoPXeJ8lSLCPFThws5XhZUlEYvURwsYGA7veK5CZ7
zQIDAQAB
-----END PUBLIC KEY-----`)

func mustParseRSAKey(data string) *rsa.PublicKey {
	pub, err := parseRSAKey(data)
	if err != nil {
		panic(err)
	}
	return pub
}

func parseRSAKey(data string) (*rsa.PublicKey, error) {
	b, _ := pem.Decode([]byte(data))
	if b == nil {
		return nil, fmt.Errorf("failed to parse PEM key")
	}
	pub, err := x509.ParsePKIXPublicKey(b.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %v", err)
	}
	if rsaPub, ok := pub.(*rsa.PublicKey); ok {
		return rsaPub, nil
	}
	return nil, fmt.Errorf("expected *rsa.PublicKey, got %T", pub)
}

func TestIntelEKURL(t *testing.T) {
	want := "https://ekop.intel.com/ekcertservice/WVEG2rRwkQ7m3RpXlUphgo6Y2HLxl18h6ZZkkOAdnBE%3D"
	got := intelEKURL(testRSAKey)
	if got != want {
		t.Fatalf("intelEKURL(), got=%q, want=%q", got, want)
	}
}
